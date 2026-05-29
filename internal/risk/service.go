package risk

import (
	"sync"
	"time"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/dlp"
)

// 事件型因子默认存活(DLP/会话异常等"事件"的衰减窗;姿态为状态型,由下次上报替换、不用此 TTL)。
// 起步固定值(L2:Redis 缓存 TTL/衰减,后续可配)。防止一次命中令 subject 永久高危(撤销后重认证又即刻再撤)。
const eventFactorTTL = 30 * time.Minute

// MutationFunc 在某 subject 风险**升入 critical**时回调(突变):用于触发自适应撤销(复用既有撤销机制)。
// jti 为触发信号关联的会话凭证(可空);调用方据此撤销该会话(L2 3.4 突变→撤销独立流)。
type MutationFunc func(tenantID, subject, jti string, a Assessment)

// subjectKey 是风险状态的 map 键:用 struct(而非字符串拼接)避免 tenant/subject 含分隔符时碰撞(评审 S2)。
type subjectKey struct{ tenant, subject string }

// Service 是控制面风险引擎:per (tenant,subject) 聚合信号、派生风险、突变即回调撤销。内存状态(起步)。
// store 为**可选**持久化快照层(WithStore 注入;nil=纯内存现状):评分变更后 best-effort upsert 快照,
// 失败不阻断评分(权威评分态仍在内存)。见 store.go。
type Service struct {
	mu    sync.Mutex
	state map[subjectKey]*subjectState
	onMut MutationFunc
	now   func() time.Time
	store data.Store // 可选;nil=不持久化(向后兼容既有 NewService 调用方)
}

// Option 配置 Service 的可选项(如 WithStore 注入持久化快照层)。
type Option func(*Service)

type subjectState struct {
	factors map[string]Factor // 当前活跃因子(id→factor)
	lastJTI string            // 最近见到的会话凭证(撤销目标)
	// 滞后键:已为哪个 jti 触发过 critical 撤销。空=当前未处"已触发 critical"态。
	// 用 jti 而非 bool:① 同 jti 同 critical 不重复撤(防抖)② **会话轮换(新 jti)即便仍 critical 也再触发**
	// (新会话须重新受保护)③ 降到 critical 以下即清空,再次升入会重新触发(评审 B1/B2)。
	firedJTI string
}

// NewService 构造风险服务。onMut 为突变(升入 critical)回调(可 nil)。opts 为可选项(如 WithStore)。
// 不带 opts 调用 = 纯内存现状(向后兼容既有调用方)。
func NewService(onMut MutationFunc, opts ...Option) *Service {
	s := &Service{state: map[subjectKey]*subjectState{}, onMut: onMut, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// add/replace 因子并重算;升入 critical(或 critical 态下会话轮换)则触发 onMut。返回当前评估。
func (s *Service) observe(tenantID, subject, jti string, f Factor, sticky bool) Assessment {
	k := subjectKey{tenantID, subject}
	s.mu.Lock()
	st := s.state[k]
	if st == nil {
		st = &subjectState{factors: map[string]Factor{}}
		s.state[k] = st
	}
	if jti != "" {
		st.lastJTI = jti
	}
	if !sticky {
		f.ExpireAt = s.now().Add(eventFactorTTL)
	}
	if f.Weight > 0 {
		st.factors[f.ID] = f
	} else {
		delete(st.factors, f.ID) // 权重 0 = 清除该因子(如姿态恢复合规)
	}
	a := s.assessLocked(st)
	target := st.lastJTI
	// 滞后(按 jti):critical 且(首次升入 或 撤销目标会话已变)→ 触发一次;非 critical → 复位(再升再触发)。
	fire := false
	if a.Level == LevelCritical {
		if st.firedJTI != target {
			fire = true
			st.firedJTI = target
		}
	} else {
		st.firedJTI = ""
	}
	s.mu.Unlock()

	// 旁路持久化快照(评分变更即刷新最新快照;在锁外做,失败不阻断评分)。仅在配置了快照层时。
	if s.store != nil {
		s.persistSnapshot(tenantID, subject, a)
	}

	if fire && s.onMut != nil {
		s.onMut(tenantID, subject, target, a)
	}
	return a
}

// assessLocked 重算当前评估(剔除已过期事件因子;调用方持锁)。
// 注:会**就地删除过期因子**(GC 副作用),故即便经只读的 Assess 调用也会改 st.factors——是有意的惰性清理。
func (s *Service) assessLocked(st *subjectState) Assessment {
	now := s.now()
	score := 0
	factors := make([]Factor, 0, len(st.factors))
	for id, f := range st.factors {
		if !f.ExpireAt.IsZero() && now.After(f.ExpireAt) {
			delete(st.factors, id) // 顺手清过期(惰性 GC)
			continue
		}
		score += f.Weight
		factors = append(factors, f)
	}
	if score > 100 { // 截顶 100;权重恒非负(信号只加风险),无需下界,但防御性夹到 [0,100]
		score = 100
	} else if score < 0 {
		score = 0
	}
	return Assessment{Score: score, Level: levelOf(score), Factors: factors, ComputedAt: now}
}

// Assess 返回某 subject 当前评估(惰性 GC 过期因子,见 assessLocked;不改滞后态 firedJTI)。
func (s *Service) Assess(tenantID, subject string) Assessment {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state[subjectKey{tenantID, subject}]
	if st == nil {
		return Assessment{Score: 0, Level: LevelLow, ComputedAt: s.now()}
	}
	return s.assessLocked(st)
}

// ObservePosture 消费设备姿态(状态型因子):非合规 → 加高权因子(致 critical);合规 → 清除。
// 承接 Slice6 的"姿态非合规→撤销",改为经风险引擎(可解释 + 与其他信号聚合)。
func (s *Service) ObservePosture(tenantID, subject, jti, posture string) Assessment {
	w := 0
	if posture != "compliant" {
		w = WeightPostureNonCompliant
	}
	// 固定因子 ID "posture"(状态型):新姿态报告替换旧值——合规(w=0)即清除,非合规即置高权。
	// 用固定 ID 而非 "posture:<值>",否则换值会新增 key 而不清旧 key(L2 状态型因子语义)。
	return s.observe(tenantID, subject, jti, Factor{ID: "posture", Weight: w}, true)
}

// Report 实现 dlp.FindingSink:DLP 命中 → 事件型风险因子(按严重度加权),累积升入 critical 即触发撤销。
// 这是 DLP 命中闭环到动态访问控制的接入点(L2 3.1 DLP 信号 + 3.4 突变→撤销)。
func (s *Service) Report(tenantID, subject, jti string, f dlp.Finding) {
	w := WeightDLPMedium
	switch f.Severity {
	case dlp.SeverityHigh:
		w = WeightDLPHigh
	case dlp.SeverityLow:
		w = WeightDLPLow
	}
	s.observe(tenantID, subject, jti, Factor{ID: "dlp:" + f.RuleName, Weight: w}, false)
}

var _ dlp.FindingSink = (*Service)(nil)
