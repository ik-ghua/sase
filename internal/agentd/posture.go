package agentd

import (
	"context"
	"log"
	"sync"
	"time"
)

// PostureFacts 是设备姿态字段集(L2 §3.8 钉死的 10 字段单一来源)。本刀**先定 Go struct**;
// api/proto 的 PostureFacts message(姿态单一来源:采集/上报线格式/凭证填充/策略选择器引用)= 后续刀。
//
// 反作弊分级(L2 §3.8,核心诚实边界,不夸大):
//   - DeviceCertValid 最强——由 PoP 侧 mTLS 证书验证背书(非 Agent 自报);本端的 bool 仅本地自查参考。
//   - 其余 9 项(os/os_version/patch_level/disk_encryption/av_edr/firewall/screen_lock/jailbroken_rooted/
//     agent_version)= **Agent 自报**(端被控即可伪造,防篡改抬门槛非密码学保证)。
//   - 姿态非唯一门禁、PoP 权威判定、端不可信(配合设备证书 + 短 TTL + risk)。
//
// 字段可空(某 OS 无该项)→ 留零值/Unknown,策略侧按「未知=不满足」fail-closed(L2 §3.8)。
type PostureFacts struct {
	OS               string    // 平台名:windows/darwin/linux
	OSVersion        string    // 版本号(/etc/os-release VERSION_ID、内核版本等)
	PatchLevel       string    // 补丁基线标识(内核/包版本;空=未知)
	DiskEncryption   FactState // 磁盘加密(LUKS/FileVault/BitLocker)
	AVEDR            FactState // 杀软/EDR 存在与健康
	Firewall         FactState // 主机防火墙启用
	ScreenLock       FactState // 锁屏策略启用
	JailbrokenRooted TriBool   // 越狱/root(桌面多为 No/Unknown)
	DeviceCertValid  TriBool   // 本端自查设备证书有效(权威由 PoP mTLS 背书)
	AgentVersion     string    // Agent 版本(编译期注入)
}

// FactState 是三态合规字段(none/present/healthy + unknown),映射 L2 §3.8 的 av_edr enum 口径并复用于
// 其它存在性字段。零值 = Unknown(fail-closed)。
type FactState string

const (
	FactUnknown FactState = ""        // 未采到 → 策略按不满足
	FactNone    FactState = "none"    // 明确不存在/未启用
	FactPresent FactState = "present" // 存在但健康度未知
	FactHealthy FactState = "healthy" // 存在且健康/已启用
)

// TriBool 是三态布尔(unknown/yes/no),零值 = Unknown(fail-closed)。
type TriBool string

const (
	TriUnknown TriBool = ""    // 未采到
	TriYes     TriBool = "yes" // 是
	TriNo      TriBool = "no"  // 否
)

// PostureScheduler 调度姿态采集(周期 + 事件驱动,L2 §3.8)并把最新事实交给 onUpdate 回调
// (核心据此经实时通道上报 / 凭证刷新时填 claim)。采集失败不崩:记最新一次成功结果,记录 err。
//
// 复用关系:本调度器是核心新件;实际取值经壳 PostureProbe.Collect(各 OS 系统 API)。
type PostureScheduler struct {
	probe    PostureProbe
	interval time.Duration
	version  string // Agent 版本(编译期注入;盖在壳采集结果的 AgentVersion 字段上,单一来源)
	onUpdate func(PostureFacts)

	mu   sync.RWMutex
	last PostureFacts
	ok   bool // 是否已成功采过至少一次
}

// NewPostureScheduler 构造调度器。interval<=0 时用默认 5 分钟(L2 §3.8 LZ9 默认间隔待调优)。
// version 为 Agent 编译期版本(盖在每次采集结果的 AgentVersion 上,核心单一来源)。
// onUpdate 可为 nil(仅维护 Latest 供凭证刷新/上报拉取)。
func NewPostureScheduler(probe PostureProbe, interval time.Duration, version string, onUpdate func(PostureFacts)) *PostureScheduler {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &PostureScheduler{probe: probe, interval: interval, version: version, onUpdate: onUpdate}
}

// Run 启动即采一次(避免首周期前无姿态),随后每 interval 采一次,直到 ctx 取消。绝不 panic。
func (s *PostureScheduler) Run(ctx context.Context) {
	s.collectOnce()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.collectOnce()
		}
	}
}

// Recheck 立即重采一次(供实时通道 recheck_posture 指令触发,L2 §3.6/§3.8 事件驱动)。
func (s *PostureScheduler) Recheck() { s.collectOnce() }

func (s *PostureScheduler) collectOnce() {
	if s.probe == nil {
		return
	}
	facts, err := s.probe.Collect()
	if err != nil {
		// 采集失败降级:保留上次成功结果(若有),只记 err,绝不崩守护进程(L2 §3.8 fail-closed)。
		log.Printf("[agentd] 姿态采集失败(保留上次结果): %v", err)
		return
	}
	if s.version != "" {
		facts.AgentVersion = s.version // 核心盖版本(单一来源,壳无需知道版本号)
	}
	s.mu.Lock()
	s.last, s.ok = facts, true
	s.mu.Unlock()
	if s.onUpdate != nil {
		s.onUpdate(facts)
	}
}

// Latest 返回最近一次成功采集的姿态;ok=false 表示尚未采到任何结果。
func (s *PostureScheduler) Latest() (PostureFacts, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.last, s.ok
}

// Summary 把姿态压成单字符串摘要,作过渡填入现 cred.Claims.Posture(单字符串)与实时通道上报
// (L2 §3.8:claim 结构化「关键布尔位+摘要哈希」演进 = LZ1 后续刀,与身份/编译器/PEP 协同)。
// 形如 "os=linux ver=22.04 disk=healthy fw=present"——给 PoP/控制面一个比 "compliant" 更有信息的过渡值。
func (f PostureFacts) Summary() string {
	parts := []string{"os=" + nz(f.OS)}
	if f.OSVersion != "" {
		parts = append(parts, "ver="+f.OSVersion)
	}
	parts = append(parts,
		"disk="+nzState(f.DiskEncryption),
		"av="+nzState(f.AVEDR),
		"fw="+nzState(f.Firewall),
		"lock="+nzState(f.ScreenLock),
		"root="+nzTri(f.JailbrokenRooted),
	)
	out := parts[0]
	for _, p := range parts[1:] {
		out += " " + p
	}
	return out
}

func nz(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
func nzState(s FactState) string {
	if s == FactUnknown {
		return "unknown"
	}
	return string(s)
}
func nzTri(t TriBool) string {
	if t == TriUnknown {
		return "unknown"
	}
	return string(t)
}
