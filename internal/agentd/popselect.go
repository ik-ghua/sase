package agentd

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// PoPCandidate 是一个候选 PoP 节点(L2 §3.7:控制面下发候选列表,不硬编码 IP)。
//   - Name 逻辑名(日志/可观测);HandshakeAddr 是握手 TCP 地址(tunhandshake.Dial 目标)。
//   - 候选列表来自入网响应(pop_list)与运行期实时通道 config_update,由配置注入(去硬编码 IP)。
type PoPCandidate struct {
	Name          string
	HandshakeAddr string // PoP 握手地址(host:port);RTT 探测与建隧道均用此
}

// RTTProber 探测到候选 PoP 的往返时延(L2 §3.7:轻量握手/UDP RTT,不依赖 ICMP——部分网络禁 ICMP)。
// 返回 err 视为该候选当前不可达。可注入便于单测(真实现用 TCP 连握手端口测 RTT)。
type RTTProber interface {
	ProbeRTT(ctx context.Context, c PoPCandidate) (time.Duration, error)
}

// ErrNoCandidates / ErrNoHealthy:无候选 / 全部候选不可达(选址失败,调用方据此重试或等 config_update)。
var (
	ErrNoCandidates = errors.New("agentd: 无候选 PoP(待入网/实时通道下发列表)")
	ErrNoHealthy    = errors.New("agentd: 候选 PoP 均不可达(RTT 探测全失败)")
)

// PoPSelector 据候选列表 + RTT 实测选最近 PoP(L2 §3.7)。复用 linkmon 的「RTT 实测选优」思路,
// 但 PoP 选址候选数少、切换语义不同(linkmon 是多 WAN 上联),故本刀独立最小实现:
// 选 RTT 最低且可达者;动态切换由调用方据 Select 结果 + 抑抖动阈值执行(本刀给基础,深化为后续刀)。
type PoPSelector struct {
	prober RTTProber

	mu         sync.RWMutex
	candidates []PoPCandidate
	current    string // 当前选定 PoP 名(用于抑抖动:RTT 改善须超阈值才切)
}

// NewPoPSelector 构造选址器(prober 必需:RTT 实测是选址核心,L2 §3.7「不硬编码 IP + RTT 实测」)。
func NewPoPSelector(prober RTTProber) *PoPSelector {
	return &PoPSelector{prober: prober}
}

// SetCandidates 更新候选列表(入网 pop_list / 实时通道 config_update 下发,L2 §3.7)。空名/空地址项被忽略。
func (s *PoPSelector) SetCandidates(cands []PoPCandidate) {
	out := make([]PoPCandidate, 0, len(cands))
	seen := map[string]bool{}
	for _, c := range cands {
		if c.Name == "" || c.HandshakeAddr == "" || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		out = append(out, c)
	}
	s.mu.Lock()
	s.candidates = out
	s.mu.Unlock()
}

// Candidates 返回候选列表快照。
func (s *PoPSelector) Candidates() []PoPCandidate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]PoPCandidate(nil), s.candidates...)
}

// rttResult 内部:某候选的探测结果。
type rttResult struct {
	cand PoPCandidate
	rtt  time.Duration
	ok   bool
}

// Select 对所有候选并发探测 RTT,返回 RTT 最低且可达的 PoP。
//   - 无候选 → ErrNoCandidates;全部不可达 → ErrNoHealthy。
//   - 确定性:同 RTT 时按 Name 升序取(避免抖动);记录选定 current(供后续抑抖动切换)。
func (s *PoPSelector) Select(ctx context.Context) (PoPCandidate, error) {
	s.mu.RLock()
	cands := append([]PoPCandidate(nil), s.candidates...)
	s.mu.RUnlock()
	if len(cands) == 0 {
		return PoPCandidate{}, ErrNoCandidates
	}

	results := make([]rttResult, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Add(1)
		go func(i int, c PoPCandidate) {
			defer wg.Done()
			rtt, err := s.prober.ProbeRTT(ctx, c)
			results[i] = rttResult{cand: c, rtt: rtt, ok: err == nil}
		}(i, c)
	}
	wg.Wait()

	healthy := make([]rttResult, 0, len(results))
	for _, r := range results {
		if r.ok {
			healthy = append(healthy, r)
		}
	}
	if len(healthy) == 0 {
		return PoPCandidate{}, ErrNoHealthy
	}
	sort.SliceStable(healthy, func(i, j int) bool {
		if healthy[i].rtt != healthy[j].rtt {
			return healthy[i].rtt < healthy[j].rtt
		}
		return healthy[i].cand.Name < healthy[j].cand.Name // 同 RTT 名序定夺,确定性
	})
	best := healthy[0].cand
	s.mu.Lock()
	s.current = best.Name
	s.mu.Unlock()
	return best, nil
}

// Current 返回当前选定 PoP 名(空=尚未选过)。
func (s *PoPSelector) Current() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}
