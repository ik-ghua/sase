package pop

import (
	"sort"
	"sync"

	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/fw"
)

// FWStore 持各租户当前 FWaaS 规则(由 FW xDS 流回调整体替换);实现 dptunnel.Firewall 供 Router 站点间裁决。
// 桥接 fw.Engine(纯裁决)与 dptunnel(数据面),使 dptunnel 不依赖 fw 策略包。
type FWStore struct {
	mu     sync.RWMutex
	m      map[string][]fw.Rule
	engine fw.Engine
}

// NewFWStore 构造 FWStore(engine 为裁决引擎)。
func NewFWStore(engine fw.Engine) *FWStore {
	return &FWStore{m: map[string][]fw.Rule{}, engine: engine}
}

// Set 整体替换某租户的 FW 规则集。防御性按 priority 升序(引擎首次匹配依赖此序——序错会颠倒 allow/deny
// 语义;下发侧已 ORDER BY priority,此处再保证一次,每租户替换时一次、非热路径)。
func (s *FWStore) Set(tenantID string, rules []fw.Rule) {
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	s.mu.Lock()
	s.m[tenantID] = rules
	s.mu.Unlock()
}

// Allow 实现 dptunnel.Firewall:按租户规则裁决一个内层包 5 元组。
// 无该租户规则集(尚未下发)→ 默认拒绝(fail-closed):FWaaS 启用后规则未达不应放行。
func (s *FWStore) Allow(tenantID string, p dptunnel.Packet5Tuple) bool {
	s.mu.RLock()
	rules, ok := s.m[tenantID]
	s.mu.RUnlock()
	if !ok {
		return false // 规则未下发 → fail-closed(与 fw.Engine 默认拒绝一致)
	}
	d := s.engine.Evaluate(rules, fw.Packet{
		SrcIP: p.SrcIP, DstIP: p.DstIP, Proto: p.Proto, DstPort: p.DstPort,
	})
	return d.Allow
}
