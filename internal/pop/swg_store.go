package pop

import (
	"sync"

	"github.com/ikuai8/sase/internal/swg"
)

// SWGStore 持各租户当前 SWG 规则(由 SWG xDS 流回调整体替换,inspect 流量裁决时查)。
type SWGStore struct {
	mu sync.RWMutex
	m  map[string][]swg.Rule
}

func NewSWGStore() *SWGStore { return &SWGStore{m: map[string][]swg.Rule{}} }

// Set 整体替换某租户的 SWG 规则集。
func (s *SWGStore) Set(tenantID string, rules []swg.Rule) {
	s.mu.Lock()
	s.m[tenantID] = rules
	s.mu.Unlock()
}

// Get 返回某租户 SWG 规则(无则 nil,引擎按 allow-by-default 处理)。
func (s *SWGStore) Get(tenantID string) []swg.Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[tenantID]
}
