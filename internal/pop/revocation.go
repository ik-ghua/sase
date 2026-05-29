package pop

import "sync"

// RevocationStore 持各租户当前被撤销的凭证 jti 集(由撤销 xDS 流回调整体替换,PEP 验凭证后查)。
// 秒级失效的 PoP 侧权威:命中即拒(ZTNA 硬化 L2 3.4;短 TTL 为不可达兜底)。
type RevocationStore struct {
	mu sync.RWMutex
	m  map[string]map[string]bool // tenantID → jti 集
}

func NewRevocationStore() *RevocationStore { return &RevocationStore{m: map[string]map[string]bool{}} }

// Set 整体替换某租户的撤销集(xDS 下发的是全量 jti 清单)。
func (rs *RevocationStore) Set(tenantID string, jtis []string) {
	set := make(map[string]bool, len(jtis))
	for _, j := range jtis {
		set[j] = true
	}
	rs.mu.Lock()
	rs.m[tenantID] = set
	rs.mu.Unlock()
}

// IsRevoked 判定某租户下 jti 是否已撤销。
func (rs *RevocationStore) IsRevoked(tenantID, jti string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.m[tenantID][jti]
}
