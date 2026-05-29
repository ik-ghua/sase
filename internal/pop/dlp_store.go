package pop

import (
	"log"
	"sync"

	"github.com/ikuai8/sase/internal/dlp"
)

// DLPStore 持各租户当前 DLP 规则(由 DLP xDS 流回调整体替换,inspect 流量检测时查)。
type DLPStore struct {
	mu sync.RWMutex
	m  map[string][]dlp.Rule
}

func NewDLPStore() *DLPStore { return &DLPStore{m: map[string][]dlp.Rule{}} }

// Set 整体替换某租户的 DLP 规则集。
func (s *DLPStore) Set(tenantID string, rules []dlp.Rule) {
	s.mu.Lock()
	s.m[tenantID] = rules
	s.mu.Unlock()
}

// Get 返回某租户 DLP 规则(无则 nil,引擎按无命中处理)。
func (s *DLPStore) Get(tenantID string) []dlp.Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[tenantID]
}

// LogFindingSink 是 DLP 命中的兜底出口:记日志(并可经 metrics 计数)。
// 风险引擎(internal/risk,L2 已设计未编码)落地后由其实现 dlp.FindingSink 消费命中(DLP 命中→风险评分)。
type LogFindingSink struct{}

func (LogFindingSink) Report(tenantID, subject, jti string, f dlp.Finding) {
	log.Printf("[pop] DLP FINDING tenant=%s sub=%s jti=%s rule=%q severity=%s action=%s (待经遥测上报风险引擎)",
		tenantID, subject, jti, f.RuleName, f.Severity, f.Action)
}
