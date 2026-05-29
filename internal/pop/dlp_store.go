package pop

import (
	"log"
	"sync"

	"github.com/ikuai8/sase/internal/dlp"
)

// DLPStore 持各租户当前 DLP 规则(由 DLP xDS 流回调整体替换,inspect 流量检测时查)。
// 持**预编译**规则集(Set 时编译 regex,inspect 热路径零 regexp.Compile)。
type DLPStore struct {
	mu sync.RWMutex
	m  map[string]dlp.CompiledRuleSet
}

func NewDLPStore() *DLPStore { return &DLPStore{m: map[string]dlp.CompiledRuleSet{}} }

// Set 整体替换某租户的 DLP 规则集(预编译 regex,每租户替换时一次、非热路径)。
func (s *DLPStore) Set(tenantID string, rules []dlp.Rule) {
	cs := dlp.Compile(rules)
	s.mu.Lock()
	s.m[tenantID] = cs
	s.mu.Unlock()
}

// Get 返回某租户预编译 DLP 规则集(无则零值 CompiledRuleSet,引擎按无命中处理)。
func (s *DLPStore) Get(tenantID string) dlp.CompiledRuleSet {
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
