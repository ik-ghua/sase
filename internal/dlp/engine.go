// Package dlp 是安全能力 CASB-DLP(数据防泄漏,P5)的规则模型 + 纯函数检测引擎 + 命中上报接口。
//
// 安全栈 L2:三项安全能力共享底座(authoring→编译/下发→PoP 执行同一管线),加能力不加基础设施。
// DLP 挂在 PoP L7 inspect 检查点(与 SWG 同),对内容做敏感数据匹配:命中 block 规则即拒,命中任意规则
// **喂风险引擎**(DLP 命中→风险评分)。起步基于规则(关键词/正则),引擎接口隔离,后续可换指纹/ML/采购规则源。
//
// 内容来源:生产经 Envoy ext_proc 取请求/响应体;当前数据路径无 body,stand-in 扫描可见内容(URL path 等)。
package dlp

import (
	"regexp"
	"strings"
)

// 匹配类型 / 动作 / 严重度。
const (
	MatchKeyword = "keyword"
	MatchRegex   = "regex"

	ActionBlock = "block" // 命中即拒(inline)
	ActionAlert = "alert" // 放行但告警 + 喂风险

	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// Rule 是一条 DLP 规则。
type Rule struct {
	ID        string `json:"id,omitempty"` // authoring/管理标识(PUT/DELETE 寻址用);数据面引擎不读
	Name      string `json:"name"`
	MatchType string `json:"match_type"` // keyword | regex
	Pattern   string `json:"pattern"`
	Action    string `json:"action"`   // block | alert
	Severity  string `json:"severity"` // low | medium | high
}

// Finding 是一次命中(喂风险引擎 / 审计)。
type Finding struct {
	RuleName string
	Severity string
	Action   string
}

// Result 是对一段内容的 DLP 检测结果。
type Result struct {
	Block    bool      // 是否命中任一 block 规则(inline 拒绝)
	Findings []Finding // 所有命中(含 alert),供喂风险引擎
}

// Engine 是 DLP 检测引擎(接口隔离:关键词/正则起步,后续可换指纹/ML/采购)。
//   - Evaluate:对原始规则检测(每次内部 Compile,便于测试/低频路径)。
//   - EvaluateCompiled:对**预编译**规则集检测(热路径:regex 已 Compile,免每次扫描重编译)。
type Engine interface {
	Evaluate(rules []Rule, content string) Result
	EvaluateCompiled(cs CompiledRuleSet, content string) Result
}

// NewRuleEngine 返回规则引擎:扫描内容,命中即记 Finding;命中 block 规则置 Block。
func NewRuleEngine() Engine { return ruleEngine{} }

type ruleEngine struct{}

// compiledRule 是预编译规则:regex 已 Compile 一次(非法正则 → re=nil,永不命中,保留 fail-open)。
type compiledRule struct {
	name      string
	severity  string
	action    string
	matchType string
	keyword   string         // MatchKeyword:子串
	re        *regexp.Regexp // MatchRegex:已编译(nil=非法,永不命中)
}

// CompiledRuleSet 是预编译规则集(下发侧 Set 时编译一次,热路径零 regexp.Compile)。
type CompiledRuleSet struct {
	rules []compiledRule
}

// Len 返回规则条数(测试/自检用;零值 CompiledRuleSet 为 0)。
func (cs CompiledRuleSet) Len() int { return len(cs.rules) }

// Compile 把规则集预编译:regex 规则 Compile 一次(非法正则保留 fail-open:re=nil 永不命中)。
func Compile(rules []Rule) CompiledRuleSet {
	out := make([]compiledRule, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		cr := compiledRule{name: r.Name, severity: r.Severity, action: r.Action, matchType: r.MatchType}
		switch r.MatchType {
		case MatchKeyword:
			cr.keyword = r.Pattern
		case MatchRegex:
			if re, err := regexp.Compile(r.Pattern); err == nil {
				cr.re = re
			} // 非法正则:re 留 nil → 永不命中(fail-open,与原 ruleMatch 一致)
		}
		out = append(out, cr)
	}
	return CompiledRuleSet{rules: out}
}

func (ruleEngine) Evaluate(rules []Rule, content string) Result {
	return ruleEngine{}.EvaluateCompiled(Compile(rules), content)
}

func (ruleEngine) EvaluateCompiled(cs CompiledRuleSet, content string) Result {
	var res Result
	for i := range cs.rules {
		cr := &cs.rules[i]
		if !matchesCompiled(cr, content) {
			continue
		}
		res.Findings = append(res.Findings, Finding{RuleName: cr.name, Severity: cr.severity, Action: cr.action})
		if cr.action == ActionBlock {
			res.Block = true
		}
	}
	return res
}

// matchesCompiled:keyword 子串匹配;regex 用预编译 re(nil → 不命中,fail-open)。
func matchesCompiled(cr *compiledRule, content string) bool {
	switch cr.matchType {
	case MatchKeyword:
		return cr.keyword != "" && strings.Contains(content, cr.keyword)
	case MatchRegex:
		return cr.re != nil && cr.re.MatchString(content)
	default:
		return false
	}
}

// FindingSink 是 DLP 命中的上报出口(安全栈 L2:DLP 命中喂风险引擎)。
// 风险引擎(internal/risk)实现此接口消费命中做动态风险评估;jti 为触发会话凭证(供突变时定位撤销)。
type FindingSink interface {
	Report(tenantID, subject, jti string, f Finding)
}
