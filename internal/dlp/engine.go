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
type Engine interface {
	Evaluate(rules []Rule, content string) Result
}

// NewRuleEngine 返回规则引擎:扫描内容,命中即记 Finding;命中 block 规则置 Block。
func NewRuleEngine() Engine { return ruleEngine{} }

type ruleEngine struct{}

func (ruleEngine) Evaluate(rules []Rule, content string) Result {
	var res Result
	for i := range rules {
		r := &rules[i]
		if !ruleMatch(r, content) {
			continue
		}
		res.Findings = append(res.Findings, Finding{RuleName: r.Name, Severity: r.Severity, Action: r.Action})
		if r.Action == ActionBlock {
			res.Block = true
		}
	}
	return res
}

// ruleMatch:keyword 子串匹配;regex 正则匹配。非法正则视为不命中(fail-open:DLP 缺陷不应误拦正常流量;
// 与 PEP/防火墙的 fail-closed 不同——DLP 是 inspect 之上的附加检测,引擎缺陷不扩大访问也不误阻断)。
// 骨架性能限:每次扫描对每条 regex 规则重 Compile;生产应预编译缓存进 Rule。
func ruleMatch(r *Rule, content string) bool {
	switch r.MatchType {
	case MatchKeyword:
		return r.Pattern != "" && strings.Contains(content, r.Pattern)
	case MatchRegex:
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return false
		}
		return re.MatchString(content)
	default:
		return false
	}
}

// FindingSink 是 DLP 命中的上报出口(安全栈 L2:DLP 命中喂风险引擎)。
// 风险引擎(internal/risk)实现此接口消费命中做动态风险评估;jti 为触发会话凭证(供突变时定位撤销)。
type FindingSink interface {
	Report(tenantID, subject, jti string, f Finding)
}
