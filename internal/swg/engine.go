// Package swg 是安全能力 SWG(安全 Web 网关,P2)的引擎:对 inspect 流量做 URL 过滤裁决。
//
// 安全栈 L2:三项安全能力共享底座(同一 authoring→编译/下发→PoP 执行管线),加能力不加基础设施。
// SWG 挂在 PEP 的 inspect 效果上(策略 inspect=放行但导入安全栈)。起步基于规则(allow-by-default +
// 阻断名单),引擎为**接口隔离**(Engine),后续可换 ML/采购规则源而不动数据路径与下发管线。
package swg

import "strings"

// 规则 kind / action。
const (
	KindHost       = "host"
	KindPathPrefix = "path_prefix"
	ActionBlock    = "block"
)

// Rule 是一条 SWG 规则(起步仅阻断)。
type Rule struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
}

// Request 是被裁决的 web 请求要素。
type Request struct {
	Host string
	Path string
}

// Decision 是 SWG 裁决。
type Decision struct {
	Allow  bool
	Reason string
}

// Engine 是 SWG 裁决引擎(接口隔离:rule-based 起步,后续可换 ML/采购)。
type Engine interface {
	Evaluate(rules []Rule, req Request) Decision
}

// NewRuleEngine 返回基于规则的引擎:allow-by-default,命中任一 block 规则即拒。
func NewRuleEngine() Engine { return ruleEngine{} }

type ruleEngine struct{}

func (ruleEngine) Evaluate(rules []Rule, req Request) Decision {
	for _, r := range rules {
		if r.Action != ActionBlock {
			continue // 仅阻断规则参与;未知 action 视为不命中(放行)
		}
		switch r.Kind {
		case KindHost:
			// slice 简化:req.Host 当前传的是 app key(应用级阻断);接真实 L7 解包后改为真实 URL host。
			if req.Host == r.Pattern {
				return Decision{Allow: false, Reason: "host blocked: " + r.Pattern}
			}
		case KindPathPrefix:
			if strings.HasPrefix(req.Path, r.Pattern) {
				return Decision{Allow: false, Reason: "path blocked: " + r.Pattern}
			}
			// 未知 kind:不命中 → 放行(allow-by-default,与起步语义一致)
		}
	}
	return Decision{Allow: true}
}
