// Package xdsv1 是控制面 → PoP 下发的资源契约(单一来源)。
//
// Slice 2 现状:契约以 Go 结构体表达、JSON 编码、经最小 HTTP 流式通道下发(slice stand-in)。
// 生产形态(xDS server L2 3.1/3.11):这些类型对应自定义 xDS 资源(`L7PolicyBundle` /
// `L34RuleSet`),经 go-control-plane 的 ADS + 增量 + ACK/NACK + mTLS 下发,schema 落 api/proto。
// 加厚时本包替换为 proto 生成类型,契约语义(字段/求值语义)保持不变。
//
// 放在 api/(非 internal/)因这是跨进程契约,xds-server 与 pop-agent 共同依赖(总览 3.6 单一来源)。
package xdsv1

// Effect 是策略裁决效果(策略编译器 L2 3.1)。
const (
	EffectAllow   = "allow"
	EffectDeny    = "deny"
	EffectInspect = "inspect" // 放行但导入安全栈(SWG/DLP)
)

// 风险等级取值域(信任/风险引擎 L2 3.1 单一来源;risk 引擎产出同一组字符串)。放此契约包,供编译器(校验)
// 与 PoP PEP(比较)共用,二者不依赖 risk 包。SubjectKind "risk_gte" 的 SubjectValue 取这些值。
const (
	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
)

var riskRank = map[string]int{RiskLow: 0, RiskMedium: 1, RiskHigh: 2, RiskCritical: 3}

// ValidRiskLevel 判定是否合法风险等级(编译器校验 risk_gte 的 SubjectValue)。
func ValidRiskLevel(s string) bool { _, ok := riskRank[s]; return ok }

// RiskAtLeast 判定 claimLevel(凭证 risk claim)是否 ≥ threshold(规则阈值)。空/未知 claimLevel 视作最低
// (依赖 map 未命中返回零值 0 = low:无信号即低风险,与 risk 引擎一致;勿把 RiskLow 的 rank 改成非 0)。
// 数据面只做此有序比较,不解释规则(L2 3.5)。
func RiskAtLeast(claimLevel, threshold string) bool {
	return riskRank[claimLevel] >= riskRank[threshold]
}

// L7Rule 是编译后的 L7 PEP 决策规则(策略编译器 L2 3.4)。
// subject 保持选择器(不展开为具体用户),求值期由 PEP 用凭证声明匹配(3.1)。
// 规则在 PolicyBundle 内已按 priority 升序排列,PEP 取优先级序内首次匹配(3.2)。
type L7Rule struct {
	Priority     int    `json:"priority"`      // 小=高优先
	SubjectKind  string `json:"subject_kind"`  // user / group / posture
	SubjectValue string `json:"subject_value"` // 选择器值
	Resource     string `json:"resource"`      // 应用 id / FQDN
	Action       string `json:"action"`        // connect / http-get ...
	Effect       string `json:"effect"`        // allow / deny / inspect
}

// PolicyBundle 是控制面下发给 PoP 的编译态产物(L1 3.3 + content_hash)。
// Slice 2 仅含 L7 维度;L3/L4(eBPF 网络分段,L34RuleSet)留后续刀。
// 默认拒绝(default-deny)为求值语义:无任一 L7Rule 匹配 → 拒绝(策略编译器 L2 3.2),
// 不在 bundle 内显式表达兜底拒绝规则。
type PolicyBundle struct {
	TenantID    string   `json:"tenant_id"`
	Version     int64    `json:"version"`      // 每租户单调递增
	ContentHash string   `json:"content_hash"` // sha256(规范化 L7Rules),幂等用
	L7Rules     []L7Rule `json:"l7_rules"`     // 按 priority 升序
}
