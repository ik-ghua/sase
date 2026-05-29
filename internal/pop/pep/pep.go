// Package pep 是 PoP 侧策略执行点:对编译态 PolicyBundle 做请求级裁决。
//
// 守策略编译器 L2 3.5「热路径无解释器」契约:求值 = 有界查表(单遍历已按 priority 排序的规则集,
// 规则数 ≤ 配额)+ 有界谓词比较,无 AST 解释 / 无回溯。默认拒绝(3.2);优先级序内首次匹配。
//
// Slice 3 范围:L7 维度裁决(subject 选择器 × resource × action → effect)。L3/L4 eBPF 与
// 条件谓词(time/geo/risk,编译器 L2 3.6)留后续刀。
package pep

import (
	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/cred"
)

// Decide 返回请求的裁决效果(allow/deny/inspect)。bundle 为 nil(该租户无激活策略)→ 拒绝。
// 规则在 bundle 内已按 priority 升序;取第一条匹配(subject 选择器 + resource + action)的 effect;
// 无任一匹配 → 默认拒绝(策略编译器 L2 3.2 规则 1)。
func Decide(bundle *xdsv1.PolicyBundle, claims cred.Claims, resource, action string) string {
	if bundle == nil {
		return xdsv1.EffectDeny
	}
	for i := range bundle.L7Rules {
		r := &bundle.L7Rules[i]
		if r.Resource != resource {
			continue
		}
		if r.Action != "" && action != "" && r.Action != action {
			continue
		}
		if !subjectMatch(r, claims) {
			continue
		}
		return r.Effect // 优先级序内首次匹配即裁决
	}
	return xdsv1.EffectDeny
}

// subjectMatch 判定凭证声明是否满足规则的 subject 选择器(有界比较,无解释)。
func subjectMatch(r *xdsv1.L7Rule, claims cred.Claims) bool {
	switch r.SubjectKind {
	case "user":
		return claims.Subject == r.SubjectValue
	case "group":
		for _, g := range claims.Groups {
			if g == r.SubjectValue {
				return true
			}
		}
		return false
	case "posture":
		// slice:姿态简化为标量相等;生产为姿态谓词(编译器 L2 3.6)。
		return claims.Posture == r.SubjectValue
	case "risk_gte":
		// 动态访问控制(risk L2 3.3):匹配当凭证 risk_level ≥ 规则阈值(有序枚举比较,数据面不解释规则)。
		// 典型:高优先 risk_gte=critical→deny / risk_gte=medium→inspect,叠在普通 allow 之上,首次匹配成阶梯。
		return xdsv1.RiskAtLeast(claims.RiskLevel, r.SubjectValue)
	default:
		return false // 未知选择器类型 → 不匹配(fail-closed)
	}
}
