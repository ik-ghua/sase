// Package compiler 是策略编译器:编写态策略集 → 执行态 PolicyBundle(纯函数,无副作用)。
// 上承策略编译器 L2(3.2 求值语义、3.3 管线、3.7 fail-closed/content_hash)。
//
// Slice 2 范围:校验(字段值空间)→ 冲突检测(同匹配集效果相反 → 编译失败)→ 按 priority 排序
// → 产 L7Rule 列表 → content_hash。fail-closed:任一步出错不产 bundle(3.7,L1「编译错误=安全漏洞」)。
// 未做(后续加厚):L3/L4 eBPF 降级、遮蔽检测、属性测试、防抖。
package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ikuai8/sase/api/xdsv1"
)

// Policy 是编译器输入的编写态策略(对应 policies 表的最小子集,策略编译器 L2 3.1)。
type Policy struct {
	ID           string
	Name         string
	Priority     int
	SubjectKind  string // user / group / posture
	SubjectValue string
	Resource     string
	Action       string
	Effect       string // allow / deny / inspect
}

var validEffects = map[string]bool{
	xdsv1.EffectAllow:   true,
	xdsv1.EffectDeny:    true,
	xdsv1.EffectInspect: true,
}

var validSubjectKinds = map[string]bool{
	"user": true, "group": true, "posture": true,
	"risk_gte": true, // 风险选择器:匹配当 subject 风险 ≥ SubjectValue(risk L2 3.3 动态访问控制)
}

// CompileError 带策略 id / 字段定位,回传编写态供修正(策略编译器 L2 3.3 错误定位)。
type CompileError struct {
	PolicyID string
	Field    string
	Msg      string
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("compile: policy=%s field=%s: %s", e.PolicyID, e.Field, e.Msg)
}

// Compile 把租户策略集编译为 PolicyBundle(纯函数:相同输入 → 相同输出,可重放可单测)。
// version 由调用方(落库时)分配,这里置 0;调用方据 content_hash 幂等并填版本(3.7)。
//
// knownApps 是已注册应用键集合(解析快照,编译器 L2 3.3 显式输入):非 nil 时校验每条策略的
// resource 引用存在(引用未注册应用 → 编译失败 fail-closed,3.3①);为 nil 时跳过该校验(无注册表场景)。
func Compile(tenantID string, policies []Policy, knownApps map[string]bool) (xdsv1.PolicyBundle, error) {
	rules := make([]xdsv1.L7Rule, 0, len(policies))

	// ① 校验:字段值空间 + 引用存在性(3.3 阶段①)。
	for _, p := range policies {
		if !validEffects[p.Effect] {
			return xdsv1.PolicyBundle{}, &CompileError{p.ID, "effect", fmt.Sprintf("非法 effect %q", p.Effect)}
		}
		if !validSubjectKinds[p.SubjectKind] {
			return xdsv1.PolicyBundle{}, &CompileError{p.ID, "subject_kind", fmt.Sprintf("非法 subject_kind %q", p.SubjectKind)}
		}
		if p.SubjectKind == "risk_gte" && !xdsv1.ValidRiskLevel(p.SubjectValue) {
			return xdsv1.PolicyBundle{}, &CompileError{p.ID, "subject_value", fmt.Sprintf("risk_gte 的值须为风险等级(low/medium/high/critical),得 %q", p.SubjectValue)}
		}
		if p.Resource == "" || p.Action == "" {
			return xdsv1.PolicyBundle{}, &CompileError{p.ID, "resource/action", "resource 与 action 必填"}
		}
		if knownApps != nil && !knownApps[p.Resource] {
			return xdsv1.PolicyBundle{}, &CompileError{p.ID, "resource", fmt.Sprintf("引用了未注册的应用 %q", p.Resource)}
		}
		rules = append(rules, xdsv1.L7Rule{
			Priority:     p.Priority,
			SubjectKind:  p.SubjectKind,
			SubjectValue: p.SubjectValue,
			Resource:     p.Resource,
			Action:       p.Action,
			Effect:       p.Effect,
		})
	}

	// ② 冲突检测(3.2 规则 3 的最小子集):同匹配集(subject+resource+action)但效果相反 → 编译失败。
	// 这类是「同条件既 allow 又 deny」的硬冲突,放行将是安全漏洞,fail-closed 拒绝产 bundle。
	type matchKey struct{ sk, sv, res, act string }
	seen := map[matchKey]string{} // 匹配集 → 已见 effect
	for i, r := range rules {
		k := matchKey{r.SubjectKind, r.SubjectValue, r.Resource, r.Action}
		if prev, ok := seen[k]; ok && prev != r.Effect {
			return xdsv1.PolicyBundle{}, &CompileError{
				policies[i].ID, "effect",
				fmt.Sprintf("同 subject/resource/action 效果冲突:%s vs %s", prev, r.Effect),
			}
		}
		seen[k] = r.Effect
	}

	// ③ 序化:按 priority 升序、同优先级用稳定次序(求值首次匹配,3.2)。
	sortRules(rules)

	// ④ content_hash:对规范化后的规则取 sha256(幂等,3.7)。
	hash, err := contentHash(rules)
	if err != nil {
		return xdsv1.PolicyBundle{}, fmt.Errorf("compile: 计算 content_hash: %w", err)
	}

	return xdsv1.PolicyBundle{
		TenantID:    tenantID,
		Version:     0, // 落库时分配
		ContentHash: hash,
		L7Rules:     rules,
	}, nil
}

// sortRules 按 priority 升序,priority 相同再按 (resource, subject, action, effect) 定序,
// 保证编译确定性(相同策略集 → 相同顺序 → 相同 hash)。
func sortRules(rules []xdsv1.L7Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if a.SubjectKind != b.SubjectKind {
			return a.SubjectKind < b.SubjectKind
		}
		if a.SubjectValue != b.SubjectValue {
			return a.SubjectValue < b.SubjectValue
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Effect < b.Effect
	})
}

func contentHash(rules []xdsv1.L7Rule) (string, error) {
	b, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
