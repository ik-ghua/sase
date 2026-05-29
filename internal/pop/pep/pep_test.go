package pep

import (
	"testing"

	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/cred"
)

func bundle(rules ...xdsv1.L7Rule) *xdsv1.PolicyBundle {
	return &xdsv1.PolicyBundle{TenantID: "t", Version: 1, L7Rules: rules}
}

func TestDecideDefaultDeny(t *testing.T) {
	// 无规则匹配 → 拒绝
	b := bundle(xdsv1.L7Rule{Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow})
	if got := Decide(b, cred.Claims{Groups: []string{"g1"}}, "app2", "connect"); got != xdsv1.EffectDeny {
		t.Fatalf("不匹配资源应默认拒绝,得 %s", got)
	}
	if got := Decide(nil, cred.Claims{}, "app1", "connect"); got != xdsv1.EffectDeny {
		t.Fatalf("无 bundle 应拒绝,得 %s", got)
	}
}

func TestDecideGroupAllow(t *testing.T) {
	b := bundle(xdsv1.L7Rule{Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow})
	if got := Decide(b, cred.Claims{Groups: []string{"g0", "g1"}}, "app1", "connect"); got != xdsv1.EffectAllow {
		t.Fatalf("组匹配应放行,得 %s", got)
	}
	if got := Decide(b, cred.Claims{Groups: []string{"g2"}}, "app1", "connect"); got != xdsv1.EffectDeny {
		t.Fatalf("组不匹配应拒绝,得 %s", got)
	}
}

func TestDecideFirstMatchByPriority(t *testing.T) {
	// 高优先(prio 小)具体 allow + 低优先宽 deny:首次匹配取高优先 allow(编译器 L2 3.2 例外语义)
	b := bundle(
		xdsv1.L7Rule{Priority: 10, SubjectKind: "user", SubjectValue: "u1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow},
		xdsv1.L7Rule{Priority: 100, SubjectKind: "group", SubjectValue: "all", Resource: "app1", Action: "connect", Effect: xdsv1.EffectDeny},
	)
	if got := Decide(b, cred.Claims{Subject: "u1", Groups: []string{"all"}}, "app1", "connect"); got != xdsv1.EffectAllow {
		t.Fatalf("应取高优先 allow,得 %s", got)
	}
	// 非 u1 但属 all 组 → 落到低优先 deny
	if got := Decide(b, cred.Claims{Subject: "u2", Groups: []string{"all"}}, "app1", "connect"); got != xdsv1.EffectDeny {
		t.Fatalf("非 u1 应落到宽 deny,得 %s", got)
	}
}

// risk_gte 选择器:风险阶梯。高优先 risk_gte=critical→deny、risk_gte=medium→inspect 叠在普通 allow 之上,
// 首次匹配按凭证 risk_level 给出动态裁决(risk L2 3.3)。
func TestDecideRiskLadder(t *testing.T) {
	b := bundle(
		xdsv1.L7Rule{Priority: 1, SubjectKind: "risk_gte", SubjectValue: xdsv1.RiskCritical, Resource: "app1", Action: "connect", Effect: xdsv1.EffectDeny},
		xdsv1.L7Rule{Priority: 3, SubjectKind: "risk_gte", SubjectValue: xdsv1.RiskMedium, Resource: "app1", Action: "connect", Effect: xdsv1.EffectInspect},
		xdsv1.L7Rule{Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow},
	)
	base := []string{"g1"}
	if got := Decide(b, cred.Claims{Groups: base}, "app1", "connect"); got != xdsv1.EffectAllow {
		t.Fatalf("低风险(空 level=low)应 allow,得 %s", got)
	}
	// 未知/垃圾 level → 视作最低(rank0),不命中 risk_gte≥medium 限制(锁定 fail-open-to-low 是刻意语义)
	if got := Decide(b, cred.Claims{Groups: base, RiskLevel: "garbage"}, "app1", "connect"); got != xdsv1.EffectAllow {
		t.Fatalf("未知 level 应视作 low → allow,得 %s", got)
	}
	if got := Decide(b, cred.Claims{Groups: base, RiskLevel: xdsv1.RiskMedium}, "app1", "connect"); got != xdsv1.EffectInspect {
		t.Fatalf("medium 应 inspect,得 %s", got)
	}
	if got := Decide(b, cred.Claims{Groups: base, RiskLevel: xdsv1.RiskHigh}, "app1", "connect"); got != xdsv1.EffectInspect {
		t.Fatalf("high(≥medium)应 inspect,得 %s", got)
	}
	if got := Decide(b, cred.Claims{Groups: base, RiskLevel: xdsv1.RiskCritical}, "app1", "connect"); got != xdsv1.EffectDeny {
		t.Fatalf("critical 应 deny,得 %s", got)
	}
}

func TestDecideActionAndPosture(t *testing.T) {
	b := bundle(xdsv1.L7Rule{Priority: 10, SubjectKind: "posture", SubjectValue: "compliant", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow})
	if got := Decide(b, cred.Claims{Posture: "compliant"}, "app1", "connect"); got != xdsv1.EffectAllow {
		t.Fatalf("姿态匹配应放行,得 %s", got)
	}
	if got := Decide(b, cred.Claims{Posture: "stale"}, "app1", "connect"); got != xdsv1.EffectDeny {
		t.Fatalf("姿态不符应拒绝,得 %s", got)
	}
}
