package compiler

import (
	"errors"
	"testing"

	"github.com/ikuai8/sase/api/xdsv1"
)

// 已注册应用集(测试中策略引用的 app 均在此,除非专门测未注册)
var apps = map[string]bool{"app1": true, "app2": true}

// TestCompileSortsByPriorityAndIsDeterministic:乱序输入 → 按 priority 升序;同输入同 hash(幂等基础)。
func TestCompileSortsByPriorityAndIsDeterministic(t *testing.T) {
	ps := []Policy{
		{ID: "p2", Priority: 200, SubjectKind: "group", SubjectValue: "g2", Resource: "app2", Action: "connect", Effect: xdsv1.EffectDeny},
		{ID: "p1", Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow},
	}
	b1, err := Compile("t1", ps, apps)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(b1.L7Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(b1.L7Rules))
	}
	if b1.L7Rules[0].Priority != 10 || b1.L7Rules[1].Priority != 200 {
		t.Fatalf("rules not sorted asc by priority: %+v", b1.L7Rules)
	}
	psReordered := []Policy{ps[1], ps[0]}
	b2, err := Compile("t1", psReordered, apps)
	if err != nil {
		t.Fatalf("compile2: %v", err)
	}
	if b1.ContentHash != b2.ContentHash {
		t.Fatalf("hash 不确定:%s vs %s", b1.ContentHash, b2.ContentHash)
	}
}

// TestCompileRiskGte:risk_gte 选择器编译通过(值为合法等级),非法等级 fail-closed。
func TestCompileRiskGte(t *testing.T) {
	ok := []Policy{{ID: "pr", Priority: 1, SubjectKind: "risk_gte", SubjectValue: xdsv1.RiskCritical, Resource: "app1", Action: "connect", Effect: xdsv1.EffectDeny}}
	b, err := Compile("t1", ok, apps)
	if err != nil {
		t.Fatalf("合法 risk_gte 应编译通过: %v", err)
	}
	if len(b.L7Rules) != 1 || b.L7Rules[0].SubjectKind != "risk_gte" || b.L7Rules[0].SubjectValue != xdsv1.RiskCritical {
		t.Fatalf("risk_gte 规则未正确编译: %+v", b.L7Rules)
	}
	if _, err := Compile("t1", []Policy{{ID: "pb", Priority: 1, SubjectKind: "risk_gte", SubjectValue: "sky-high", Resource: "app1", Action: "connect", Effect: xdsv1.EffectDeny}}, apps); err == nil {
		t.Fatal("risk_gte 非法等级应编译失败(fail-closed)")
	}
}

// TestCompileRejectsInvalidEffect:非法 effect → fail-closed 编译错误,不产 bundle。
func TestCompileRejectsInvalidEffect(t *testing.T) {
	_, err := Compile("t1", []Policy{
		{ID: "bad", SubjectKind: "group", SubjectValue: "g", Resource: "app1", Action: "connect", Effect: "permit"},
	}, apps)
	if err == nil {
		t.Fatal("非法 effect 应编译失败")
	}
	var ce *CompileError
	if !errors.As(err, &ce) || ce.Field != "effect" {
		t.Fatalf("应为 effect 字段的 CompileError,得 %v", err)
	}
}

// TestCompileRejectsConflict:同匹配集效果相反 → 编译失败(安全:不可既 allow 又 deny)。
func TestCompileRejectsConflict(t *testing.T) {
	_, err := Compile("t1", []Policy{
		{ID: "a", SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow},
		{ID: "b", SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectDeny},
	}, apps)
	if err == nil {
		t.Fatal("同匹配集冲突应编译失败")
	}
}

// TestCompileRejectsUnknownApp:策略引用未注册应用 → 编译失败(引用存在性校验,3.3①)。
func TestCompileRejectsUnknownApp(t *testing.T) {
	_, err := Compile("t1", []Policy{
		{ID: "x", SubjectKind: "group", SubjectValue: "g1", Resource: "ghost-app", Action: "connect", Effect: xdsv1.EffectAllow},
	}, apps)
	if err == nil {
		t.Fatal("引用未注册应用应编译失败")
	}
	var ce *CompileError
	if !errors.As(err, &ce) || ce.Field != "resource" {
		t.Fatalf("应为 resource 字段的 CompileError,得 %v", err)
	}
	// knownApps 为 nil 时跳过该校验
	if _, err := Compile("t1", []Policy{
		{ID: "x", SubjectKind: "group", SubjectValue: "g1", Resource: "ghost-app", Action: "connect", Effect: xdsv1.EffectAllow},
	}, nil); err != nil {
		t.Fatalf("knownApps=nil 应跳过引用校验,得 %v", err)
	}
}

// TestCompileEmpty:空策略集 → 空 bundle(default-deny 语义由 PoP 兜底,bundle 不含规则)。
func TestCompileEmpty(t *testing.T) {
	b, err := Compile("t1", nil, apps)
	if err != nil {
		t.Fatalf("空集应可编译: %v", err)
	}
	if len(b.L7Rules) != 0 {
		t.Fatalf("空集应产 0 规则,得 %d", len(b.L7Rules))
	}
	if b.ContentHash == "" {
		t.Fatal("空集也应有确定 content_hash")
	}
}
