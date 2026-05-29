package dlp

import "testing"

func TestEvaluate(t *testing.T) {
	eng := NewRuleEngine()

	// 无规则 → 无命中、不阻断
	if r := eng.Evaluate(nil, "任意内容"); r.Block || len(r.Findings) != 0 {
		t.Fatalf("无规则应无命中,得 %+v", r)
	}

	rules := []Rule{
		{Name: "关键词secret", MatchType: MatchKeyword, Pattern: "secret", Action: ActionBlock, Severity: SeverityHigh},
		{Name: "手机号", MatchType: MatchRegex, Pattern: `1[3-9]\d{9}`, Action: ActionAlert, Severity: SeverityMedium},
	}

	// keyword 命中 block → Block=true,1 命中
	r := eng.Evaluate(rules, "this has a secret token")
	if !r.Block || len(r.Findings) != 1 || r.Findings[0].RuleName != "关键词secret" {
		t.Fatalf("应命中 block 关键词,得 %+v", r)
	}

	// regex 命中 alert → 不 Block,但有 finding(喂风险)
	r = eng.Evaluate(rules, "联系 13800138000 ")
	if r.Block || len(r.Findings) != 1 || r.Findings[0].Action != ActionAlert {
		t.Fatalf("regex alert 应命中但不阻断,得 %+v", r)
	}

	// 同时命中 block + alert → Block=true,2 命中
	r = eng.Evaluate(rules, "secret 13800138000")
	if !r.Block || len(r.Findings) != 2 {
		t.Fatalf("应两条都命中且阻断,得 %+v", r)
	}

	// 无命中
	if r := eng.Evaluate(rules, "nothing sensitive here"); r.Block || len(r.Findings) != 0 {
		t.Fatalf("无命中应空,得 %+v", r)
	}

	// 非法正则 fail-open(不命中、不误拦)
	bad := []Rule{{Name: "坏正则", MatchType: MatchRegex, Pattern: "[", Action: ActionBlock}}
	if r := eng.Evaluate(bad, "anything"); r.Block || len(r.Findings) != 0 {
		t.Fatalf("非法正则应不命中(fail-open),得 %+v", r)
	}
}

// Slice66:预编译路径——非法正则编译后永不命中(fail-open,与原 ruleMatch 一致);合法正则命中。
func TestCompiledRegex(t *testing.T) {
	e := NewRuleEngine()
	bad := Compile([]Rule{{Name: "x", MatchType: MatchRegex, Pattern: "[", Action: ActionAlert, Severity: SeverityLow}})
	if r := e.EvaluateCompiled(bad, "anything ["); len(r.Findings) != 0 {
		t.Fatalf("非法正则不应命中(fail-open),得 %+v", r.Findings)
	}
	good := Compile([]Rule{{Name: "ssn", MatchType: MatchRegex, Pattern: `\d{3}-\d{4}`, Action: ActionBlock, Severity: SeverityHigh}})
	r := e.EvaluateCompiled(good, "call 123-4567 now")
	if !r.Block || len(r.Findings) != 1 {
		t.Fatalf("合法正则应命中 block,得 %+v", r)
	}
}

func benchDLPRules() []Rule {
	return []Rule{
		{Name: "kw", MatchType: MatchKeyword, Pattern: "绝密", Action: ActionAlert, Severity: SeverityMedium},
		{Name: "ssn", MatchType: MatchRegex, Pattern: `\d{3}-\d{2}-\d{4}`, Action: ActionBlock, Severity: SeverityHigh},
		{Name: "id", MatchType: MatchRegex, Pattern: `[1-9]\d{16}[\dXx]`, Action: ActionBlock, Severity: SeverityHigh},
	}
}

// BenchmarkEvaluateRaw:每次扫描都 Compile(等价旧的每次 regexp.Compile)。
func BenchmarkEvaluateRaw(b *testing.B) {
	e, rules := NewRuleEngine(), benchDLPRules()
	const content = "normal business content with phone 555-1234 and some text"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Evaluate(rules, content)
	}
}

// BenchmarkEvaluateCompiled:预编译一次,热路径零 regexp.Compile(Slice66 收益)。
func BenchmarkEvaluateCompiled(b *testing.B) {
	e, cs := NewRuleEngine(), Compile(benchDLPRules())
	const content = "normal business content with phone 555-1234 and some text"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.EvaluateCompiled(cs, content)
	}
}
