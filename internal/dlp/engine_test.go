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
