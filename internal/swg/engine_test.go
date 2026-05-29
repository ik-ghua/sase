package swg

import "testing"

func TestRuleEngineEvaluate(t *testing.T) {
	e := NewRuleEngine()
	rules := []Rule{
		{Kind: KindPathPrefix, Pattern: "/admin", Action: ActionBlock},
		{Kind: KindHost, Pattern: "evil.com", Action: ActionBlock},
		{Kind: KindPathPrefix, Pattern: "/x", Action: "log"}, // 非 block,忽略
	}
	cases := []struct {
		name string
		req  Request
		want bool // allow?
	}{
		{"默认放行", Request{Host: "ok.com", Path: "/index"}, true},
		{"路径前缀阻断", Request{Host: "ok.com", Path: "/admin/users"}, false},
		{"host 阻断", Request{Host: "evil.com", Path: "/"}, false},
		{"非 block 动作不阻断", Request{Host: "ok.com", Path: "/x/y"}, true},
	}
	for _, c := range cases {
		if got := e.Evaluate(rules, c.req); got.Allow != c.want {
			t.Errorf("%s: allow=%v want %v (reason=%q)", c.name, got.Allow, c.want, got.Reason)
		}
	}
	if d := e.Evaluate(nil, Request{Path: "/admin"}); !d.Allow {
		t.Error("无规则应默认放行")
	}
}
