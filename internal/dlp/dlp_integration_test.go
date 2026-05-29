package dlp_test

// CASB-DLP 规则编写端到端:CreateRule/ListRules 经真实 PG(RLS)+ 校验。需 SASE_DB_RW_DSN;未设则 SKIP。
// 前置:已应用 migrations 0011。

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/dlp"
)

func TestDLPAuthoring(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 DLP 规则编写测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	svc := dlp.NewService(store)
	tid := uuid.NewString()

	if err := svc.CreateRule(ctx, tid, &dlp.Rule{Name: "身份证", MatchType: dlp.MatchRegex, Pattern: `\d{17}[\dXx]`, Action: dlp.ActionBlock, Severity: dlp.SeverityHigh}); err != nil {
		t.Fatalf("CreateRule regex: %v", err)
	}
	if err := svc.CreateRule(ctx, tid, &dlp.Rule{Name: "机密关键词", MatchType: dlp.MatchKeyword, Pattern: "绝密", Action: dlp.ActionAlert}); err != nil {
		t.Fatalf("CreateRule keyword: %v", err)
	}
	rules, err := svc.ListRules(ctx, tid)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("应 2 条,得 %d", len(rules))
	}
	// 默认 severity 填充(第二条未给 → medium)
	if rules[1].Severity != dlp.SeverityMedium {
		t.Fatalf("未给 severity 应默认 medium,得 %q", rules[1].Severity)
	}

	// 校验:非法 match_type / 非法 action / 非法正则 / 缺 pattern → 拒
	if err := svc.CreateRule(ctx, tid, &dlp.Rule{Name: "x", MatchType: "bogus", Pattern: "p", Action: dlp.ActionAlert}); err == nil {
		t.Fatal("非法 match_type 应被拒")
	}
	if err := svc.CreateRule(ctx, tid, &dlp.Rule{Name: "x", MatchType: dlp.MatchKeyword, Pattern: "p", Action: "bogus"}); err == nil {
		t.Fatal("非法 action 应被拒")
	}
	if err := svc.CreateRule(ctx, tid, &dlp.Rule{Name: "x", MatchType: dlp.MatchRegex, Pattern: "[", Action: dlp.ActionAlert}); err == nil {
		t.Fatal("非法正则应被拒")
	}
	if err := svc.CreateRule(ctx, tid, &dlp.Rule{Name: "", MatchType: dlp.MatchKeyword, Pattern: "p", Action: dlp.ActionAlert}); err == nil {
		t.Fatal("缺 name 应被拒")
	}
}
