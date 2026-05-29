package dlp_test

// CASB-DLP 规则编写端到端:CreateRule/ListRules 经真实 PG(RLS)+ 校验。需 SASE_DB_RW_DSN;未设则 SKIP。
// 前置:已应用 migrations 0011。

import (
	"context"
	"errors"
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

// Slice62 CASB-DLP 规则生命周期(真 PG,RLS):Create 回填 id → Update 改字段 → Delete → 不存在/跨租户 → ErrNotFound。
func TestDLPRuleLifecycle(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 DLP 规则生命周期测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	svc := dlp.NewService(store)
	tid := uuid.NewString()

	r := &dlp.Rule{Name: "机密", MatchType: dlp.MatchKeyword, Pattern: "secret", Action: dlp.ActionAlert, Severity: dlp.SeverityLow}
	if err := svc.CreateRule(ctx, tid, r); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if r.ID == "" {
		t.Fatal("CreateRule 应回填 r.ID")
	}
	id := r.ID

	// Update:改为 block + high + 改 pattern
	if err := svc.UpdateRule(ctx, tid, id, &dlp.Rule{Name: "机密", MatchType: dlp.MatchKeyword, Pattern: "topsecret", Action: dlp.ActionBlock, Severity: dlp.SeverityHigh}); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	rules, err := svc.ListRules(ctx, tid)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != id || rules[0].Action != dlp.ActionBlock || rules[0].Pattern != "topsecret" {
		t.Fatalf("更新后应 1 条 id=%s block:topsecret,得 %+v", id, rules)
	}

	// Update 不存在 → ErrNotFound;非法正则 → 校验拒
	if err := svc.UpdateRule(ctx, tid, uuid.NewString(), &dlp.Rule{Name: "x", MatchType: dlp.MatchKeyword, Pattern: "p", Action: dlp.ActionAlert}); !errors.Is(err, dlp.ErrNotFound) {
		t.Fatalf("更新不存在规则应 ErrNotFound,得 %v", err)
	}
	if err := svc.UpdateRule(ctx, tid, id, &dlp.Rule{Name: "x", MatchType: dlp.MatchRegex, Pattern: "[", Action: dlp.ActionAlert}); err == nil || errors.Is(err, dlp.ErrNotFound) {
		t.Fatalf("非法正则更新应被校验拒,得 %v", err)
	}

	// RLS:跨租户改/删 → ErrNotFound,不误伤本租户
	other := uuid.NewString()
	if err := svc.UpdateRule(ctx, other, id, &dlp.Rule{Name: "x", MatchType: dlp.MatchKeyword, Pattern: "p", Action: dlp.ActionAlert}); !errors.Is(err, dlp.ErrNotFound) {
		t.Fatalf("跨租户更新应 ErrNotFound,得 %v", err)
	}
	if err := svc.DeleteRule(ctx, other, id); !errors.Is(err, dlp.ErrNotFound) {
		t.Fatalf("跨租户删除应 ErrNotFound,得 %v", err)
	}
	if got, _ := svc.ListRules(ctx, tid); len(got) != 1 {
		t.Fatalf("跨租户操作不应影响本租户规则,得 %+v", got)
	}

	// Delete → 成功;再 Delete → ErrNotFound
	if err := svc.DeleteRule(ctx, tid, id); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if got, _ := svc.ListRules(ctx, tid); len(got) != 0 {
		t.Fatalf("删除后应空,得 %+v", got)
	}
	if err := svc.DeleteRule(ctx, tid, id); !errors.Is(err, dlp.ErrNotFound) {
		t.Fatalf("删除已删规则应 ErrNotFound,得 %v", err)
	}
}
