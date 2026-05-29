package swg_test

// Slice62 SWG 规则生命周期(真 PG,RLS):Create 回填 id → Update 改字段 → Delete 删除 →
// 不存在 id → ErrNotFound → 跨租户 Update/Delete 被 RLS 隔离(0 行 → ErrNotFound,不误伤本租户)。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:已应用 migrations 0005。

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/swg"
)

func TestSWGRuleLifecycle(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 SWG 规则生命周期测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	svc := swg.NewService(store)
	tid := uuid.NewString()

	r := &swg.Rule{Kind: swg.KindHost, Pattern: "evil.com", Action: swg.ActionBlock}
	if err := svc.CreateRule(ctx, tid, r); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if r.ID == "" {
		t.Fatal("CreateRule 应回填 r.ID")
	}
	id := r.ID

	// Update:全量替换改 pattern
	if err := svc.UpdateRule(ctx, tid, id, &swg.Rule{Kind: swg.KindHost, Pattern: "worse.com", Action: swg.ActionBlock}); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	rules, err := svc.ListRules(ctx, tid)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != id || rules[0].Pattern != "worse.com" {
		t.Fatalf("更新后应 1 条 id=%s pattern=worse.com,得 %+v", id, rules)
	}

	// Update 不存在 id → ErrNotFound
	if err := svc.UpdateRule(ctx, tid, uuid.NewString(), &swg.Rule{Kind: swg.KindHost, Pattern: "x.com"}); !errors.Is(err, swg.ErrNotFound) {
		t.Fatalf("更新不存在规则应 ErrNotFound,得 %v", err)
	}
	// Update 非法 kind → 校验拒(改规则与建规则同等约束,且非 ErrNotFound)
	if err := svc.UpdateRule(ctx, tid, id, &swg.Rule{Kind: "bogus", Pattern: "y.com"}); err == nil || errors.Is(err, swg.ErrNotFound) {
		t.Fatalf("非法 kind 更新应被校验拒,得 %v", err)
	}

	// RLS:另一租户不能改/删本租户规则(0 行 → ErrNotFound),且不误伤本租户
	other := uuid.NewString()
	if err := svc.UpdateRule(ctx, other, id, &swg.Rule{Kind: swg.KindHost, Pattern: "z.com"}); !errors.Is(err, swg.ErrNotFound) {
		t.Fatalf("跨租户更新应 ErrNotFound(RLS 隔离),得 %v", err)
	}
	if err := svc.DeleteRule(ctx, other, id); !errors.Is(err, swg.ErrNotFound) {
		t.Fatalf("跨租户删除应 ErrNotFound(RLS 隔离),得 %v", err)
	}
	if got, _ := svc.ListRules(ctx, tid); len(got) != 1 || got[0].Pattern != "worse.com" {
		t.Fatalf("跨租户操作不应影响本租户规则,得 %+v", got)
	}

	// Delete 本租户 → 成功;List 空;再 Delete → ErrNotFound
	if err := svc.DeleteRule(ctx, tid, id); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if got, _ := svc.ListRules(ctx, tid); len(got) != 0 {
		t.Fatalf("删除后应空,得 %+v", got)
	}
	if err := svc.DeleteRule(ctx, tid, id); !errors.Is(err, swg.ErrNotFound) {
		t.Fatalf("删除已删规则应 ErrNotFound,得 %v", err)
	}
}
