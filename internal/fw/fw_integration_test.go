package fw_test

// FWaaS 规则编写端到端:CreateRule/ListRules 经真实 PG(RLS)+ 按 priority 升序 + 校验。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:已应用 migrations 0010。

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/fw"
)

func TestFWAuthoring(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 FWaaS 规则编写测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	svc := fw.NewService(store)
	tid := uuid.NewString()

	// 乱序优先级插入,ListRules 应按 priority 升序返回
	if err := svc.CreateRule(ctx, tid, &fw.Rule{Priority: 10, Action: fw.ActionAllow, Protocol: fw.ProtoTCP, DstCIDR: "10.2.0.0/24", DstPortMin: 80, DstPortMax: 80}); err != nil {
		t.Fatalf("CreateRule allow: %v", err)
	}
	if err := svc.CreateRule(ctx, tid, &fw.Rule{Priority: 1, Action: fw.ActionDeny, Protocol: fw.ProtoTCP, DstCIDR: "10.2.0.9/32", DstPortMin: 22, DstPortMax: 22}); err != nil {
		t.Fatalf("CreateRule deny: %v", err)
	}
	rules, err := svc.ListRules(ctx, tid)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 2 || rules[0].Priority != 1 || rules[1].Priority != 10 {
		t.Fatalf("应按 priority 升序返回 2 条,得 %+v", rules)
	}
	if rules[0].Action != fw.ActionDeny || rules[1].DstPortMin != 80 {
		t.Fatalf("字段未正确往返: %+v", rules)
	}

	// 校验:非法 action / 非法 cidr / 端口区间反转 → 拒绝入库
	if err := svc.CreateRule(ctx, tid, &fw.Rule{Action: "bogus"}); err == nil {
		t.Fatal("非法 action 应被拒")
	}
	if err := svc.CreateRule(ctx, tid, &fw.Rule{Action: fw.ActionAllow, DstCIDR: "nope"}); err == nil {
		t.Fatal("非法 cidr 应被拒")
	}
	if err := svc.CreateRule(ctx, tid, &fw.Rule{Action: fw.ActionAllow, DstPortMin: 100, DstPortMax: 50}); err == nil {
		t.Fatal("端口区间反转应被拒")
	}
}

// Slice62 FWaaS 规则生命周期(真 PG,RLS):Create 回填 id → Update 改字段 → Delete → 不存在/跨租户 → ErrNotFound。
func TestFWRuleLifecycle(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 FWaaS 规则生命周期测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	svc := fw.NewService(store)
	tid := uuid.NewString()

	r := &fw.Rule{Priority: 5, Action: fw.ActionDeny, Protocol: fw.ProtoTCP, DstCIDR: "10.9.0.0/24", DstPortMin: 22, DstPortMax: 22}
	if err := svc.CreateRule(ctx, tid, r); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if r.ID == "" {
		t.Fatal("CreateRule 应回填 r.ID")
	}
	id := r.ID

	// Update:改为 allow + 改端口
	if err := svc.UpdateRule(ctx, tid, id, &fw.Rule{Priority: 5, Action: fw.ActionAllow, Protocol: fw.ProtoTCP, DstCIDR: "10.9.0.0/24", DstPortMin: 443, DstPortMax: 443}); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	rules, err := svc.ListRules(ctx, tid)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != id || rules[0].Action != fw.ActionAllow || rules[0].DstPortMin != 443 {
		t.Fatalf("更新后应 1 条 id=%s allow:443,得 %+v", id, rules)
	}

	// Update 不存在 → ErrNotFound;非法 cidr → 校验拒
	if err := svc.UpdateRule(ctx, tid, uuid.NewString(), &fw.Rule{Action: fw.ActionAllow}); !errors.Is(err, fw.ErrNotFound) {
		t.Fatalf("更新不存在规则应 ErrNotFound,得 %v", err)
	}
	if err := svc.UpdateRule(ctx, tid, id, &fw.Rule{Action: fw.ActionAllow, DstCIDR: "nope"}); err == nil || errors.Is(err, fw.ErrNotFound) {
		t.Fatalf("非法 cidr 更新应被校验拒,得 %v", err)
	}

	// RLS:跨租户改/删 → ErrNotFound,不误伤本租户
	other := uuid.NewString()
	if err := svc.UpdateRule(ctx, other, id, &fw.Rule{Action: fw.ActionDeny}); !errors.Is(err, fw.ErrNotFound) {
		t.Fatalf("跨租户更新应 ErrNotFound,得 %v", err)
	}
	if err := svc.DeleteRule(ctx, other, id); !errors.Is(err, fw.ErrNotFound) {
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
	if err := svc.DeleteRule(ctx, tid, id); !errors.Is(err, fw.ErrNotFound) {
		t.Fatalf("删除已删规则应 ErrNotFound,得 %v", err)
	}
}
