package fw_test

// FWaaS 规则编写端到端:CreateRule/ListRules 经真实 PG(RLS)+ 按 priority 升序 + 校验。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:已应用 migrations 0010。

import (
	"context"
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
