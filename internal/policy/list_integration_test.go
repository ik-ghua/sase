package policy_test

// Slice58 policy.ListByTenant 端到端(真实 PG):创建 → 列出(按 priority 序)+ RLS 跨租户隔离。
// 需 SASE_DB_RW_DSN + SASE_DB_RO_DSN;前置 migrations 0001-0002。

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/policy"
)

func TestPolicyListByTenant(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN/RO_DSN,跳过")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := policy.NewService(store)

	tid := uuid.NewString()
	p1 := &policy.Policy{Name: "p-hi", Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app-a", Action: "access", Effect: "allow"}
	p2 := &policy.Policy{Name: "p-lo", Priority: 50, SubjectKind: "risk_gte", SubjectValue: "critical", Resource: "app-b", Action: "access", Effect: "deny"}
	if e := svc.CreatePolicy(ctx, tid, p1); e != nil {
		t.Fatalf("create p1: %v", e)
	}
	if e := svc.CreatePolicy(ctx, tid, p2); e != nil {
		t.Fatalf("create p2: %v", e)
	}

	ps, e := svc.ListByTenant(ctx, tid)
	if e != nil {
		t.Fatalf("ListByTenant: %v", e)
	}
	if len(ps) != 2 {
		t.Fatalf("应 2 条,得 %d", len(ps))
	}
	// 按 priority,id 排序:p1(10)在前
	if ps[0].Priority != 10 || ps[1].Priority != 50 {
		t.Fatalf("应按 priority 升序,得 %d,%d", ps[0].Priority, ps[1].Priority)
	}
	if ps[0].Name != "p-hi" || ps[0].Effect != "allow" || ps[0].Resource != "app-a" {
		t.Fatalf("字段错: %+v", ps[0])
	}

	// RLS 跨租户隔离:另一租户 list 不含本租户策略
	other := uuid.NewString()
	op, e := svc.ListByTenant(ctx, other)
	if e != nil {
		t.Fatalf("ListByTenant(other): %v", e)
	}
	for _, p := range op {
		if p.ID == p1.ID || p.ID == p2.ID {
			t.Fatalf("RLS 跨租户泄漏!other 租户列到了 tid=%s 的策略 %s", tid, p.ID)
		}
	}
}
