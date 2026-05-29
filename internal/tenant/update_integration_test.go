package tenant_test

// Slice33(b) PC-API-2a 租户部分更新(PATCH)集成测试:验证
//   ① 改 status(停用/恢复)、改 name 生效;PATCH 语义(nil 字段不改);
//   ② 非法 status 拒;无字段 → ErrNoPatchFields;不存在租户 → ErrNotFound;
//   ③ 走业务 InTx(目标租户 RLS 上下文),RLS WITH CHECK 只动该租户行(0 泄漏不破)。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:migrations 0001。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/tenant"
)

func strptr(s string) *string { return &s }
func intptr(i int) *int       { return &i }

func TestTenantUpdate(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过租户 PATCH 测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := tenant.NewService(store)

	tid := uuid.NewString()
	if err := svc.Create(ctx, &tenant.Tenant{ID: tid, Name: "PATCH-T", Status: "active"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}

	// ① 改 status → suspended(只传 status,name 不变)
	got, err := svc.Update(ctx, tid, tenant.Patch{Status: strptr("suspended")})
	if err != nil {
		t.Fatalf("Update status: %v", err)
	}
	if got.Status != "suspended" || got.Name != "PATCH-T" {
		t.Fatalf("应 status=suspended、name 不变,得 %+v", got)
	}

	// 改 name(只传 name,status 应仍 suspended)
	got, err = svc.Update(ctx, tid, tenant.Patch{Name: strptr("PATCH-T2")})
	if err != nil {
		t.Fatalf("Update name: %v", err)
	}
	if got.Name != "PATCH-T2" || got.Status != "suspended" {
		t.Fatalf("应 name 改、status 留 suspended(PATCH 语义),得 %+v", got)
	}

	// 恢复 active
	if got, err = svc.Update(ctx, tid, tenant.Patch{Status: strptr("active")}); err != nil || got.Status != "active" {
		t.Fatalf("恢复 active 失败: %+v err=%v", got, err)
	}

	// ② 非法 status → 错误(不写)
	if _, err := svc.Update(ctx, tid, tenant.Patch{Status: strptr("bogus")}); err == nil {
		t.Fatal("非法 status 应被拒")
	}
	// 无字段 → ErrNoPatchFields
	if _, err := svc.Update(ctx, tid, tenant.Patch{}); !errors.Is(err, tenant.ErrNoPatchFields) {
		t.Fatalf("空 patch 应 ErrNoPatchFields,得 %v", err)
	}
	// 不存在租户 → ErrNotFound
	if _, err := svc.Update(ctx, uuid.NewString(), tenant.Patch{Name: strptr("x")}); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("不存在租户应 ErrNotFound,得 %v", err)
	}

	// ③ 跨租户不泄漏:在租户 tid 的 PATCH 不会动到另一租户。建第二租户,确认其不受影响。
	tid2 := uuid.NewString()
	if err := svc.Create(ctx, &tenant.Tenant{ID: tid2, Name: "OTHER", Status: "active"}); err != nil {
		t.Fatalf("建租户2: %v", err)
	}
	if _, err := svc.Update(ctx, tid, tenant.Patch{Status: strptr("offboarding")}); err != nil {
		t.Fatalf("Update tid: %v", err)
	}
	t2, err := svc.Get(ctx, tid2)
	if err != nil || t2.Status != "active" || t2.Name != "OTHER" {
		t.Fatalf("租户2 不应受租户1 的 PATCH 影响,得 %+v err=%v", t2, err)
	}
}

func TestTenantPlanAndQuotaPATCH(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 plan/quota PATCH 测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := tenant.NewService(store)

	tid := uuid.NewString()
	if err := svc.Create(ctx, &tenant.Tenant{ID: tid, Name: "PQ", Status: "active"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}
	// 新建租户默认 plan='standard'、配额 nil(不限)
	g, err := svc.Get(ctx, tid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g.Plan != "standard" || g.MaxUsers != nil || g.MaxPolicies != nil || g.MaxBandwidthMbps != nil {
		t.Fatalf("默认应 plan=standard、配额全 nil,得 %+v", g)
	}

	// PATCH plan=gm + max_users=100
	got, err := svc.Update(ctx, tid, tenant.Patch{Plan: strptr("gm"), MaxUsers: intptr(100)})
	if err != nil {
		t.Fatalf("Update plan+quota: %v", err)
	}
	if got.Plan != "gm" || got.MaxUsers == nil || *got.MaxUsers != 100 {
		t.Fatalf("应 plan=gm、max_users=100,得 %+v", got)
	}

	// PATCH 其它配额(独立设)
	got, err = svc.Update(ctx, tid, tenant.Patch{MaxPolicies: intptr(500), MaxBandwidthMbps: intptr(1000)})
	if err != nil {
		t.Fatalf("Update quotas: %v", err)
	}
	if got.MaxPolicies == nil || *got.MaxPolicies != 500 || got.MaxBandwidthMbps == nil || *got.MaxBandwidthMbps != 1000 {
		t.Fatalf("应配额齐设,得 %+v", got)
	}
	// 之前的 max_users 不应被本次 PATCH 清掉(PATCH 语义)
	if got.MaxUsers == nil || *got.MaxUsers != 100 {
		t.Fatalf("PATCH 不应影响未提供的 max_users,得 %+v", got)
	}

	// 校验:plan 空 → 400-类
	if _, err := svc.Update(ctx, tid, tenant.Patch{Plan: strptr("")}); !errors.Is(err, tenant.ErrInvalidPatch) {
		t.Fatalf("plan 空应 ErrInvalidPatch,得 %v", err)
	}
	// 校验:负配额 → 400-类
	if _, err := svc.Update(ctx, tid, tenant.Patch{MaxUsers: intptr(-1)}); !errors.Is(err, tenant.ErrInvalidPatch) {
		t.Fatalf("负配额应 ErrInvalidPatch,得 %v", err)
	}
}

func TestTenantDecommission(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过租户注销测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := tenant.NewService(store)

	tid := uuid.NewString()
	if err := svc.Create(ctx, &tenant.Tenant{ID: tid, Name: "DECO", Status: "active"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}

	// 进入注销宽限期(1h)→ offboarding + decommission_at ≈ now+1h
	before := time.Now()
	got, err := svc.Decommission(ctx, tid, time.Hour)
	if err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if got.Status != "offboarding" || got.DecommissionAt == nil {
		t.Fatalf("应 offboarding + decommission_at 非空,得 %+v", got)
	}
	if got.DecommissionAt.Before(before.Add(30*time.Minute)) || got.DecommissionAt.After(before.Add(90*time.Minute)) {
		t.Fatalf("decommission_at 应约 now+1h,得 %v(基准 %v)", got.DecommissionAt, before)
	}
	// Get 也应见 offboarding 调度
	if g, _ := svc.Get(ctx, tid); g.Status != "offboarding" || g.DecommissionAt == nil {
		t.Fatalf("Get 应见注销调度,得 %+v", g)
	}

	// 宽限期内取消 → active + decommission_at 清空
	got, err = svc.CancelDecommission(ctx, tid)
	if err != nil {
		t.Fatalf("CancelDecommission: %v", err)
	}
	if got.Status != "active" || got.DecommissionAt != nil {
		t.Fatalf("取消后应 active + decommission_at 空,得 %+v", got)
	}
	// 再次取消(已非 offboarding)→ ErrNotDecommissioning
	if _, err := svc.CancelDecommission(ctx, tid); !errors.Is(err, tenant.ErrNotDecommissioning) {
		t.Fatalf("非 offboarding 取消应 ErrNotDecommissioning,得 %v", err)
	}
	// grace<=0 → ErrInvalidPatch
	if _, err := svc.Decommission(ctx, tid, 0); !errors.Is(err, tenant.ErrInvalidPatch) {
		t.Fatalf("grace<=0 应 ErrInvalidPatch,得 %v", err)
	}
	// 不存在租户 → ErrNotFound
	if _, err := svc.Decommission(ctx, uuid.NewString(), time.Hour); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("不存在租户应 ErrNotFound,得 %v", err)
	}
}
