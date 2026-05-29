package platform_test

// Slice32 PC-API-0 跨租户数据路径地基:验证
//   ① 平台经 InPlatformTx + 策展视图 tenant_summary **跨租户**读到多个租户(不设 app.current_tenant)。
//   ② 隔离底线不破:app_platform_ro **NOBYPASSRLS**(靠策展视图授权跨租户,非角色绕 RLS,LP-PC6/CI G2)。
//   ③ app_platform_ro 对**基表 tenants 无授权**(只能经视图看安全字段,看不到基表)。
//   ④ 业务路径 RLS 仍生效:app_rw 在租户 A 上下文看不到租户 B(沿用 0 泄漏)。
// 需 SASE_DB_RW_DSN + SASE_DB_PLATFORM_DSN(app_platform_ro);未设则 SKIP。前置:migrations 0001 + 0013。

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/platform"
)

func newStore(t *testing.T) (data.Store, context.Context) {
	t.Helper()
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" {
		t.Skip("未设 SASE_DB_RW_DSN / SASE_DB_PLATFORM_DSN,跳过平台跨租户路径测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	t.Cleanup(store.Close)
	return store, ctx
}

// createTenant 以 app_rw 在该租户 RLS 上下文内插一行 tenants(id=current_tenant,WITH CHECK 通过)。
//
//nolint:revive // 测试 helper:ctx 在 *testing.T 之后(项目测试惯例)
func createTenant(t *testing.T, store data.Store, ctx context.Context, id, name string) {
	t.Helper()
	err := store.InTx(ctx, id, func(q data.Queries) error {
		_, e := q.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$2)`, id, name)
		return e
	})
	if err != nil {
		t.Fatalf("建租户 %s: %v", name, err)
	}
}

func TestPlatformCrossTenantRead(t *testing.T) {
	store, ctx := newStore(t)

	// 建两个租户(各在自身 RLS 上下文内创建)
	idA, idB := uuid.NewString(), uuid.NewString()
	createTenant(t, store, ctx, idA, "PC-A")
	createTenant(t, store, ctx, idB, "PC-B")

	// ① 平台跨租户读:一次调用应同时看到 A 与 B(无 app.current_tenant)
	svc := platform.NewService(store)
	ts, err := svc.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	seen := map[string]bool{}
	for _, x := range ts {
		seen[x.ID] = true
	}
	if !seen[idA] || !seen[idB] {
		t.Fatalf("平台应跨租户看到 A(%s)与 B(%s),得 %d 条租户", idA, idB, len(ts))
	}
}

func TestPlatformRoleIsMinimal(t *testing.T) {
	store, ctx := newStore(t)

	// ② app_platform_ro 必须 NOBYPASSRLS(跨租户靠策展视图授权,非角色绕 RLS;CI G2 不松动)
	var bypass bool
	if err := store.InPlatformTx(ctx, func(q data.Queries) error {
		return q.QueryRow(ctx, `SELECT rolbypassrls FROM pg_roles WHERE rolname='app_platform_ro'`).Scan(&bypass)
	}); err != nil {
		t.Fatalf("查角色属性: %v", err)
	}
	if bypass {
		t.Fatal("app_platform_ro 不应有 BYPASSRLS(LP-PC6:最小授权视图,非角色绕 RLS)")
	}

	// ③ app_platform_ro 对基表 tenants 无授权 → 直读基表应失败(只能经策展视图 tenant_summary)
	err := store.InPlatformTx(ctx, func(q data.Queries) error {
		var n int
		return q.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n)
	})
	if err == nil {
		t.Fatal("app_platform_ro 不应能直读基表 tenants(应仅经策展视图);却成功")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("直读 tenants 应因**无授权**被拒(permission denied),实际错误为: %v", err) // 收紧:确证是权限拒绝而非其它错
	}
}

func TestBusinessPathStillIsolated(t *testing.T) {
	store, ctx := newStore(t)

	idA, idB := uuid.NewString(), uuid.NewString()
	createTenant(t, store, ctx, idA, "ISO-A")
	createTenant(t, store, ctx, idB, "ISO-B")

	// ④ 业务路径 RLS 仍生效:在租户 A 的 RLS 上下文里,只能看到 A 自己(看不到 B)。
	err := store.InTxRO(ctx, idA, func(q data.Queries) error {
		var n int
		if e := q.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id=$1`, idB).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			t.Fatalf("租户 A 上下文不应看到租户 B(0 泄漏),却见到 %d 行", n)
		}
		// 看自己应可见
		if e := q.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id=$1`, idA).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			t.Fatalf("租户 A 上下文应看到自己,得 %d 行", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("业务路径隔离检查: %v", err)
	}
}
