package data_test

// 跨租户隔离集成测试:经真实 Go 数据层(pgx + RLS)验证 0 泄漏。
// 需要环境变量 SASE_DB_RW_DSN(及可选 SASE_DB_RO_DSN);未设则 SKIP。
// 前置:已对该库应用 migrations/0001_init(tenants/users + RLS + app_rw/app_ro)。
//
// 跑法(VM 上,PG 在本机):
//   SASE_DB_RW_DSN='postgres://app_rw:app_rw_dev@127.0.0.1:5432/sase' \
//   SASE_DB_RO_DSN='postgres://app_ro:app_ro_dev@127.0.0.1:5432/sase' \
//   go test ./internal/data/ -run TestRLS -v

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/tenant"
)

func newTestStore(t *testing.T) data.Store {
	t.Helper()
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过集成测试")
	}
	store, err := data.NewPgxStore(context.Background(), cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

// TestRLSCrossTenantIsolation:两租户各建用户,断言彼此不可见、无上下文 0 行。
func TestRLSCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	tenantSvc := tenant.NewService(store)
	idSvc := identity.NewService(store)

	ta := uuid.NewString()
	tb := uuid.NewString()
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: ta, Name: "TA"}); err != nil {
		t.Fatalf("建租户A: %v", err)
	}
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tb, Name: "TB"}); err != nil {
		t.Fatalf("建租户B: %v", err)
	}
	if err := idSvc.Create(ctx, &identity.User{ID: uuid.NewString(), TenantID: ta, ExternalID: "ua", Email: "ua@a.com"}); err != nil {
		t.Fatalf("建用户A: %v", err)
	}
	if err := idSvc.Create(ctx, &identity.User{ID: uuid.NewString(), TenantID: tb, ExternalID: "ub", Email: "ub@b.com"}); err != nil {
		t.Fatalf("建用户B: %v", err)
	}

	// A 上下文只见 A 的用户
	usA, err := idSvc.ListByTenant(ctx, ta)
	if err != nil {
		t.Fatalf("列A用户: %v", err)
	}
	for _, u := range usA {
		if u.TenantID != ta {
			t.Fatalf("租户A的查询泄漏了租户 %s 的用户 %s", u.TenantID, u.Email)
		}
	}
	if !containsEmail(usA, "ua@a.com") {
		t.Fatalf("租户A应能看到自己的用户 ua@a.com,实得 %v", usA)
	}
	if containsEmail(usA, "ub@b.com") {
		t.Fatalf("跨租户泄漏:租户A看到了租户B的 ub@b.com")
	}

	// B 上下文只见 B 的用户
	usB, err := idSvc.ListByTenant(ctx, tb)
	if err != nil {
		t.Fatalf("列B用户: %v", err)
	}
	if !containsEmail(usB, "ub@b.com") || containsEmail(usB, "ua@a.com") {
		t.Fatalf("租户B视图错误: %v", usB)
	}
}

// TestRLSNoTenantContextFailsClosed:空 tenantID 必须 fail-loud,不得跑查询。
func TestRLSNoTenantContextFailsClosed(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	err := store.InTxRO(ctx, "", func(q data.Queries) error {
		_, qerr := q.Query(ctx, "SELECT 1")
		return qerr
	})
	if err != data.ErrNoTenantContext {
		t.Fatalf("空租户上下文应返回 ErrNoTenantContext,实得: %v", err)
	}
}

// TestRLSCrossTenantReadInvisible:在 A 上下文下直接查 B 的用户行,应 0 行(SQL 级证明)。
func TestRLSCrossTenantReadInvisible(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	tenantSvc := tenant.NewService(store)
	idSvc := identity.NewService(store)

	ta := uuid.NewString()
	tb := uuid.NewString()
	bUser := uuid.NewString()
	mustCreate(t, tenantSvc, ta)
	mustCreate(t, tenantSvc, tb)
	if err := idSvc.Create(ctx, &identity.User{ID: bUser, TenantID: tb, ExternalID: "bx", Email: "bx@b.com"}); err != nil {
		t.Fatalf("建B用户: %v", err)
	}

	// 在 ta 上下文下按 B 的用户 id 直接查 —— RLS 应使其 0 行
	var cnt int
	err := store.InTxRO(ctx, ta, func(q data.Queries) error {
		return q.QueryRow(ctx, "SELECT count(*) FROM users WHERE id = $1", bUser).Scan(&cnt)
	})
	if err != nil {
		t.Fatalf("查询: %v", err)
	}
	if cnt != 0 {
		t.Fatalf("跨租户泄漏:租户A上下文按id查到了租户B的用户(cnt=%d)", cnt)
	}
}

func mustCreate(t *testing.T, svc tenant.Service, id string) {
	t.Helper()
	if err := svc.Create(context.Background(), &tenant.Tenant{ID: id, Name: id}); err != nil {
		t.Fatalf("建租户 %s: %v", id, err)
	}
}

func containsEmail(us []identity.User, email string) bool {
	for _, u := range us {
		if u.Email == email {
			return true
		}
	}
	return false
}
