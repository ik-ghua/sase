package identity_test

// Slice37a EnsureUserByExternalID:验证
//   ① 不存在 → 建,返新行;
//   ② 已存在 → 不重建(id 不变),邮箱以 IdP 最新值刷新;
//   ③ UNIQUE(tenant_id, external_id) 单点强约束兜底(同 external_id 不会产生两条);
//   ④ 跨租户同名 external_id 各自合法(联合 UNIQUE)。
// 需 SASE_DB_RW_DSN + migrations 0001-0018(0018 加 UNIQUE 约束);未设则 SKIP。

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestEnsureUserByExternalID(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	tenantSvc := tenant.NewService(store)
	idSvc := identity.NewService(store)

	tidA := uuid.NewString()
	tidB := uuid.NewString()
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tidA, Name: "TA"}); err != nil {
		t.Fatalf("建租户 A: %v", err)
	}
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tidB, Name: "TB"}); err != nil {
		t.Fatalf("建租户 B: %v", err)
	}

	// ① 首次 EnsureUser:建
	u1, err := idSvc.EnsureUserByExternalID(ctx, tidA, "", "alice-sub", "alice@a.com")
	if err != nil {
		t.Fatalf("首次 ensure: %v", err)
	}
	if u1.ID == "" || u1.TenantID != tidA || u1.ExternalID != "alice-sub" || u1.Email != "alice@a.com" || u1.Status != "active" {
		t.Fatalf("首次 ensure 字段错: %+v", u1)
	}
	// ② 二次 ensure:不重建(id 不变),邮箱刷新
	u2, err := idSvc.EnsureUserByExternalID(ctx, tidA, "", "alice-sub", "alice@new.com")
	if err != nil {
		t.Fatalf("二次 ensure: %v", err)
	}
	if u2.ID != u1.ID {
		t.Fatalf("二次 ensure 不应重建,id %s→%s", u1.ID, u2.ID)
	}
	if u2.Email != "alice@new.com" {
		t.Fatalf("二次 ensure 邮箱未刷新:got %s want alice@new.com", u2.Email)
	}
	// ③ 跨租户同 external_id 各自合法
	uB, err := idSvc.EnsureUserByExternalID(ctx, tidB, "", "alice-sub", "alice@b.com")
	if err != nil {
		t.Fatalf("跨租户 ensure: %v", err)
	}
	if uB.ID == u1.ID || uB.TenantID != tidB {
		t.Fatalf("跨租户应是不同用户,got %+v", uB)
	}

	// ④ 并发 EnsureUser:不会建出两条(UNIQUE 约束兜底)
	const N = 8
	var wg sync.WaitGroup
	ids := make([]string, N)
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			u, e := idSvc.EnsureUserByExternalID(ctx, tidA, "", "bob-sub", "bob@a.com")
			ids[idx] = u.ID
			errs[idx] = e
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("并发 ensure[%d]: %v", i, e)
		}
	}
	first := ids[0]
	for i, id := range ids {
		if id != first {
			t.Fatalf("并发 ensure 应全部返回同一用户:[%d]=%s vs [0]=%s(UNIQUE 约束未生效?)", i, id, first)
		}
	}
}
