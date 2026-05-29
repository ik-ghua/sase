package secret_test

// Slice34 secret 模块集成测试(VM 真 PG,需 SASE_DB_RW_DSN;未设则 SKIP)。
//   ① CreateTenantKey → tenant_keys 行存在(alg/kek_id 正确、wrapped_dek 非空、destroyed_at NULL)。
//   ② CreateTenantKey 重复 → ErrAlreadyExists(防意外重生 DEK,旧加密数据保住)。
//   ③ GetDEK → 返回 32B 明文 DEK(Provider Unwrap 还原)。
//   ④ DestroyTenantKey → wrapped_dek=NULL、destroyed_at 非空;**幂等**(再调不改 destroyed_at)。
//   ⑤ GetDEK 销毁后 → ErrDestroyed;IsDestroyed=true。
//   ⑥ tenant.Create + WithKeyCreator → tenant_keys 行**同事务建**;无 KeyCreator 选项 → tenant_keys 无行(向后兼容)。
//   ⑦ RLS:某租户的 InTxRO 看不到他租户的 tenant_keys 行(0 泄漏沿用项目纪律)。
// 前置:migrations 0001-0016。

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/secret"
	"github.com/ikuai8/sase/internal/tenant"
)

func newStore(t *testing.T) (data.Store, context.Context) {
	t.Helper()
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 secret 集成测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	t.Cleanup(store.Close)
	return store, ctx
}

// mkTenant 在该租户 RLS 上下文内插一行 tenants(满足 secret tenant_keys.tenant_id FK)。
//
//nolint:revive // 测试 helper:ctx 在 *testing.T 之后(项目测试惯例,与既有 platform_integration_test 一致)
func mkTenant(t *testing.T, ctx context.Context, store data.Store, tid string) {
	t.Helper()
	tenantSvc := tenant.NewService(store) // 不带 KeyCreator,纯建租户(给 secret 单独建 DEK)
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "sec-" + tid[:6]}); err != nil {
		t.Fatalf("建租户: %v", err)
	}
}

func newSecretSvc(t *testing.T, store data.Store) secret.Service {
	t.Helper()
	p, err := secret.NewDevProvider("")
	if err != nil {
		t.Fatalf("NewDevProvider: %v", err)
	}
	return secret.NewService(store, p)
}

func TestSecretCreateGetDestroy(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)

	tid := uuid.NewString()
	mkTenant(t, ctx, store, tid)

	// ① CreateTenantKey
	if err := svc.CreateTenantKey(ctx, tid); err != nil {
		t.Fatalf("CreateTenantKey: %v", err)
	}
	// 行存在 + 字段正确
	var alg, kekID string
	var hasWrapped, destroyed bool
	err := store.InTxRO(ctx, tid, func(q data.Queries) error {
		return q.QueryRow(ctx,
			`SELECT alg, kek_id, wrapped_dek IS NOT NULL, destroyed_at IS NOT NULL FROM tenant_keys WHERE tenant_id=$1`,
			tid).Scan(&alg, &kekID, &hasWrapped, &destroyed)
	})
	if err != nil {
		t.Fatalf("查 tenant_keys: %v", err)
	}
	if alg != secret.AlgChaCha20Poly1305 || kekID != "dev-mem" || !hasWrapped || destroyed {
		t.Fatalf("tenant_keys 字段错: alg=%s kek=%s hasWrapped=%v destroyed=%v", alg, kekID, hasWrapped, destroyed)
	}

	// ② 重复 Create → ErrAlreadyExists
	if err := svc.CreateTenantKey(ctx, tid); !errors.Is(err, secret.ErrAlreadyExists) {
		t.Fatalf("重复 Create 应 ErrAlreadyExists,得 %v", err)
	}

	// ③ GetDEK 返回 32B 明文
	dek, err := svc.GetDEK(ctx, tid)
	if err != nil {
		t.Fatalf("GetDEK: %v", err)
	}
	if len(dek) != 32 {
		t.Fatalf("DEK 长度应 32,得 %d", len(dek))
	}

	// ④ DestroyTenantKey → wrapped_dek=NULL + destroyed_at 非空
	if err := svc.DestroyTenantKey(ctx, tid); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	err = store.InTxRO(ctx, tid, func(q data.Queries) error {
		return q.QueryRow(ctx,
			`SELECT wrapped_dek IS NULL, destroyed_at IS NOT NULL FROM tenant_keys WHERE tenant_id=$1`,
			tid).Scan(&hasWrapped /*now means "is null"*/, &destroyed)
	})
	if err != nil || !hasWrapped || !destroyed {
		t.Fatalf("Destroy 后应 wrapped NULL + destroyed_at 非空,得 wrapped_null=%v destroyed=%v err=%v", hasWrapped, destroyed, err)
	}

	// ⑤ 幂等:再 Destroy 一次 → nil(不刷新 destroyed_at);GetDEK → ErrDestroyed;IsDestroyed=true
	if err := svc.DestroyTenantKey(ctx, tid); err != nil {
		t.Fatalf("幂等 Destroy 应 nil,得 %v", err)
	}
	if _, err := svc.GetDEK(ctx, tid); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("销毁后 GetDEK 应 ErrDestroyed,得 %v", err)
	}
	if d, _ := svc.IsDestroyed(ctx, tid); !d {
		t.Fatal("IsDestroyed 应 true")
	}

	// 不存在租户 → 各方法返 ErrNotFound
	other := uuid.NewString()
	if _, err := svc.GetDEK(ctx, other); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("不存在租户 GetDEK 应 ErrNotFound,得 %v", err)
	}
	if err := svc.DestroyTenantKey(ctx, other); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("不存在租户 Destroy 应 ErrNotFound,得 %v", err)
	}
}

func TestTenantCreateAtomicWithDEK(t *testing.T) {
	store, ctx := newStore(t)
	p, _ := secret.NewDevProvider("")
	secSvc := secret.NewService(store, p)

	// ⑥ 带 WithKeyCreator → tenant.Create 同事务建 DEK
	tenantSvc := tenant.NewService(store, tenant.WithKeyCreator(secSvc))
	tid := uuid.NewString()
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "atomic-T"}); err != nil {
		t.Fatalf("Create with KeyCreator: %v", err)
	}
	// tenant_keys 应有行
	if _, err := secSvc.GetDEK(ctx, tid); err != nil {
		t.Fatalf("Create 后 DEK 应已建,GetDEK 报: %v", err)
	}

	// 无 WithKeyCreator → 不建 DEK(向后兼容,既有测试不破)
	plain := tenant.NewService(store)
	tid2 := uuid.NewString()
	if err := plain.Create(ctx, &tenant.Tenant{ID: tid2, Name: "no-key-T"}); err != nil {
		t.Fatalf("Create 无 KeyCreator: %v", err)
	}
	if _, err := secSvc.GetDEK(ctx, tid2); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("无 KeyCreator 时 Create 不应建 DEK,GetDEK 期望 ErrNotFound,得 %v", err)
	}
}

func TestSecretTenantIsolation(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)
	tidA, tidB := uuid.NewString(), uuid.NewString()
	mkTenant(t, ctx, store, tidA)
	mkTenant(t, ctx, store, tidB)
	if err := svc.CreateTenantKey(ctx, tidA); err != nil {
		t.Fatalf("Create A: %v", err)
	}
	if err := svc.CreateTenantKey(ctx, tidB); err != nil {
		t.Fatalf("Create B: %v", err)
	}
	// ⑦ 在 A 的 RLS 上下文里,直查 B 的 tenant_keys 行应 0 行(RLS 隔离,沿用项目纪律)
	var n int
	err := store.InTxRO(ctx, tidA, func(q data.Queries) error {
		return q.QueryRow(ctx, `SELECT count(*) FROM tenant_keys WHERE tenant_id=$1`, tidB).Scan(&n)
	})
	if err != nil {
		t.Fatalf("查 B 在 A 上下文: %v", err)
	}
	if n != 0 {
		t.Fatalf("RLS 隔离失败:A 上下文看到 B 的 tenant_keys %d 行", n)
	}
}
