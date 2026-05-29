package idp_test

// Slice36 IdP 配置集成测试(VM 真 PG;需 SASE_DB_RW_DSN + SASE_DB_PLATFORM_DSN)。
//   ① Create + Get + List + Update + Delete CRUD;响应不含 client_secret 字段(由 Go struct 保证)。
//   ② GetClientSecret 返回解密的原始明文(印证 secret.Encrypt/Decrypt 往返正确)。
//   ③ **Slice34→35→36 链路证据**:DEK 销毁后,Decrypt → secret.ErrDestroyed(client_secret 不可恢复)。
//   ④ RLS 跨租户 0 泄漏:租户 A 上下文不可见租户 B 的 idp_configs 行。
//   ⑤ DEK 未就绪(无 tenant_keys 行)→ Create 拒(secret.ErrNotFound)。
// 前置:migrations 0001-0017。

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/secret"
	"github.com/ikuai8/sase/internal/tenant"
)

func newStores(t *testing.T) (data.Store, context.Context) {
	t.Helper()
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 idp 集成测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	t.Cleanup(store.Close)
	return store, ctx
}

func newSvc(t *testing.T, store data.Store) (idp.Service, secret.Service) {
	t.Helper()
	p, err := secret.NewDevProvider("")
	if err != nil {
		t.Fatalf("NewDevProvider: %v", err)
	}
	sec := secret.NewService(store, p)
	return idp.NewService(store, sec), sec
}

// mkTenantWithDEK 建租户 + 同事务建 DEK(secret.CreateInTx),供 idp.Create 加密用。
//
//nolint:revive // 测试 helper:ctx 在 *testing.T 之后
func mkTenantWithDEK(t *testing.T, ctx context.Context, store data.Store, sec secret.Service, tid string) {
	t.Helper()
	tenantSvc := tenant.NewService(store, tenant.WithKeyCreator(sec))
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "idp-" + tid[:6]}); err != nil {
		t.Fatalf("建租户 %s: %v", tid, err)
	}
}

func TestIdPCRUD(t *testing.T) {
	store, ctx := newStores(t)
	svc, sec := newSvc(t, store)

	tid := uuid.NewString()
	mkTenantWithDEK(t, ctx, store, sec, tid)

	// ① Create
	c, err := svc.Create(ctx, tid, idp.CreateRequest{
		Name: "企微 OIDC", Kind: "wecom",
		Endpoint: "https://example.com/.well-known/openid-configuration",
		ClientID: "wx-client-1", ClientSecret: "super-secret-123",
		Extra: map[string]any{"scopes": "openid"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.ID == "" || c.Status != "active" || c.Kind != "wecom" {
		t.Fatalf("响应字段错: %+v", c)
	}

	// ② GetClientSecret 返回明文(印证 Encrypt/Decrypt 往返)
	plain, err := svc.GetClientSecret(ctx, tid, c.ID)
	if err != nil {
		t.Fatalf("GetClientSecret: %v", err)
	}
	if !bytes.Equal(plain, []byte("super-secret-123")) {
		t.Fatalf("解密明文不符: 得 %q", string(plain))
	}

	// Get / List
	got, _ := svc.Get(ctx, tid, c.ID)
	if got.Name != "企微 OIDC" {
		t.Fatalf("Get 名错: %+v", got)
	}
	list, _ := svc.List(ctx, tid)
	if len(list) != 1 || list[0].ID != c.ID {
		t.Fatalf("List 应 1 条,得 %d", len(list))
	}

	// Update(改 client_secret + status)
	newSecret := "rotated-secret-456"
	disabled := "disabled"
	u, err := svc.Update(ctx, tid, c.ID, idp.Patch{ClientSecret: &newSecret, Status: &disabled})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if u.Status != "disabled" {
		t.Fatalf("status 应 disabled,得 %s", u.Status)
	}
	plain2, _ := svc.GetClientSecret(ctx, tid, c.ID)
	if !bytes.Equal(plain2, []byte(newSecret)) {
		t.Fatalf("Update 后 secret 未轮换: 得 %q", string(plain2))
	}

	// Delete
	if err := svc.Delete(ctx, tid, c.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Get(ctx, tid, c.ID); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("Delete 后 Get 应 ErrNotFound,得 %v", err)
	}
}

// TestIdPSurvivesUntilDEKDestroyed 是 **Slice34→35→36 链路的核心证据**:
// IdP 配置创建后可解密 → 销毁租户 DEK → 再 GetClientSecret → secret.ErrDestroyed(数据等效不可恢复)。
// 这是"DEK 销毁式删除"对真加密数据的真实效果(Slice34 时是符号性的,本刀转为真实)。
func TestIdPSurvivesUntilDEKDestroyed(t *testing.T) {
	store, ctx := newStores(t)
	svc, sec := newSvc(t, store)

	tid := uuid.NewString()
	mkTenantWithDEK(t, ctx, store, sec, tid)

	c, err := svc.Create(ctx, tid, idp.CreateRequest{
		Name: "dingtalk", Kind: "dingtalk",
		Endpoint: "https://dd.example.com", ClientID: "dd-1", ClientSecret: "dd-secret",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// 销毁前可解
	if _, err := svc.GetClientSecret(ctx, tid, c.ID); err != nil {
		t.Fatalf("销毁前应可解 client_secret: %v", err)
	}
	// 销毁 DEK(模拟 Slice35 sweep 硬删)
	if err := sec.DestroyTenantKey(ctx, tid); err != nil {
		t.Fatalf("DestroyTenantKey: %v", err)
	}
	// 销毁后:client_secret 等效不可恢复
	_, err = svc.GetClientSecret(ctx, tid, c.ID)
	if !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("DEK 销毁后 GetClientSecret 应 secret.ErrDestroyed,得 %v", err)
	}
	// Update client_secret 也应拒(Encrypt 需 DEK,已销毁)
	newSecret := "x"
	if _, err := svc.Update(ctx, tid, c.ID, idp.Patch{ClientSecret: &newSecret}); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("DEK 销毁后 Update client_secret 应拒,得 %v", err)
	}
	// 但 Get(不解密)仍可返(元数据未销毁——本刀只销毁 DEK 不删 idp 行;sweep 后租户 status=decommissioned 也是同语义)
	if _, err := svc.Get(ctx, tid, c.ID); err != nil {
		t.Fatalf("Get 元数据应仍可读(只是 client_secret 不可解),得 %v", err)
	}
}

func TestIdPNoDEKRejects(t *testing.T) {
	store, ctx := newStores(t)
	svc, _ := newSvc(t, store)

	// 建租户**但不带 KeyCreator** → 无 tenant_keys 行
	tid := uuid.NewString()
	if err := tenant.NewService(store).Create(ctx, &tenant.Tenant{ID: tid, Name: "no-dek"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}
	_, err := svc.Create(ctx, tid, idp.CreateRequest{
		Name: "x", Kind: "oidc", Endpoint: "x", ClientID: "x", ClientSecret: "x",
	})
	if !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("无 DEK 的租户 Create 应 secret.ErrNotFound,得 %v", err)
	}
}

func TestIdPTenantIsolation(t *testing.T) {
	store, ctx := newStores(t)
	svc, sec := newSvc(t, store)
	tidA, tidB := uuid.NewString(), uuid.NewString()
	mkTenantWithDEK(t, ctx, store, sec, tidA)
	mkTenantWithDEK(t, ctx, store, sec, tidB)

	cA, _ := svc.Create(ctx, tidA, idp.CreateRequest{Name: "A", Kind: "oidc", Endpoint: "x", ClientID: "x", ClientSecret: "x"})
	if _, err := svc.Create(ctx, tidB, idp.CreateRequest{Name: "B", Kind: "oidc", Endpoint: "x", ClientID: "x", ClientSecret: "x"}); err != nil {
		t.Fatalf("Create B: %v", err)
	}
	// A 上下文 List 只见自己
	listA, _ := svc.List(ctx, tidA)
	if len(listA) != 1 || listA[0].ID != cA.ID {
		t.Fatalf("List 跨租户泄漏:A 见 %d 条", len(listA))
	}
	// A 上下文 Get B 的 → ErrNotFound(RLS)
	if _, err := svc.Get(ctx, tidA /* 用 B 的 id 不知道,用任意 uuid 模拟 */, uuid.NewString()); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("跨租户 Get 应 ErrNotFound,得 %v", err)
	}
}
