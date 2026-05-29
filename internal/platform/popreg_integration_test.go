package platform_test

// Slice38a PopRegistry CRUD 端到端(真实 PG):
//   ① Create:成功 + 字段校验(空 name/region/endpoint 拒 + 负 max_users 拒)+ name UNIQUE → 409;
//   ② Get/List:成功 + 不存在 → ErrPopNotFound;
//   ③ Update:status/max_users PATCH 语义 + 非法 status 拒 + 不存在 → ErrPopNotFound;
//   ④ 不可改字段(name/region/endpoint)PATCH 不暴露(由 PopPatch 类型本身保证,这里只验 status/max_users 通路)。
// 需 SASE_DB_RW_DSN + SASE_DB_PLATFORM_DSN + SASE_DB_PLATFORM_RW_DSN;前置 migrations 0001-0019;未设则 SKIP。

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/platform"
)

func TestPopRegistryCRUD(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 SASE_DB_RW_DSN + PLATFORM_DSN + PLATFORM_RW_DSN,跳过 PopRegistry 测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	reg := platform.NewPopRegistry(store)

	// 用本测唯一前缀,避免与其它测试或既有 PoP 冲突(name UNIQUE)
	prefix := "test-pop-" + uniq(t)

	// ① Create 成功
	max := 1000
	created, err := reg.Create(ctx, platform.CreatePopRequest{
		Name: prefix + "-a", Region: "cn-east-1", Endpoint: "pop-a.example.com:443", MaxUsers: &max,
	})
	if err != nil {
		t.Fatalf("Create a: %v", err)
	}
	if created.ID == "" || created.Status != platform.PopStatusActive || created.MaxUsers == nil || *created.MaxUsers != 1000 {
		t.Fatalf("Create a 字段错: %+v", created)
	}
	if created.Endpoint != "pop-a.example.com:443" || created.Region != "cn-east-1" {
		t.Fatalf("Create a 字段错: %+v", created)
	}

	// ① Create 字段校验:空 name 拒
	if _, err := reg.Create(ctx, platform.CreatePopRequest{Name: "", Region: "x", Endpoint: "y"}); !errors.Is(err, platform.ErrInvalidPopPatch) {
		t.Fatalf("空 name 期望 ErrInvalidPopPatch,得 %v", err)
	}
	// ① 负 max_users 拒
	bad := -1
	if _, err := reg.Create(ctx, platform.CreatePopRequest{Name: prefix + "-bad", Region: "r", Endpoint: "e", MaxUsers: &bad}); !errors.Is(err, platform.ErrInvalidPopPatch) {
		t.Fatalf("负 max_users 期望 ErrInvalidPopPatch,得 %v", err)
	}
	// ① name 重复拒(name UNIQUE)
	if _, err := reg.Create(ctx, platform.CreatePopRequest{Name: prefix + "-a", Region: "cn-east-1", Endpoint: "x"}); !errors.Is(err, platform.ErrPopAlreadyExists) {
		t.Fatalf("重复 name 期望 ErrPopAlreadyExists,得 %v", err)
	}

	// ② Get 成功 + 不存在
	got, err := reg.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID || got.Name != created.Name {
		t.Fatalf("Get 不一致: %+v vs %+v", got, created)
	}
	if _, err := reg.Get(ctx, "00000000-0000-0000-0000-000000000001"); !errors.Is(err, platform.ErrPopNotFound) {
		t.Fatalf("Get 不存在期望 ErrPopNotFound,得 %v", err)
	}

	// ② List 含新建的
	all, err := reg.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, p := range all {
		if p.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("List 应含新建 PoP id=%s", created.ID)
	}

	// ③ Update status → draining(PATCH 语义:max_users 未提供,不动)
	drain := platform.PopStatusDraining
	updated, err := reg.Update(ctx, created.ID, platform.PopPatch{Status: &drain})
	if err != nil {
		t.Fatalf("Update status: %v", err)
	}
	if updated.Status != platform.PopStatusDraining {
		t.Fatalf("status 应为 draining,得 %s", updated.Status)
	}
	if updated.MaxUsers == nil || *updated.MaxUsers != 1000 {
		t.Fatalf("max_users 未提供,应保持 1000,得 %v", updated.MaxUsers)
	}
	// ③ Update max_users:status 不动
	newMax := 2000
	updated2, err := reg.Update(ctx, created.ID, platform.PopPatch{MaxUsers: &newMax})
	if err != nil {
		t.Fatalf("Update max_users: %v", err)
	}
	if updated2.MaxUsers == nil || *updated2.MaxUsers != 2000 {
		t.Fatalf("max_users 应为 2000,得 %v", updated2.MaxUsers)
	}
	if updated2.Status != platform.PopStatusDraining {
		t.Fatalf("status 未提供,应保持 draining,得 %s", updated2.Status)
	}
	// ③ 非法 status 拒
	bogus := "weird"
	if _, err := reg.Update(ctx, created.ID, platform.PopPatch{Status: &bogus}); !errors.Is(err, platform.ErrInvalidPopPatch) {
		t.Fatalf("非法 status 期望 ErrInvalidPopPatch,得 %v", err)
	}
	// ③ 空 PATCH 拒
	if _, err := reg.Update(ctx, created.ID, platform.PopPatch{}); !errors.Is(err, platform.ErrInvalidPopPatch) {
		t.Fatalf("空 PATCH 期望 ErrInvalidPopPatch,得 %v", err)
	}
	// ③ 不存在 PATCH
	if _, err := reg.Update(ctx, "00000000-0000-0000-0000-000000000002", platform.PopPatch{Status: &drain}); !errors.Is(err, platform.ErrPopNotFound) {
		t.Fatalf("不存在期望 ErrPopNotFound,得 %v", err)
	}
}

// TestPopRegistryNoRWPath:未配 SASE_DB_PLATFORM_RW_DSN 时,Create/Update 走 ErrNoPlatformRWPath(fail-loud)。
// (Get/List 走 InPlatformTx 只读路径,只要 PLATFORM_DSN 在仍可用。)
func TestPopRegistryNoRWPath(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" {
		t.Skip("未设 SASE_DB_RW_DSN + PLATFORM_DSN,跳过")
	}
	// 故意把 PlatformRWConnString 清空模拟未配
	cfg.PlatformRWConnString = ""
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	reg := platform.NewPopRegistry(store)
	if _, err := reg.Create(ctx, platform.CreatePopRequest{Name: "x", Region: "r", Endpoint: "e"}); !errors.Is(err, data.ErrNoPlatformRWPath) {
		t.Fatalf("无 PLATFORM_RW_DSN 时 Create 应返 ErrNoPlatformRWPath,得 %v", err)
	}
	status := platform.PopStatusDraining
	if _, err := reg.Update(ctx, "00000000-0000-0000-0000-000000000003", platform.PopPatch{Status: &status}); !errors.Is(err, data.ErrNoPlatformRWPath) {
		t.Fatalf("无 PLATFORM_RW_DSN 时 Update 应返 ErrNoPlatformRWPath,得 %v", err)
	}
}

// uniq 生成本测唯一短串(uuid 前 8 字符,避免重跑同名 PoP 撞 UNIQUE)。
func uniq(t *testing.T) string {
	t.Helper()
	return uuid.NewString()[:8]
}
