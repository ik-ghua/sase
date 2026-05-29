package platformrbac_test

// Slice38c platformrbac CRUD + IsActive 端到端(真实 PG):
//   ① Create:成功 + 空 subject 拒 + subject UNIQUE → 409;
//   ② Get/GetBySubject/List;
//   ③ Update PATCH(status/email);非法 status 拒;空 PATCH 拒;
//   ④ Delete + 不存在 → ErrAdminNotFound;
//   ⑤ IsActive:active→true;disabled→false;不存在→false(不报错)。
// 需 SASE_DB_RW_DSN + PLATFORM_DSN + PLATFORM_RW_DSN;前置 migrations 0001-0022。

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/platformrbac"
)

func TestPlatformRBACCRUD(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 PLATFORM_DSN + PLATFORM_RW_DSN,跳过")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := platformrbac.NewService(store)

	// last-admin 保护(Slice55)后,本测试要 disable/delete 自己的 admin,须保证表内另有 active admin,
	// 否则触发 ErrLastActiveAdmin。用固定 subject 幂等建一枚 keeper(忽略已存在)。
	if _, e := svc.Create(ctx, platformrbac.CreateRequest{Subject: "rbac-keeper", CreatedBy: "test"}); e != nil && !errors.Is(e, platformrbac.ErrAdminAlreadyExists) {
		t.Fatalf("建 keeper: %v", e)
	}

	subj := "rbac-test-" + uuid.NewString()[:8]

	// ① Create
	a, err := svc.Create(ctx, platformrbac.CreateRequest{Subject: subj, Email: "x@y", CreatedBy: "test"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a.ID == "" || a.Status != "active" || a.CreatedBy != "test" {
		t.Fatalf("Create 字段错: %+v", a)
	}
	// ① 空 subject 拒
	if _, err := svc.Create(ctx, platformrbac.CreateRequest{Subject: "  "}); !errors.Is(err, platformrbac.ErrInvalidAdminPatch) {
		t.Fatalf("空 subject 期望 ErrInvalidAdminPatch,得 %v", err)
	}
	// ① 重复 → 409
	if _, err := svc.Create(ctx, platformrbac.CreateRequest{Subject: subj}); !errors.Is(err, platformrbac.ErrAdminAlreadyExists) {
		t.Fatalf("重复 subject 期望 ErrAdminAlreadyExists,得 %v", err)
	}

	// ② Get / GetBySubject
	g, err := svc.Get(ctx, a.ID)
	if err != nil || g.Subject != subj {
		t.Fatalf("Get: %+v err=%v", g, err)
	}
	bs, err := svc.GetBySubject(ctx, subj)
	if err != nil || bs.ID != a.ID {
		t.Fatalf("GetBySubject: %+v err=%v", bs, err)
	}
	if _, err := svc.Get(ctx, "00000000-0000-0000-0000-000000000099"); !errors.Is(err, platformrbac.ErrAdminNotFound) {
		t.Fatalf("Get 不存在期望 ErrAdminNotFound,得 %v", err)
	}

	// ② List 含新建
	all, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, x := range all {
		if x.ID == a.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("List 应含新建 admin id=%s", a.ID)
	}

	// ⑤ IsActive
	if ok, err := svc.IsActive(ctx, subj); err != nil || !ok {
		t.Errorf("active subject IsActive 应 true,得 %v err=%v", ok, err)
	}
	if ok, err := svc.IsActive(ctx, "no-such-subject-"+uuid.NewString()[:6]); err != nil || ok {
		t.Errorf("不存在 IsActive 应 false 不报错,得 %v err=%v", ok, err)
	}

	// ③ Update status
	disabled := "disabled"
	u, err := svc.Update(ctx, a.ID, platformrbac.Patch{Status: &disabled})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if u.Status != "disabled" {
		t.Fatalf("status 应 disabled,得 %s", u.Status)
	}
	// IsActive 此时 false
	if ok, _ := svc.IsActive(ctx, subj); ok {
		t.Error("disabled subject IsActive 应 false")
	}
	// 非法 status
	bogus := "weird"
	if _, err := svc.Update(ctx, a.ID, platformrbac.Patch{Status: &bogus}); !errors.Is(err, platformrbac.ErrInvalidAdminPatch) {
		t.Fatalf("非法 status 期望 ErrInvalidAdminPatch,得 %v", err)
	}
	// 空 PATCH
	if _, err := svc.Update(ctx, a.ID, platformrbac.Patch{}); !errors.Is(err, platformrbac.ErrInvalidAdminPatch) {
		t.Fatalf("空 PATCH 期望 ErrInvalidAdminPatch,得 %v", err)
	}

	// ④ Delete + 不存在
	if err := svc.Delete(ctx, a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := svc.Delete(ctx, a.ID); !errors.Is(err, platformrbac.ErrAdminNotFound) {
		t.Fatalf("二次 Delete 期望 ErrAdminNotFound,得 %v", err)
	}
}

// wipeAdmins 清空 platform_admins(该表为 backend 测试 scratch,无前端依赖),建立确定性初态。
// last-admin 保护是「全局 active 计数」特性,必须独占该表才能确定性测试"最后一枚"。
func wipeAdmins(t *testing.T, ctx context.Context, store data.Store) {
	t.Helper()
	if e := store.InPlatformTxRW(ctx, func(q data.Queries) error {
		_, ex := q.Exec(ctx, "DELETE FROM platform_admins")
		return ex
	}); e != nil {
		t.Fatalf("清空 platform_admins: %v", e)
	}
}

// Slice55:last-admin 保护——不能停用/删除最后一枚 active 平台管理员(防锁死)。
func TestLastActiveAdminProtection(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 PLATFORM_DSN + PLATFORM_RW_DSN,跳过")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := platformrbac.NewService(store)
	wipeAdmins(t, ctx, store)

	disabled := "disabled"
	mk := func(tag string) *platformrbac.Admin {
		a, e := svc.Create(ctx, platformrbac.CreateRequest{Subject: "last-" + tag + "-" + uuid.NewString()[:8], CreatedBy: "test"})
		if e != nil {
			t.Fatalf("Create %s: %v", tag, e)
		}
		return a
	}

	// 只有一枚 active(A)→ 删/禁均拒
	A := mk("A")
	if e := svc.Delete(ctx, A.ID); !errors.Is(e, platformrbac.ErrLastActiveAdmin) {
		t.Fatalf("删最后一枚 active 期望 ErrLastActiveAdmin,得 %v", e)
	}
	if _, e := svc.Update(ctx, A.ID, platformrbac.Patch{Status: &disabled}); !errors.Is(e, platformrbac.ErrLastActiveAdmin) {
		t.Fatalf("禁最后一枚 active 期望 ErrLastActiveAdmin,得 %v", e)
	}

	// 两枚 active(A,B)→ 可禁 A
	B := mk("B")
	if _, e := svc.Update(ctx, A.ID, platformrbac.Patch{Status: &disabled}); e != nil {
		t.Fatalf("两枚 active 时禁 A 应成功,得 %v", e)
	}
	// 删 disabled 的 A → 允许(不减 active)
	if e := svc.Delete(ctx, A.ID); e != nil {
		t.Fatalf("删 disabled 的 A 应成功,得 %v", e)
	}
	// 现只剩 B active → 删 B 拒
	if e := svc.Delete(ctx, B.ID); !errors.Is(e, platformrbac.ErrLastActiveAdmin) {
		t.Fatalf("删最后一枚 active(B)期望 ErrLastActiveAdmin,得 %v", e)
	}
}

// Slice55:并发 TOCTOU——两 goroutine 各停用一枚 active(共 2 枚),guardLastActive 的 FOR UPDATE
// 序列化 → 恰一成功一被拒 → 终态保留 ≥1 active(若无 FOR UPDATE,两者各见 count=2 均放行 → 归零,本测会失败)。
func TestLastActiveAdminConcurrent(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 PLATFORM_DSN + PLATFORM_RW_DSN,跳过")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := platformrbac.NewService(store)
	wipeAdmins(t, ctx, store)

	disabled := "disabled"
	mk := func(tag string) *platformrbac.Admin {
		a, e := svc.Create(ctx, platformrbac.CreateRequest{Subject: "conc-" + tag + "-" + uuid.NewString()[:8], CreatedBy: "test"})
		if e != nil {
			t.Fatalf("Create %s: %v", tag, e)
		}
		return a
	}
	A, B := mk("A"), mk("B") // 2 枚 active

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []string{A.ID, B.ID} {
		wg.Add(1)
		go func(idx int, aid string) {
			defer wg.Done()
			_, errs[idx] = svc.Update(ctx, aid, platformrbac.Patch{Status: &disabled})
		}(i, id)
	}
	wg.Wait()

	rejected := 0
	for _, e := range errs {
		switch {
		case errors.Is(e, platformrbac.ErrLastActiveAdmin):
			rejected++
		case e != nil:
			t.Fatalf("非预期错误:%v", e)
		}
	}
	if rejected != 1 {
		t.Fatalf("并发停用两枚 active 应恰一被拒(FOR UPDATE 序列化),得 rejected=%d", rejected)
	}
	// 终态:仍保留 1 枚 active(未归零)
	all, e := svc.List(ctx)
	if e != nil {
		t.Fatalf("List: %v", e)
	}
	active := 0
	for _, a := range all {
		if a.Status == "active" {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("终态应保留 1 枚 active,得 %d", active)
	}
}
