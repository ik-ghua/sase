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
