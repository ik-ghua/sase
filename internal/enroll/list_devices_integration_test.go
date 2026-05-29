package enroll_test

// ListDevices(ZTP 可见性,M2)端到端:列租户已登记设备。需 SASE_DB_RW_DSN(device_enrollments 走 RLS);
// 未设则 SKIP。前置:已应用 migrations 0001-0009。覆盖:
//   ① 列出 + 按 created_at 升序 + 字段正确(含兑换后 status/redeemed_at)。
//   ② **RLS 跨租户隔离实证**:tA 的列表绝不含 tB 的设备,反之亦然。
//   ③ 空租户 → 非 nil 空切片(序列化为 [])。
//   ④ **不暴露敏感字段**:Device 结构体无 activation_code 字段(编译期保证),此处再断言 identity 非空、未泄漏码。

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/enroll"
)

func TestListDevices(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 ListDevices 端到端测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	svc := enroll.NewService(store, ca)

	tA := uuid.NewString()
	tB := uuid.NewString()

	// 安全护栏:Device 结构体绝不能有 activation_code(激活码=秘密)。编译期+反射双保险。
	dt := reflect.TypeOf(enroll.Device{})
	for i := 0; i < dt.NumField(); i++ {
		name := dt.Field(i).Name
		if name == "ActivationCode" || name == "Code" || name == "Secret" {
			t.Fatalf("enroll.Device 不得暴露敏感字段,发现 %q", name)
		}
	}

	// tA:预置两台设备(web=connector、site1=cpe);web 兑换以验 status/redeemed_at。
	if _, err := svc.CreateEnrollment(ctx, tA, enroll.KindConnector, "web"); err != nil {
		t.Fatalf("CreateEnrollment tA/web: %v", err)
	}
	codeSite1, err := svc.CreateEnrollment(ctx, tA, enroll.KindCPE, "site1")
	if err != nil {
		t.Fatalf("CreateEnrollment tA/site1: %v", err)
	}
	// tB:一台设备(验跨租户隔离)。
	if _, err := svc.CreateEnrollment(ctx, tB, enroll.KindConnector, "b-only"); err != nil {
		t.Fatalf("CreateEnrollment tB/b-only: %v", err)
	}

	// 兑换 tA/site1 → status=redeemed + redeemed_at 非空。
	csrPEM, _, err := devpki.GenerateCSR("site1")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if _, err := svc.Redeem(ctx, codeSite1, csrPEM); err != nil {
		t.Fatalf("Redeem tA/site1: %v", err)
	}

	// ① 列 tA → 2 条,按 created_at 升序(web 先建在前)。
	devsA, err := svc.ListDevices(ctx, tA)
	if err != nil {
		t.Fatalf("ListDevices tA: %v", err)
	}
	if len(devsA) != 2 {
		t.Fatalf("tA 应 2 台设备,得 %d: %+v", len(devsA), devsA)
	}
	if devsA[0].Identity != "web" || devsA[1].Identity != "site1" {
		t.Fatalf("应按 created_at 升序 web 在前 site1 在后,得 %+v", devsA)
	}
	// web 未兑换:status=pending、redeemed_at=nil。
	if devsA[0].Status != "pending" || devsA[0].Kind != enroll.KindConnector || devsA[0].RedeemedAt != nil {
		t.Fatalf("tA/web 应 pending/connector/未兑换,得 %+v", devsA[0])
	}
	if devsA[0].ID == "" || devsA[0].CreatedAt.IsZero() {
		t.Fatalf("tA/web 应有 id/created_at,得 %+v", devsA[0])
	}
	// site1 已兑换:status=redeemed、redeemed_at 非空。
	if devsA[1].Status != "redeemed" || devsA[1].Kind != enroll.KindCPE || devsA[1].RedeemedAt == nil {
		t.Fatalf("tA/site1 应 redeemed/cpe/已兑换,得 %+v", devsA[1])
	}

	// ② RLS 跨租户隔离实证:tA 列表绝不含 tB 的 b-only。
	for _, d := range devsA {
		if d.Identity == "b-only" {
			t.Fatalf("RLS 泄漏:tA 列表不应含 tB 的 b-only,得 %+v", devsA)
		}
	}
	// 反向:tB 只见自己的 b-only,不见 tA 的 web/site1。
	devsB, err := svc.ListDevices(ctx, tB)
	if err != nil {
		t.Fatalf("ListDevices tB: %v", err)
	}
	if len(devsB) != 1 || devsB[0].Identity != "b-only" {
		t.Fatalf("tB 应仅 1 台 b-only,得 %+v", devsB)
	}

	// ③ 空租户 → 非 nil 空切片。
	devsEmpty, err := svc.ListDevices(ctx, uuid.NewString())
	if err != nil {
		t.Fatalf("ListDevices 空租户: %v", err)
	}
	if devsEmpty == nil {
		t.Fatal("空租户应返非 nil 空切片(序列化为 []),得 nil")
	}
	if len(devsEmpty) != 0 {
		t.Fatalf("空租户应 0 台,得 %d", len(devsEmpty))
	}
}
