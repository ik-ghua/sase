package httpapi_test

// GET /tenants/{tid}/devices(ZTP 可见性,M2)端到端(真 PG;需 SASE_DB_RW_DSN;未设则 SKIP)。
// 前置:migrations 0001-0009。覆盖:
//   ① tenant_admin 列本租户 → 200 + 多台 + 按 created_at 升序 + **不暴露 activation_code**。
//   ② auditor(只读)列本租户 → 200(子路径读放行)。
//   ③ **跨租户**:tB 的 tenant_admin 列 tA → 403(authz 限本租户)。
//   ④ platform_admin 经 path-tid 列任意租户 → 200(对齐 listUsers/listPolicies)。
//   ⑤ RLS 隔离实证:tA 列表绝不含 tB 的设备。
//   ⑥ 空租户 → 200 + 空数组 [](非 null)。

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/admin/httpapi"
	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/authz"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/fw"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/platform"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestDevicesEndpoint(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 devices 端点端到端测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("签发器: %v", err)
	}
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("验证器: %v", err)
	}
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	identitySvc := identity.NewService(store, identity.WithSigner(signer))
	secSvc := testSecretSvc(t, store)
	enrollSvc := enroll.NewService(store, ca)

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enrollSvc,
		platform.NewService(store), nil, nil, nil,
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil, nil,
		nil,
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tA := uuid.NewString()
	tB := uuid.NewString()
	tEmpty := uuid.NewString()

	// tA 两台(web=connector、site1=cpe);site1 兑换以验 redeemed 状态进列表。
	if _, err := enrollSvc.CreateEnrollment(ctx, tA, enroll.KindConnector, "web"); err != nil {
		t.Fatalf("CreateEnrollment tA/web: %v", err)
	}
	codeSite1, err := enrollSvc.CreateEnrollment(ctx, tA, enroll.KindCPE, "site1")
	if err != nil {
		t.Fatalf("CreateEnrollment tA/site1: %v", err)
	}
	csrPEM, _, err := devpki.GenerateCSR("site1")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if _, err := enrollSvc.Redeem(ctx, codeSite1, csrPEM); err != nil {
		t.Fatalf("Redeem tA/site1: %v", err)
	}
	// tB 一台(验跨租户隔离)。
	if _, err := enrollSvc.CreateEnrollment(ctx, tB, enroll.KindConnector, "b-only"); err != nil {
		t.Fatalf("CreateEnrollment tB/b-only: %v", err)
	}

	taTok, err := identitySvc.IssueAdminToken(ctx, "ta", authz.RoleTenantAdmin, tA, time.Hour)
	if err != nil {
		t.Fatalf("签发 tenant_admin(tA): %v", err)
	}
	tbTok, err := identitySvc.IssueAdminToken(ctx, "tb", authz.RoleTenantAdmin, tB, time.Hour)
	if err != nil {
		t.Fatalf("签发 tenant_admin(tB): %v", err)
	}
	audTok, err := identitySvc.IssueAdminToken(ctx, "aud", authz.RoleAuditor, tA, time.Hour)
	if err != nil {
		t.Fatalf("签发 auditor(tA): %v", err)
	}
	platTok, err := identitySvc.IssueAdminToken(ctx, "plat", authz.RolePlatformAdmin, "", time.Hour)
	if err != nil {
		t.Fatalf("签发 platform_admin: %v", err)
	}

	type devRow struct {
		ID         string     `json:"id"`
		Kind       string     `json:"kind"`
		Identity   string     `json:"identity"`
		Status     string     `json:"status"`
		RedeemedAt *time.Time `json:"redeemed_at"`
		CreatedAt  time.Time  `json:"created_at"`
	}

	// ① tenant_admin 列 tA → 200 + 2 台 + 升序 + RLS 隔离。
	st, body := doRaw(t, srv.URL, taTok, "GET", "/api/v1/tenants/"+tA+"/devices", nil)
	if st != http.StatusOK {
		t.Fatalf("tenant_admin 列 tA 应 200,得 %d body=%s", st, body)
	}
	var rows []devRow
	if e := json.Unmarshal(body, &rows); e != nil {
		t.Fatalf("解析列表: %v body=%s", e, body)
	}
	if len(rows) != 2 {
		t.Fatalf("tA 应 2 台,得 %d: %+v", len(rows), rows)
	}
	if rows[0].Identity != "web" || rows[1].Identity != "site1" {
		t.Fatalf("应按 created_at 升序 web>site1,得 %+v", rows)
	}
	if rows[0].Status != "pending" || rows[0].RedeemedAt != nil {
		t.Fatalf("tA/web 应 pending/未兑换,得 %+v", rows[0])
	}
	if rows[1].Status != "redeemed" || rows[1].RedeemedAt == nil {
		t.Fatalf("tA/site1 应 redeemed/已兑换,得 %+v", rows[1])
	}
	for _, rw := range rows { // RLS 隔离实证:tA 列表绝不含 tB 的 b-only
		if rw.Identity == "b-only" {
			t.Fatalf("RLS 泄漏:tA 列表不应含 tB 的 b-only,得 %+v", rows)
		}
	}
	// 安全:响应 JSON 绝不能含激活码(activation_code 字段名或租户前缀码片段)。
	if bytes.Contains(body, []byte("activation_code")) || bytes.Contains(body, []byte(tA+".")) {
		t.Fatalf("响应不得暴露激活码,得 body=%s", body)
	}

	// ② auditor(只读)列 tA → 200。
	st, body = doRaw(t, srv.URL, audTok, "GET", "/api/v1/tenants/"+tA+"/devices", nil)
	if st != http.StatusOK {
		t.Fatalf("auditor 列 tA 应 200,得 %d body=%s", st, body)
	}

	// ③ 跨租户:tB 的 tenant_admin 列 tA → 403。
	st, _ = doRaw(t, srv.URL, tbTok, "GET", "/api/v1/tenants/"+tA+"/devices", nil)
	if st != http.StatusForbidden {
		t.Fatalf("跨租户列应 403,得 %d", st)
	}

	// ④ platform_admin 经 path-tid 列任意租户 → 200(读到 tA 的 2 台)。
	st, body = doRaw(t, srv.URL, platTok, "GET", "/api/v1/tenants/"+tA+"/devices", nil)
	if st != http.StatusOK {
		t.Fatalf("platform_admin 经 path-tid 列应 200,得 %d body=%s", st, body)
	}
	rows = nil
	if e := json.Unmarshal(body, &rows); e != nil {
		t.Fatalf("解析 platform 列表: %v body=%s", e, body)
	}
	if len(rows) != 2 {
		t.Fatalf("platform_admin 列 tA 应 2 台,得 %d", len(rows))
	}

	// ⑤ 空租户 → 200 + 空数组(非 null)。
	st, body = doRaw(t, srv.URL, platTok, "GET", "/api/v1/tenants/"+tEmpty+"/devices", nil)
	if st != http.StatusOK {
		t.Fatalf("空租户应 200,得 %d body=%s", st, body)
	}
	if string(body) != "[]\n" && string(body) != "[]" {
		t.Fatalf("空租户应序列化为空数组 [](非 null),得 %q", string(body))
	}
}
