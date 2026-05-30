package httpapi_test

// GET /tenants/{tid}/sites(SD-WAN 站点列表)端到端(真 PG;需 SASE_DB_RW_DSN;未设则 SKIP)。
// 前置:migrations 0001-0006。覆盖:
//   ① tenant_admin 列本租户 → 200 + 多站点 + 按 site_key 升序。
//   ② auditor(只读)列本租户 → 200(子路径读放行)。
//   ③ **跨租户**:tB 的 tenant_admin 列 tA → 403(authz 限本租户)。
//   ④ platform_admin 经 path-tid 列任意租户 → 200(对齐 listUsers/listDevices)。
//   ⑤ RLS 隔离实证:tA 列表绝不含 tB 的站点。
//   ⑥ 空租户 → 200 + 空数组 [](非 null)。
//   ⑦ POST 拒 v4-mapped-v6 CIDR → 400(输入侧纵深,承接 Slice70)。

import (
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

func TestSitesEndpoint(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 sites 端点端到端测试")
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
	identitySvc := identity.NewService(store, identity.WithSigner(signer))
	siteSvc := site.NewService(store)
	secSvc := testSecretSvc(t, store)

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), siteSvc, fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
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

	// tA 两站点(逆序插入验排序);tB 一站点(同 site_key 验靠 tenant 隔离)。
	if err := siteSvc.CreateSite(ctx, tA, &site.Site{SiteKey: "site-z", Name: "zz", CIDR: "10.1.2.0/24"}); err != nil {
		t.Fatalf("CreateSite tA/site-z: %v", err)
	}
	if err := siteSvc.CreateSite(ctx, tA, &site.Site{SiteKey: "site-a", Name: "aa", CIDR: "10.1.1.0/24"}); err != nil {
		t.Fatalf("CreateSite tA/site-a: %v", err)
	}
	if err := siteSvc.CreateSite(ctx, tB, &site.Site{SiteKey: "site-a", Name: "b-only", CIDR: "172.20.0.0/16"}); err != nil {
		t.Fatalf("CreateSite tB/site-a: %v", err)
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

	type siteRow struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
		SiteKey  string `json:"site_key"`
		Name     string `json:"name"`
		CIDR     string `json:"cidr"`
	}

	// ① tenant_admin 列 tA → 200 + 2 站点 + 按 site_key 升序 + RLS 隔离。
	st, body := doRaw(t, srv.URL, taTok, "GET", "/api/v1/tenants/"+tA+"/sites", nil)
	if st != http.StatusOK {
		t.Fatalf("tenant_admin 列 tA 应 200,得 %d body=%s", st, body)
	}
	var rows []siteRow
	if e := json.Unmarshal(body, &rows); e != nil {
		t.Fatalf("解析列表: %v body=%s", e, body)
	}
	if len(rows) != 2 {
		t.Fatalf("tA 应 2 站点,得 %d: %+v", len(rows), rows)
	}
	if rows[0].SiteKey != "site-a" || rows[1].SiteKey != "site-z" {
		t.Fatalf("应按 site_key 升序 site-a>site-z,得 %+v", rows)
	}
	for _, rw := range rows { // RLS 隔离实证:tA 列表绝不含 tB 的 b-only
		if rw.TenantID != tA {
			t.Fatalf("RLS 泄漏:tA 列表含非 tA 行 %+v", rw)
		}
		if rw.Name == "b-only" || rw.CIDR == "172.20.0.0/16" {
			t.Fatalf("RLS 泄漏:tA 列表混入 tB 站点 %+v", rw)
		}
	}

	// ② auditor(只读)列 tA → 200。
	st, body = doRaw(t, srv.URL, audTok, "GET", "/api/v1/tenants/"+tA+"/sites", nil)
	if st != http.StatusOK {
		t.Fatalf("auditor 列 tA 应 200,得 %d body=%s", st, body)
	}

	// ③ 跨租户:tB 的 tenant_admin 列 tA → 403。
	st, _ = doRaw(t, srv.URL, tbTok, "GET", "/api/v1/tenants/"+tA+"/sites", nil)
	if st != http.StatusForbidden {
		t.Fatalf("跨租户列应 403,得 %d", st)
	}

	// ④ platform_admin 经 path-tid 列任意租户 → 200(读到 tA 的 2 站点)。
	st, body = doRaw(t, srv.URL, platTok, "GET", "/api/v1/tenants/"+tA+"/sites", nil)
	if st != http.StatusOK {
		t.Fatalf("platform_admin 经 path-tid 列应 200,得 %d body=%s", st, body)
	}
	rows = nil
	if e := json.Unmarshal(body, &rows); e != nil {
		t.Fatalf("解析 platform 列表: %v body=%s", e, body)
	}
	if len(rows) != 2 {
		t.Fatalf("platform_admin 列 tA 应 2 站点,得 %d", len(rows))
	}

	// ⑤ 空租户 → 200 + 空数组(非 null)。
	st, body = doRaw(t, srv.URL, platTok, "GET", "/api/v1/tenants/"+tEmpty+"/sites", nil)
	if st != http.StatusOK {
		t.Fatalf("空租户应 200,得 %d body=%s", st, body)
	}
	if string(body) != "[]\n" && string(body) != "[]" {
		t.Fatalf("空租户应序列化为空数组 [](非 null),得 %q", string(body))
	}

	// ⑥ POST 拒 v4-mapped-v6 CIDR → 400(输入侧纵深)。
	st, body = doRaw(t, srv.URL, taTok, "POST", "/api/v1/tenants/"+tA+"/sites",
		map[string]string{"site_key": "mapped", "name": "v4mapped", "cidr": "::ffff:10.0.0.0/104"})
	if st != http.StatusBadRequest {
		t.Fatalf("POST v4-mapped CIDR 应 400,得 %d body=%s", st, body)
	}
}
