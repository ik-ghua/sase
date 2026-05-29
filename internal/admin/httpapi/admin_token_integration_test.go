package httpapi_test

// Slice33e PC-API-5「平台签发 admin 令牌端点」集成测试:经真实 Admin HTTP 栈(authz+audit+真实 services)验证:
//   ① platform_admin 经 POST /platform/admin-tokens 签发 tenant_admin 令牌 → 200 + 令牌可验(claims 含 role/tenant_id)。
//   ② 显式审计落到 **target tenant** 的 audit_log(detail 只含 subject+role,**不含 token**)。
//   ③ 本刀范围限制:role=platform_admin 被拒(400);role 非法被拒;tenant_id 缺被拒。
//   ④ authz:tenant_admin 调用此端点 → 403(已在 authz unit;此处端到端验证一遍)。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:migrations 0001-0015。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestAdminTokenIssuance(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 admin-token 端到端测试")
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
	auditSvc := audit.NewService(store)
	secSvc := testSecretSvc(t, store)

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), auditSvc,
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store),
		nil, // popReg
		nil, // platform audit svc
		nil, // platform RBAC svc
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil, nil,
		nil, // riskSvc
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tid := uuid.NewString()
	// 先建租户(签发的 tenant_admin 令牌作用于它);用 platform_admin 走 POST /tenants
	platTok, err := identitySvc.IssueAdminToken(ctx, "ops", authz.RolePlatformAdmin, "", time.Hour)
	if err != nil {
		t.Fatalf("签发平台令牌: %v", err)
	}
	if st, _ := doRaw(t, srv.URL, platTok, "POST", "/api/v1/tenants", map[string]string{"id": tid, "name": "T-AT"}); st != http.StatusCreated {
		t.Fatalf("建租户应 201,得 %d", st)
	}

	// ① 平台 POST /platform/admin-tokens 签发 tenant_admin 令牌
	st, body := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject":     "cust-admin",
		"role":        authz.RoleTenantAdmin,
		"tenant_id":   tid,
		"ttl_seconds": 3600,
	})
	if st != http.StatusOK {
		t.Fatalf("签发应 200,得 %d body=%s", st, body)
	}
	var resp struct {
		Token     string    `json:"token"`
		Subject   string    `json:"subject"`
		Role      string    `json:"role"`
		TenantID  string    `json:"tenant_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if e := json.Unmarshal(body, &resp); e != nil {
		t.Fatalf("解析响应: %v", e)
	}
	if resp.Token == "" || resp.Subject != "cust-admin" || resp.Role != authz.RoleTenantAdmin || resp.TenantID != tid {
		t.Fatalf("响应字段错: %+v", resp)
	}
	if resp.ExpiresAt.Before(time.Now()) || resp.ExpiresAt.After(time.Now().Add(2*time.Hour)) {
		t.Fatalf("expires_at 应约 now+1h,得 %v", resp.ExpiresAt)
	}
	// 验签发的令牌可验(role/tenant_id 正确)→ 用其对本租户做 GET(应 200)
	if st2, _ := doRaw(t, srv.URL, resp.Token, "GET", "/api/v1/tenants/"+tid+"/apps", nil); st2 != http.StatusOK {
		t.Fatalf("签发的 tenant_admin 令牌应能 GET 本租户 apps(200),得 %d", st2)
	}
	// 跨租户该令牌被拒(authz)
	if st2, _ := doRaw(t, srv.URL, resp.Token, "GET", "/api/v1/tenants/"+uuid.NewString()+"/apps", nil); st2 != http.StatusForbidden {
		t.Fatalf("签发的 tenant_admin 令牌跨租户应 403,得 %d", st2)
	}

	// ② 显式审计落到 target tenant(detail 含 subject/role,**不含 token**)
	es, err := auditSvc.ListByTenant(ctx, tid, 100)
	if err != nil {
		t.Fatalf("读审计: %v", err)
	}
	var sawIssue bool
	for _, e := range es {
		if e.Action == "POST /api/v1/platform/admin-tokens" {
			sawIssue = true
			if e.ActorSubject != "ops" || e.ActorRole != authz.RolePlatformAdmin || e.Source != audit.SourceAPI {
				t.Errorf("admin-token 审计 actor/source 错: %+v", e)
			}
			if !strings.Contains(e.Detail, "subject=cust-admin") || !strings.Contains(e.Detail, "role="+authz.RoleTenantAdmin) {
				t.Errorf("audit detail 应含 subject+role: %q", e.Detail)
			}
			if strings.Contains(e.Detail, resp.Token) || strings.Contains(e.Detail, "token") {
				t.Errorf("audit detail 不应含 token: %q", e.Detail)
			}
		}
	}
	if !sawIssue {
		t.Fatalf("应有 admin-token 签发的审计行(target=%s),得 %d 条", tid, len(es))
	}

	// ③ Slice38c 扩展:platform_admin 签发现需 RBAC 表
	// 本测没注 platform RBAC → 任何 role=platform_admin 请求会撞 tenant_id 或 RBAC 服务校验:
	// 带 tenant_id → 400(跨租户作用域不应带 tenant_id);
	if st, _ := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject": "x", "role": authz.RolePlatformAdmin, "tenant_id": tid,
	}); st != http.StatusBadRequest {
		t.Fatalf("platform_admin 带 tenant_id 应 400,得 %d", st)
	}
	// 无 tenant_id + 无 RBAC 服务 → 503(端点未配置)
	if st, _ := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject": "x", "role": authz.RolePlatformAdmin,
	}); st != http.StatusServiceUnavailable {
		t.Fatalf("platform_admin 无 RBAC 服务应 503,得 %d", st)
	}
	// role 非法
	if st, _ := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject": "x", "role": "root", "tenant_id": tid,
	}); st != http.StatusBadRequest {
		t.Fatalf("非法 role 应 400,得 %d", st)
	}
	// 缺 tenant_id
	if st, _ := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject": "x", "role": authz.RoleTenantAdmin,
	}); st != http.StatusBadRequest {
		t.Fatalf("缺 tenant_id 应 400,得 %d", st)
	}

	// ④ tenant_admin 调用本端点 → 403(authz 端到端)
	taTok, _ := identitySvc.IssueAdminToken(ctx, "ta", authz.RoleTenantAdmin, tid, time.Hour)
	if st, _ := doRaw(t, srv.URL, taTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject": "x", "role": authz.RoleAuditor, "tenant_id": tid,
	}); st != http.StatusForbidden {
		t.Fatalf("tenant_admin 调用本端点应 403,得 %d", st)
	}
}
