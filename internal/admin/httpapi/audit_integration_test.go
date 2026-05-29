package httpapi_test

// Slice 10 端到端:经真实 Admin HTTP 栈(authz 鉴权 + audit 审计 + 真实 services + RLS)验证审计留痕。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:已应用 migrations/0001-0004。-run TestAudit。

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

func TestAuditTrailEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过审计端到端测试")
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
	secSvc := testSecretSvc(t, store) // 同实例传 idp 与 Register secret 参数(不同 DevProvider 实例 KEK 不同)

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), auditSvc, swg.NewService(store), site.NewService(store),
		fw.NewService(store),
		dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store),
		nil, // popReg:本测不走 PoP 注册
		nil, // platform audit svc:本测覆盖 tenant audit
		nil, // platform RBAC svc
		testIDPSvc(t, store, secSvc),
		nil, // oidc deps:本测不走 OIDC
		nil, // 限流器(测试不限流)
		verifier,
	)
	srv := httptest.NewServer(mux) // 明文 HTTP 足够(TLS 在 Slice8 单测;authz 是 app 层)
	defer srv.Close()

	tid := uuid.NewString()
	platTok, err := identitySvc.IssueAdminToken(ctx, "ops", authz.RolePlatformAdmin, "", time.Hour)
	if err != nil {
		t.Fatalf("签发平台令牌: %v", err)
	}
	taTok, err := identitySvc.IssueAdminToken(ctx, "admin-a", authz.RoleTenantAdmin, tid, time.Hour)
	if err != nil {
		t.Fatalf("签发租户令牌: %v", err)
	}

	// ① 平台建租户(POST /tenants)→ 审计记在被建租户名下
	do(t, srv.URL, platTok, "POST", "/api/v1/tenants", map[string]string{"id": tid, "name": "TAudit"}, http.StatusCreated)
	// ② 租户管理员注册应用(变更)→ 审计
	do(t, srv.URL, taTok, "POST", "/api/v1/tenants/"+tid+"/apps", map[string]string{"app_key": "app1", "name": "App1"}, http.StatusCreated)
	// ③ 读(GET)→ 不审计
	do(t, srv.URL, taTok, "GET", "/api/v1/tenants/"+tid+"/apps", nil, http.StatusOK)

	// 读审计(平台令牌可读任意租户)
	es, err := auditSvc.ListByTenant(ctx, tid, 100)
	if err != nil {
		t.Fatalf("读审计: %v", err)
	}
	// 应有 2 条变更(建租户 + 建应用),不含 GET
	var sawCreateTenant, sawCreateApp bool
	for _, e := range es {
		if e.Action == "POST /api/v1/tenants" {
			sawCreateTenant = true
			if e.ActorSubject != "ops" || e.ActorRole != authz.RolePlatformAdmin || e.Result != http.StatusCreated {
				t.Errorf("建租户审计字段错: %+v", e)
			}
		}
		if e.Action == "POST /api/v1/tenants/"+tid+"/apps" {
			sawCreateApp = true
			if e.ActorSubject != "admin-a" || e.ActorRole != authz.RoleTenantAdmin {
				t.Errorf("建应用审计字段错: %+v", e)
			}
		}
		if e.Action == "GET /api/v1/tenants/"+tid+"/apps" {
			t.Errorf("GET 不应被审计: %+v", e)
		}
	}
	if !sawCreateTenant || !sawCreateApp {
		t.Fatalf("应审计到建租户与建应用,得 %d 条: %+v", len(es), es)
	}

	// ④ 经 HTTP 读审计端点(租户管理员读本租户)→ 200 且含记录
	st, body := doRaw(t, srv.URL, taTok, "GET", "/api/v1/tenants/"+tid+"/audit", nil)
	if st != http.StatusOK {
		t.Fatalf("读审计端点应 200,得 %d", st)
	}
	var got []audit.Entry
	if err := json.Unmarshal(body, &got); err != nil || len(got) < 2 {
		t.Fatalf("审计端点应返回 ≥2 条,得 %d err=%v", len(got), err)
	}
}

func do(t *testing.T, base, token, method, path string, body any, wantStatus int) {
	t.Helper()
	st, _ := doRaw(t, base, token, method, path, body)
	if st != wantStatus {
		t.Fatalf("%s %s 期望 %d,得 %d", method, path, wantStatus, st)
	}
}

func doRaw(t *testing.T, base, token, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// Slice40 CSRF:写方法需 cookie+header 双源 + Origin 同源(同源回退 = AllowedOrigins 空 + Host 匹配)
	if method == "POST" || method == "PATCH" || method == "PUT" || method == "DELETE" {
		tok := acquireCSRFToken(t, base, token)
		req.Header.Set("X-CSRF-Token", tok)
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: tok})
		req.Header.Set("Origin", base) // base = http://127.0.0.1:NNNN(httptest.URL),与 r.Host 同源
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求: %v", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// acquireCSRFToken:首次 GET 任意非白名单端点拿 csrf_token cookie 值;后续写方法复制到 X-CSRF-Token。
// 简化:走 GET /api/v1/trust/pubkey(authz 公开,中间件给 cookie)。
// 注:trust/pubkey 在 csrf Skip 白名单内 → **不颁发** cookie!改走 GET /api/v1/tenants/<random>(authz 会 401 但 csrf 仍颁发 cookie——其在 authz 之前)。
func acquireCSRFToken(t *testing.T, base, _ string) string {
	t.Helper()
	req, err := http.NewRequest("GET", base+"/api/v1/tenants/00000000-0000-0000-0000-000000000000", nil)
	if err != nil {
		t.Fatalf("acquireCSRFToken 构造: %v", err)
	}
	// 不带 Authorization → 401,但 csrf 中间件在 authz 之前已 Set-Cookie
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("acquireCSRFToken: %v", err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "csrf_token" {
			return c.Value
		}
	}
	t.Fatalf("acquireCSRFToken: 响应无 csrf_token cookie")
	return ""
}
