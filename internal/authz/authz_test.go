package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/cred"
)

// TestAuthorizeMatrix:角色 × 路径 × 方法 的授权判定(纯函数)。
func TestAuthorizeMatrix(t *testing.T) {
	plat := Principal{Subject: "ops", Role: RolePlatformAdmin}
	taA := Principal{Subject: "a", Role: RoleTenantAdmin, TenantID: "A"}
	audA := Principal{Subject: "a", Role: RoleAuditor, TenantID: "A"}

	cases := []struct {
		name   string
		p      Principal
		method string
		path   string
		want   bool
	}{
		{"平台建租户", plat, "POST", "/api/v1/tenants", true},
		{"租户管理员不能建租户", taA, "POST", "/api/v1/tenants", false},
		{"租户管理员写本租户", taA, "POST", "/api/v1/tenants/A/policies", true},
		{"租户管理员跨租户被拒", taA, "POST", "/api/v1/tenants/B/policies", false},
		{"租户管理员读本租户", taA, "GET", "/api/v1/tenants/A/users", true},
		{"平台跨租户可写", plat, "POST", "/api/v1/tenants/B/policies", true},
		{"审计只读本租户", audA, "GET", "/api/v1/tenants/A/users", true},
		{"审计不能写", audA, "POST", "/api/v1/tenants/A/users", false},
		{"审计跨租户读被拒", audA, "GET", "/api/v1/tenants/B/users", false},
		{"GET 单租户作用域", taA, "GET", "/api/v1/tenants/A", true},
		{"GET 他租户被拒", taA, "GET", "/api/v1/tenants/B", false},
		// 租户本身的写(PATCH /tenants/{tid})= 生命周期,平台级:platform_admin 可,租户管理员/审计不可改自身
		{"平台改租户(PATCH)", plat, "PATCH", "/api/v1/tenants/A", true},
		{"租户管理员不能改自身租户(PATCH)", taA, "PATCH", "/api/v1/tenants/A", false},
		{"租户管理员不能改他租户(PATCH)", taA, "PATCH", "/api/v1/tenants/B", false},
		{"审计不能改租户(PATCH)", audA, "PATCH", "/api/v1/tenants/A", false},
		// 平台注销端点在 /platform/*(默认分支)→ 仅 platform_admin;租户管理员不能注销自身
		{"平台注销租户", plat, "POST", "/api/v1/platform/tenants/A/decommission", true},
		{"租户管理员不能注销自身", taA, "POST", "/api/v1/platform/tenants/A/decommission", false},
		{"平台列租户", plat, "GET", "/api/v1/platform/tenants", true},
		{"租户管理员不能读平台列表", taA, "GET", "/api/v1/platform/tenants", false},
		// PC-API-5:平台签发 admin 令牌端点(/platform/*) → 默认分支 → 仅 platform_admin
		{"平台签发 admin 令牌", plat, "POST", "/api/v1/platform/admin-tokens", true},
		{"租户管理员不能签发 admin 令牌", taA, "POST", "/api/v1/platform/admin-tokens", false},
	}
	for _, c := range cases {
		if got := authorize(c.p, c.method, c.path); got != c.want {
			t.Errorf("%s: authorize=%v want %v", c.name, got, c.want)
		}
	}
}

// TestMiddlewareAuthN:有效 admin 令牌放行、ZTNA 会话令牌(无角色)拒、无令牌 401、公开端点免鉴权。
func TestMiddlewareAuthN(t *testing.T) {
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	v, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	g := NewGuard(v)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := g.Middleware(next)

	adminTok, _ := signer.Issue(cred.Claims{Subject: "a", Role: RoleTenantAdmin, TenantID: "A"}, time.Hour, time.Now())
	sessionTok, _ := signer.Issue(cred.Claims{Subject: "u", TenantID: "A", Groups: []string{"g1"}}, time.Hour, time.Now()) // Role 空

	do := func(authzHdr, method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		if authzHdr != "" {
			r.Header.Set("Authorization", "Bearer "+authzHdr)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if c := do(adminTok, "GET", "/api/v1/tenants/A/users"); c != http.StatusOK {
		t.Errorf("有效 admin 令牌应 200,得 %d", c)
	}
	if c := do(sessionTok, "GET", "/api/v1/tenants/A/users"); c != http.StatusUnauthorized {
		t.Errorf("ZTNA 会话令牌(无角色)应 401,得 %d", c)
	}
	if c := do("", "GET", "/api/v1/tenants/A/users"); c != http.StatusUnauthorized {
		t.Errorf("无令牌应 401,得 %d", c)
	}
	if c := do("garbage", "GET", "/api/v1/tenants/A/users"); c != http.StatusUnauthorized {
		t.Errorf("非法令牌应 401,得 %d", c)
	}
	if c := do(adminTok, "POST", "/api/v1/tenants/B/policies"); c != http.StatusForbidden {
		t.Errorf("跨租户应 403,得 %d", c)
	}
	if c := do("", "GET", "/api/v1/trust/pubkey"); c != http.StatusOK {
		t.Errorf("公开端点应免鉴权 200,得 %d", c)
	}
}
