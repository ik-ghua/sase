package authz

import (
	"context"
	"errors"
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

// TestMiddlewareAdminActiveChecker(Slice55 主动撤销):platform_admin 令牌每请求复查 active;
// 撤销→401、checker 错→fail-closed 503、tenant_admin 不受影响、nil checker 向后兼容。
func TestMiddlewareAdminActiveChecker(t *testing.T) {
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	v, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	active := map[string]bool{"ok-admin": true} // "gone-admin" 不在 → 已撤销
	checker := func(_ context.Context, subject string) (bool, error) {
		if subject == "err-admin" {
			return false, errors.New("db down")
		}
		return active[subject], nil
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mkTok := func(sub, role, tid string) string {
		tok, _ := signer.Issue(cred.Claims{Subject: sub, Role: role, TenantID: tid}, time.Hour, time.Now())
		return tok
	}
	doWith := func(g *Guard, tok, method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		g.Middleware(next).ServeHTTP(w, r)
		return w.Code
	}

	g := NewGuard(v).WithAdminActiveChecker(checker)
	if c := doWith(g, mkTok("ok-admin", RolePlatformAdmin, ""), "GET", "/api/v1/platform/tenants"); c != http.StatusOK {
		t.Errorf("active platform_admin 应 200,得 %d", c)
	}
	if c := doWith(g, mkTok("gone-admin", RolePlatformAdmin, ""), "GET", "/api/v1/platform/tenants"); c != http.StatusUnauthorized {
		t.Errorf("已撤销 platform_admin 应 401,得 %d", c)
	}
	if c := doWith(g, mkTok("err-admin", RolePlatformAdmin, ""), "GET", "/api/v1/platform/tenants"); c != http.StatusServiceUnavailable {
		t.Errorf("checker 错应 fail-closed 503,得 %d", c)
	}
	// tenant_admin 不在该表,按角色门控不调用 checker → 不受影响(其 subject 不在 active 集也 200)
	if c := doWith(g, mkTok("any-ta", RoleTenantAdmin, "A"), "GET", "/api/v1/tenants/A/users"); c != http.StatusOK {
		t.Errorf("tenant_admin 不应被 platform checker 影响,应 200,得 %d", c)
	}
	// nil checker:向后兼容,撤销逻辑不生效 → gone-admin 也 200
	if c := doWith(NewGuard(v), mkTok("gone-admin", RolePlatformAdmin, ""), "GET", "/api/v1/platform/tenants"); c != http.StatusOK {
		t.Errorf("nil checker 向后兼容应 200,得 %d", c)
	}
}

// TestMiddlewareSessionCookie(W2 桥接):无 Bearer 时回退 sase_session cookie,**与 Bearer 完全相同**的校验。
// 覆盖:cookie 令牌有效→200、无效/空 cookie→401、Bearer 优先、ZTNA 会话令牌(无角色)cookie 也拒、
// 跨租户 cookie 仍 403、AdminActiveChecker 对 cookie 同样生效(撤销→401)。
func TestMiddlewareSessionCookie(t *testing.T) {
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	v, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	mkTok := func(sub, role, tid string) string {
		tok, _ := signer.Issue(cred.Claims{Subject: sub, Role: role, TenantID: tid}, time.Hour, time.Now())
		return tok
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	// doCookie:把令牌放 sase_session cookie(不设 Bearer),经中间件。
	doCookie := func(g *Guard, cookieTok, method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		if cookieTok != "" {
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookieTok})
		}
		w := httptest.NewRecorder()
		g.Middleware(next).ServeHTTP(w, r)
		return w.Code
	}
	// doBoth:同时设 Bearer 与 cookie,验 Bearer 优先。
	doBoth := func(g *Guard, bearerTok, cookieTok, method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+bearerTok)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookieTok})
		w := httptest.NewRecorder()
		g.Middleware(next).ServeHTTP(w, r)
		return w.Code
	}

	g := NewGuard(v)
	taA := mkTok("ta", RoleTenantAdmin, "A")

	// ① cookie 令牌有效 → 200(本租户读)
	if c := doCookie(g, taA, "GET", "/api/v1/tenants/A/users"); c != http.StatusOK {
		t.Errorf("有效 cookie 令牌应 200,得 %d", c)
	}
	// ② 无 cookie / 空 cookie / 非法 cookie → 401
	if c := doCookie(g, "", "GET", "/api/v1/tenants/A/users"); c != http.StatusUnauthorized {
		t.Errorf("无 cookie 应 401,得 %d", c)
	}
	if c := doCookie(g, "garbage.token", "GET", "/api/v1/tenants/A/users"); c != http.StatusUnauthorized {
		t.Errorf("非法 cookie 应 401,得 %d", c)
	}
	// ③ ZTNA 会话令牌(Role 空)经 cookie 也拒(不放宽角色校验)
	sessionTok := mkTok("u", "", "A")
	if c := doCookie(g, sessionTok, "GET", "/api/v1/tenants/A/users"); c != http.StatusUnauthorized {
		t.Errorf("ZTNA 会话令牌(无角色)cookie 应 401,得 %d", c)
	}
	// ④ 跨租户经 cookie 仍 403(授权不放宽)
	if c := doCookie(g, taA, "POST", "/api/v1/tenants/B/policies"); c != http.StatusForbidden {
		t.Errorf("cookie 令牌跨租户应 403,得 %d", c)
	}
	// ⑤ Bearer 优先:Bearer 是有效 tenant_admin A,cookie 是 garbage → 用 Bearer → 200
	if c := doBoth(g, taA, "garbage", "GET", "/api/v1/tenants/A/users"); c != http.StatusOK {
		t.Errorf("Bearer 优先(cookie 垃圾)应 200,得 %d", c)
	}

	// ⑥ AdminActiveChecker 对 cookie 同样生效:撤销的 platform_admin 经 cookie → 401
	active := map[string]bool{"ok-admin": true}
	checker := func(_ context.Context, subject string) (bool, error) { return active[subject], nil }
	gActive := NewGuard(v).WithAdminActiveChecker(checker)
	if c := doCookie(gActive, mkTok("ok-admin", RolePlatformAdmin, ""), "GET", "/api/v1/platform/tenants"); c != http.StatusOK {
		t.Errorf("active platform_admin cookie 应 200,得 %d", c)
	}
	if c := doCookie(gActive, mkTok("gone-admin", RolePlatformAdmin, ""), "GET", "/api/v1/platform/tenants"); c != http.StatusUnauthorized {
		t.Errorf("已撤销 platform_admin cookie 应 401,得 %d", c)
	}
}

// TestVerifyAdminToken(W2 登录端点复用):VerifyAdminToken 与 Middleware 同校验;TokenExpiry 解出 exp。
func TestVerifyAdminToken(t *testing.T) {
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	v, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	g := NewGuard(v)

	platTok, _ := signer.Issue(cred.Claims{Subject: "ops", Role: RolePlatformAdmin}, time.Hour, time.Now())
	p, err := g.VerifyAdminToken(platTok)
	if err != nil {
		t.Fatalf("有效 platform_admin 令牌应通过: %v", err)
	}
	if p.Subject != "ops" || p.Role != RolePlatformAdmin {
		t.Errorf("Principal 错: %+v", p)
	}
	exp, err := g.TokenExpiry(platTok)
	if err != nil {
		t.Fatalf("TokenExpiry: %v", err)
	}
	if exp.Before(time.Now()) || exp.After(time.Now().Add(2*time.Hour)) {
		t.Errorf("exp 应约 now+1h,得 %v", exp)
	}

	// ZTNA 会话令牌(无角色)→ 拒
	sessTok, _ := signer.Issue(cred.Claims{Subject: "u", TenantID: "A"}, time.Hour, time.Now())
	if _, err := g.VerifyAdminToken(sessTok); err == nil {
		t.Errorf("无 admin 角色令牌应被 VerifyAdminToken 拒")
	}
	// 过期令牌 → 拒
	expTok, _ := signer.Issue(cred.Claims{Subject: "ops", Role: RolePlatformAdmin}, -time.Hour, time.Now())
	if _, err := g.VerifyAdminToken(expTok); err == nil {
		t.Errorf("过期令牌应被拒")
	}
	// 垃圾串 → 拒
	if _, err := g.VerifyAdminToken("not.a.token"); err == nil {
		t.Errorf("垃圾串应被拒")
	}
}
