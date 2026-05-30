package httpapi_test

// W2 会话登录(sase_session cookie → authz 桥接)端到端测试,经真实 Admin HTTP 栈(csrf+authz+真 services):
//   ① POST /api/v1/login 用有效 platform_admin 令牌 → 200 + Set-Cookie sase_session(HttpOnly);响应体不含 token。
//   ② 用 cookie(不带 Bearer)请求受保护端点 → 200(桥接生效)。
//   ③ POST /api/v1/logout 清 cookie(Max-Age<0)→ 之后 cookie 请求 401。
//   ④ login 端点在 CSRF 白名单:无 csrf_token cookie / 无 X-CSRF-Token 也能 POST 成功(否则首次登录死锁)。
//   ⑤ 无效/过期令牌 login → 401(不放宽校验);缺 token → 400。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:migrations 0001+。

import (
	"bytes"
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

func TestSessionLoginCookieBridge(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过会话登录端到端测试")
	}
	// 隔离进程级 /login 限流单例:用生产默认(burst 10),本测试 ~5 次 login 远不触发 429。
	httpapi.ResetLoginLimiterForTest(0, 0)
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
		nil, nil, nil,
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil, nil,
		nil,
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// platform_admin 令牌(login 用它换 cookie)
	platTok, err := identitySvc.IssueAdminToken(ctx, "ops", authz.RolePlatformAdmin, "", time.Hour)
	if err != nil {
		t.Fatalf("签发平台令牌: %v", err)
	}

	// ── ① POST /login(CSRF 白名单:不带 csrf cookie / X-CSRF-Token)→ 200 + Set-Cookie sase_session ──
	loginResp := doLogin(t, srv.URL, map[string]string{"token": platTok})
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login 应 200(CSRF 白名单),得 %d", loginResp.StatusCode)
	}
	var sessionCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == authz.SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatalf("login 应 Set-Cookie sase_session")
	}
	if !sessionCookie.HttpOnly {
		t.Errorf("sase_session 应 HttpOnly")
	}
	if sessionCookie.Value != platTok {
		t.Errorf("sase_session cookie 值应等于令牌(只在 cookie,不进 body)")
	}
	// 响应体不含 token,但有 role/subject/exp
	body := readBody(t, loginResp)
	if strings.Contains(string(body), platTok) || strings.Contains(string(body), "\"token\"") {
		t.Errorf("login 响应体不应含 token: %s", body)
	}
	var info struct {
		Subject   string    `json:"subject"`
		Role      string    `json:"role"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if e := json.Unmarshal(body, &info); e != nil {
		t.Fatalf("解析 SessionInfo: %v", e)
	}
	if info.Subject != "ops" || info.Role != authz.RolePlatformAdmin {
		t.Errorf("SessionInfo 错: %+v", info)
	}
	if info.ExpiresAt.Before(time.Now()) {
		t.Errorf("expires_at 应在未来: %v", info.ExpiresAt)
	}

	// ── ② 用 cookie(不带 Bearer)请求受保护端点 → 200(桥接生效)──
	if code := doWithCookie(t, srv.URL, sessionCookie, "GET", "/api/v1/platform/tenants"); code != http.StatusOK {
		t.Fatalf("cookie 请求受保护端点应 200(桥接),得 %d", code)
	}

	// ── ③ POST /logout(带 session cookie)→ 清 cookie;之后无 cookie 请求 → 401 ──
	cleared := doLogout(t, srv.URL, sessionCookie)
	if cleared.StatusCode != http.StatusOK {
		t.Fatalf("logout 应 200,得 %d", cleared.StatusCode)
	}
	var clearedCookie *http.Cookie
	for _, c := range cleared.Cookies() {
		if c.Name == authz.SessionCookieName {
			clearedCookie = c
		}
	}
	if clearedCookie == nil || clearedCookie.MaxAge >= 0 {
		t.Errorf("logout 应清除 sase_session cookie(MaxAge<0),得 %+v", clearedCookie)
	}
	// 模拟浏览器:cookie 被清后不再带 → 401
	if code := doWithCookie(t, srv.URL, nil, "GET", "/api/v1/platform/tenants"); code != http.StatusUnauthorized {
		t.Fatalf("登出后无 cookie 请求应 401,得 %d", code)
	}

	// ── ④ 无效令牌 login → 401(不放宽校验)──
	if r := doLogin(t, srv.URL, map[string]string{"token": "garbage.token"}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无效令牌 login 应 401,得 %d", r.StatusCode)
	}
	// 过期令牌 → 401
	expTok, _ := signer.Issue(cred.Claims{Subject: "ops", Role: authz.RolePlatformAdmin}, -time.Hour, time.Now())
	if r := doLogin(t, srv.URL, map[string]string{"token": expTok}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("过期令牌 login 应 401,得 %d", r.StatusCode)
	}
	// ZTNA 会话令牌(无角色)→ 401
	sessTok, _ := signer.Issue(cred.Claims{Subject: "u", TenantID: uuid.NewString()}, time.Hour, time.Now())
	if r := doLogin(t, srv.URL, map[string]string{"token": sessTok}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无角色令牌 login 应 401,得 %d", r.StatusCode)
	}
	// 缺 token → 400
	if r := doLogin(t, srv.URL, map[string]string{}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺 token login 应 400,得 %d", r.StatusCode)
	}
}

// TestSessionLoginHardening 验 Slice74 W2 reviewer 跟进的 /login 纵深:
//
//	R1 — 超大请求体经 http.MaxBytesReader 拦截 → 413(不读进内存、不崩、不 panic);正常体仍可登录。
//	R2 — 未认证公开端点 IP 限流:超速率 → 429;限流不影响正常登录(桶内仍有令牌时 401/200 正常返回)。
//
// 不需 DB(login 在 DB 错误之前就被 body 上限 / 限流 / 校验拦下;无效令牌走验签 401),
// 故 services 全传 nil-able 占位 + nil verifier? 不:login 需 verifier 验令牌,故传真 verifier;
// 但本测试不触达任何 Service(超大体/限流/无效令牌都在 Service 调用前返回),无需真 DB。
func TestSessionLoginHardening(t *testing.T) {
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("签发器: %v", err)
	}
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("验证器: %v", err)
	}

	// ── R1:超大 body → 413(用生产默认限流,确保不被 429 抢先)──
	t.Run("R1_oversize_body_413", func(t *testing.T) {
		httpapi.ResetLoginLimiterForTest(0, 0) // 生产默认 burst 10:本子测试单发一次,不触限流
		srv := newLoginOnlyServer(t, verifier)
		defer srv.Close()

		// 2 MiB body(> 1 MiB 上限):构造**合法 JSON 外形**({"token":"aaa…"})使 decoder 须读过
		// 上限才能解析 → MaxBytesReader 触发 *http.MaxBytesError → handler 返 413(而非 JSON 语法错的 400)。
		var buf bytes.Buffer
		buf.WriteString(`{"token":"`)
		buf.Write(bytes.Repeat([]byte("a"), 2<<20))
		buf.WriteString(`"}`)
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/login", bytes.NewReader(buf.Bytes()))
		req.Header.Set("Origin", srv.URL)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("超大 body login 请求出错(应得 413 响应,非传输错): %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("超大 body 应 413,得 %d", resp.StatusCode)
		}
	})

	// ── R1b:正常大小但缺 token → 400(证 body 上限不误伤正常体)──
	t.Run("R1b_normal_body_not_blocked", func(t *testing.T) {
		httpapi.ResetLoginLimiterForTest(0, 0)
		srv := newLoginOnlyServer(t, verifier)
		defer srv.Close()

		if r := doLogin(t, srv.URL, map[string]string{}); r.StatusCode != http.StatusBadRequest {
			r.Body.Close()
			t.Fatalf("正常空体(缺 token)应 400,得 %d", r.StatusCode)
		}
	})

	// ── R2:超速率 → 429;限流不影响桶内正常请求 ──
	t.Run("R2_rate_limit_429", func(t *testing.T) {
		// 小桶(burst 3, rate 极低)使 429 在数次请求内确定性触发,不依赖时序。
		httpapi.ResetLoginLimiterForTest(0.01, 3)
		srv := newLoginOnlyServer(t, verifier)
		defer srv.Close()

		// 前 burst(=3)次:不被限流(无效令牌 → 401,证请求到达 handler);第 4 次起 → 429。
		var got401, got429 int
		for i := 0; i < 6; i++ {
			r := doLogin(t, srv.URL, map[string]string{"token": "garbage.token"})
			switch r.StatusCode {
			case http.StatusUnauthorized:
				got401++
			case http.StatusTooManyRequests:
				got429++
			default:
				r.Body.Close()
				t.Fatalf("第 %d 次 login 期望 401 或 429,得 %d", i+1, r.StatusCode)
			}
			r.Body.Close()
		}
		if got401 != 3 {
			t.Errorf("应有 3 次到达 handler(401),得 %d", got401)
		}
		if got429 != 3 {
			t.Errorf("应有 3 次被限流(429),得 %d", got429)
		}
	})
}

// newLoginOnlyServer 起一个仅用于 /login 纵深测试的 Admin HTTP 栈(services 传 nil 占位:
// 本组测试都在触达 Service 之前返回,无需真 DB)。verifier 真实(login 需验签)。
func newLoginOnlyServer(t *testing.T, verifier *cred.Verifier) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	httpapi.Register(mux,
		nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil,
		nil, nil, nil,
		nil,
		nil, nil, verifier, nil, nil,
		nil,
	)
	srv := httptest.NewServer(mux)
	return srv
}

// doLogin 发 POST /api/v1/login(不带 Authorization、不带 csrf cookie/header → 验白名单)。
func doLogin(t *testing.T, base string, body map[string]string) *http.Response {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader([]byte("{}"))
	}
	req, err := http.NewRequest("POST", base+"/api/v1/login", rdr)
	if err != nil {
		t.Fatalf("构造 login: %v", err)
	}
	req.Header.Set("Origin", base)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login 请求: %v", err)
	}
	return resp
}

// doLogout 发 POST /api/v1/logout(带当前 session cookie)。
func doLogout(t *testing.T, base string, sess *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", base+"/api/v1/logout", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("构造 logout: %v", err)
	}
	if sess != nil {
		req.AddCookie(sess)
	}
	req.Header.Set("Origin", base)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout 请求: %v", err)
	}
	return resp
}

// doWithCookie 用 sase_session cookie(不带 Bearer)请求,返回状态码。
func doWithCookie(t *testing.T, base string, sess *http.Cookie, method, path string) int {
	t.Helper()
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	if sess != nil {
		req.AddCookie(sess)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return buf.Bytes()
}
