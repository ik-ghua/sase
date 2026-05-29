package oidc

// Slice37c 验:
//   ① cookie+302 路径:Accept 显式含 text/html(浏览器) → Set-Cookie sase_session + 302→rec.ReturnTo;
//   ② JSON 路径:Accept 无 text/html(默认/API/curl)→ 返 JSON(向后兼容 Slice37a/b);
//   ③ return_to 安全:绝对 URL / protocol-relative / 含 \ / 空 → 退默认 "/";同源相对路径放行;
//   ④ Cookie 属性:HttpOnly / SameSite=Lax / Path=/ / MaxAge;
//   ⑤ Delete IdP 联动淘汰:InvalidateForIDP(wecom, corpid) 清掉 wecom token cache;feishu 同;
//   ⑥ AuthHost 经 Extra 可配:DispatchFactory 把 cfg.Extra["wecom_auth_host"] 传到 NewWeCom。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
)

// ---------- (③) return_to 校验 ----------

func TestSanitizeReturnTo(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "/"},                    // 空 → 默认
		{"/app/users", "/app/users"}, // 同源相对 OK
		{"/", "/"},                   // 单 /
		{"//evil.com/x", "/"},        // protocol-relative 禁
		{"https://evil.com", "/"},    // absolute URL 禁
		{"http://x", "/"},
		{"javascript:alert(1)", "/"},
		{"/path?with=query&a=b", "/path?with=query&a=b"}, // query 放行
		{"/path#frag", "/path#frag"},                     // fragment 放行
		{`/path\with\backslash`, "/"},                    // \ 禁(IE/历史浏览器歧义)
		{"/path\r\nLocation: evil", "/"},                 // B1:控制字符拒(防 header splitting / SPA 路由误判)
		{"/path\x00null", "/"},                           // B1:NUL 拒
		{"/path\ttab", "/"},                              // B1:TAB 拒
	}
	for _, c := range cases {
		if got := sanitizeReturnTo(c.in); got != c.want {
			t.Errorf("sanitizeReturnTo(%q): got %q want %q", c.in, got, c.want)
		}
	}
}

// ---------- (①②④) cookie+302 vs JSON 路径 ----------

func TestCallbackCookieRedirect(t *testing.T) {
	mock := newMockOIDC(t)
	defer mock.Close()
	const (
		tid = "t-cookie"
		cid = "c-cookie"
	)
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: cid, TenantID: tid, Kind: "oidc", Endpoint: mock.URL(), ClientID: "sase-test", Status: "active"},
		secret: []byte("s"),
	}
	stubID := &stubIdentity{users: make(map[string]identity.User)}
	stateStore := NewInMemoryStateStore()
	defer stateStore.Stop()
	deps := &HandlerDeps{
		IDPSvc: stubIDP, Identity: stubID, StateStore: stateStore,
		Factory: GenericFactory, CallbackURL: "http://localhost/api/v1/idp/callback",
	}

	// 走 login 拿 state(带 return_to)
	loginReq := httptest.NewRequest(http.MethodGet, "/api/v1/idp/login?tenant_id="+tid+"&idp_id="+cid+"&return_to=/app/dashboard", nil)
	loginRec := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusSeeOther {
		t.Fatalf("/login 期望 303,得 %d", loginRec.Code)
	}
	u, _ := url.Parse(loginRec.Header().Get("Location"))
	state := u.Query().Get("state")
	challenge := u.Query().Get("code_challenge")
	code := mock.issueCode("sase-test", challenge, "alice-cookie", "alice@x", "Alice")

	// 回调(显式 Accept: text/html,模拟浏览器)→ 302 + cookie
	cbReq := httptest.NewRequest(http.MethodGet, "/api/v1/idp/callback?code="+code+"&state="+state, nil)
	cbReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	cbRec := httptest.NewRecorder()
	CallbackHandler(deps).ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("浏览器回调期望 302,得 %d body=%s", cbRec.Code, cbRec.Body.String())
	}
	loc := cbRec.Header().Get("Location")
	if loc != "/app/dashboard" {
		t.Fatalf("302 Location 应跳 return_to=/app/dashboard,得 %q", loc)
	}
	// Cookie 属性
	setCookie := cbRec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "sase_session=") {
		t.Fatalf("应设 sase_session cookie,得 %q", setCookie)
	}
	if !strings.Contains(setCookie, "HttpOnly") {
		t.Errorf("cookie 应含 HttpOnly: %q", setCookie)
	}
	if !strings.Contains(setCookie, "SameSite=Lax") {
		t.Errorf("cookie 应含 SameSite=Lax: %q", setCookie)
	}
	if !strings.Contains(setCookie, "Path=/") {
		t.Errorf("cookie 应含 Path=/: %q", setCookie)
	}
	if !strings.Contains(setCookie, "Max-Age=") {
		t.Errorf("cookie 应含 Max-Age: %q", setCookie)
	}
}

func TestCallbackJSONPath(t *testing.T) {
	mock := newMockOIDC(t)
	defer mock.Close()
	const (
		tid = "t-json"
		cid = "c-json"
	)
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: cid, TenantID: tid, Kind: "oidc", Endpoint: mock.URL(), ClientID: "sase-json", Status: "active"},
		secret: []byte("s"),
	}
	stubID := &stubIdentity{users: make(map[string]identity.User)}
	stateStore := NewInMemoryStateStore()
	defer stateStore.Stop()
	deps := &HandlerDeps{
		IDPSvc: stubIDP, Identity: stubID, StateStore: stateStore,
		Factory: GenericFactory, CallbackURL: "http://localhost/api/v1/idp/callback",
	}
	loginReq := httptest.NewRequest(http.MethodGet, "/api/v1/idp/login?tenant_id="+tid+"&idp_id="+cid, nil)
	loginRec := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(loginRec, loginReq)
	u, _ := url.Parse(loginRec.Header().Get("Location"))
	state := u.Query().Get("state")
	challenge := u.Query().Get("code_challenge")
	code := mock.issueCode("sase-json", challenge, "bob-json", "bob@x", "Bob")

	// 默认无 Accept(模拟编程客户端/curl)→ JSON
	cbReq := httptest.NewRequest(http.MethodGet, "/api/v1/idp/callback?code="+code+"&state="+state, nil)
	cbRec := httptest.NewRecorder()
	CallbackHandler(deps).ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusOK {
		t.Fatalf("默认 Accept 应返 200 JSON,得 %d body=%s", cbRec.Code, cbRec.Body.String())
	}
	// **不**应有 Set-Cookie / Location
	if cbRec.Header().Get("Set-Cookie") != "" {
		t.Errorf("JSON 路径不应设 cookie")
	}
	if cbRec.Header().Get("Location") != "" {
		t.Errorf("JSON 路径不应 302")
	}
	var resp CallbackResponse
	if err := json.Unmarshal(cbRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解 JSON: %v", err)
	}
	if resp.Token == "" || resp.UserID == "" {
		t.Errorf("JSON 响应缺字段: %+v", resp)
	}
}

// LoginHandler 接 return_to 不合规 → 落 state 默认 "/" 而不报错
func TestLoginHandlerReturnToDownsizedToDefault(t *testing.T) {
	mock := newMockOIDC(t)
	defer mock.Close()
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: "c", TenantID: "t", Kind: "oidc", Endpoint: mock.URL(), ClientID: "x", Status: "active"},
		secret: []byte("s"),
	}
	stateStore := NewInMemoryStateStore()
	defer stateStore.Stop()
	deps := &HandlerDeps{
		IDPSvc: stubIDP, Identity: &stubIdentity{users: make(map[string]identity.User)}, StateStore: stateStore,
		Factory: GenericFactory, CallbackURL: "http://cb",
	}
	// 攻击者注入绝对 URL
	loginReq := httptest.NewRequest(http.MethodGet, "/api/v1/idp/login?tenant_id=t&idp_id=c&return_to=https://evil.com", nil)
	loginRec := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusSeeOther {
		t.Fatalf("/login 期望 303,得 %d", loginRec.Code)
	}
	// 取 state record 校 ReturnTo 已被压成 "/"
	u, _ := url.Parse(loginRec.Header().Get("Location"))
	state := u.Query().Get("state")
	rec, err := stateStore.TakeOnce(context.Background(), state)
	if err != nil {
		t.Fatalf("TakeOnce: %v", err)
	}
	if rec.ReturnTo != "/" {
		t.Fatalf("绝对 URL return_to 应被压成 /,得 %q(open-redirect 风险)", rec.ReturnTo)
	}
}

// ---------- (⑤) Delete IdP 联动淘汰 token cache ----------

func TestInvalidateForIDPWeCom(t *testing.T) {
	resetWeComCache(t)
	// 预置两条 wecom cache(不同 apiBase 但同 corpid)+ 一条无关 corpid
	wecomTokenCachePut("http://mock1|corp-A", "tokA1", time.Now().Add(time.Hour))
	wecomTokenCachePut("http://mock2|corp-A", "tokA2", time.Now().Add(time.Hour))
	wecomTokenCachePut("http://mock1|corp-B", "tokB", time.Now().Add(time.Hour))

	InvalidateForIDP(KindWeCom, "corp-A")

	if _, ok := wecomTokenCacheGet("http://mock1|corp-A"); ok {
		t.Error("corp-A cache 应被清(mock1)")
	}
	if _, ok := wecomTokenCacheGet("http://mock2|corp-A"); ok {
		t.Error("corp-A cache 应被清(mock2)")
	}
	if _, ok := wecomTokenCacheGet("http://mock1|corp-B"); !ok {
		t.Error("corp-B 与 corp-A 无关,不应被清")
	}
}

func TestInvalidateForIDPFeishu(t *testing.T) {
	resetFeishuCache(t)
	feishuTokenCachePut("http://mock|app-X", "tokX", time.Now().Add(time.Hour))
	feishuTokenCachePut("http://mock|app-Y", "tokY", time.Now().Add(time.Hour))

	InvalidateForIDP(KindFeishu, "app-X")

	if _, ok := feishuTokenCacheGet("http://mock|app-X"); ok {
		t.Error("app-X feishu cache 应被清")
	}
	if _, ok := feishuTokenCacheGet("http://mock|app-Y"); !ok {
		t.Error("app-Y 不应受影响")
	}
}

func TestInvalidateForIDPNoOp(_ *testing.T) {
	// oidc / dingtalk / 未知 kind:noop,不 panic
	InvalidateForIDP(KindOIDC, "x")
	InvalidateForIDP(KindDingTalk, "x")
	InvalidateForIDP("unknown-kind", "x")
}

// ---------- (⑥) AuthHost 经 Extra 可配 ----------

func TestDispatchFactoryReadsExtraAuthHost(t *testing.T) {
	// 用 wecom 验证(其它两家同形态)。需要的是 NewWeCom 实际收到 AuthHost——但 NewWeCom 返
	// Adapter 接口,内部 authHost 字段不可见。退一步:经 AuthURL 检查跳转 host 是否反映 Extra 值。
	cfg := &idp.Config{
		ID: "x", TenantID: "t", Kind: KindWeCom, Endpoint: "http://api",
		ClientID: "corpid", Status: "active",
		Extra: map[string]any{"wecom_auth_host": "http://private-wecom.example.com"},
	}
	a, err := DispatchFactory(context.Background(), cfg, []byte("sec"))
	if err != nil {
		t.Fatalf("DispatchFactory: %v", err)
	}
	auth, err := a.AuthURL(context.Background(), "s", "v", "http://cb")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	if !strings.HasPrefix(auth, "http://private-wecom.example.com/connect/oauth2/authorize") {
		t.Fatalf("AuthURL 应使用 Extra 配的 AuthHost,得 %s", auth)
	}
}

func TestDispatchFactoryExtraMissingFallsBack(t *testing.T) {
	cfg := &idp.Config{
		ID: "x", TenantID: "t", Kind: KindWeCom, Endpoint: "http://api",
		ClientID: "corpid", Status: "active",
		Extra: nil, // 未配 Extra
	}
	a, err := DispatchFactory(context.Background(), cfg, []byte("sec"))
	if err != nil {
		t.Fatalf("DispatchFactory: %v", err)
	}
	auth, _ := a.AuthURL(context.Background(), "s", "v", "http://cb")
	if !strings.HasPrefix(auth, wecomDefaultAuthHost) {
		t.Fatalf("未配 Extra 应走生产默认 %s,得 %s", wecomDefaultAuthHost, auth)
	}
}
