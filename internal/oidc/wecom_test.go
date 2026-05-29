package oidc

// 企微 adapter 端到端测试(Slice37b-1):
// 用 httptest 模拟企微 API(/cgi-bin/gettoken / user/getuserinfo / user/get),
// 验证:
//   ① AuthURL 字段(无 PKCE challenge,纯 state);
//   ② Exchange 三步链路(token cache → code→userid → user/get → UserInfo);
//   ③ access_token 缓存复用(多次 Exchange 仅一次 gettoken 调用);
//   ④ 业务错误(IdP errcode != 0)正确转 wecomAPIError;
//   ⑤ 外部联系人(只返 OpenId 无 UserId)被拒;
//   ⑥ 走 CallbackHandler 端到端(state TakeOnce + EnsureUser idpID 传入 + IssueCredential)。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
)

// mockWeCom 模拟企微 API server。
type mockWeCom struct {
	srv                 *httptest.Server
	expectCorpID        string
	expectCorpSec       string
	getTokenCalls       atomic.Int32      // 计数 /cgi-bin/gettoken 被调次数(验证缓存复用)
	codeToUser          map[string]string // code → userid(预置)
	userToDetail        map[string]struct{ Name, Email string }
	openIDOnlyCodes     map[string]bool // 这些 code 返 OpenId 不返 UserId(外部联系人)
	tokenErrcode        int             // 注入 gettoken 错码(0=正常)
	tokenExpireOverride *int            // 注入 gettoken 响应中的 expires_in 覆盖(nil=默认 7200,可注入 0/-1 边界)
}

func newMockWeCom(t *testing.T, corpID, corpSec string) *mockWeCom {
	t.Helper()
	m := &mockWeCom{
		expectCorpID:    corpID,
		expectCorpSec:   corpSec,
		codeToUser:      make(map[string]string),
		userToDetail:    make(map[string]struct{ Name, Email string }),
		openIDOnlyCodes: make(map[string]bool),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/cgi-bin/gettoken", m.getToken)
	mux.HandleFunc("/cgi-bin/user/getuserinfo", m.getUserInfo)
	mux.HandleFunc("/cgi-bin/user/get", m.getUserDetail)
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockWeCom) URL() string { return m.srv.URL }
func (m *mockWeCom) Close()      { m.srv.Close() }

func (m *mockWeCom) getToken(w http.ResponseWriter, r *http.Request) {
	m.getTokenCalls.Add(1)
	if r.URL.Query().Get("corpid") != m.expectCorpID || r.URL.Query().Get("corpsecret") != m.expectCorpSec {
		writeJSONResp(w, map[string]any{"errcode": 40013, "errmsg": "invalid corpid/secret"})
		return
	}
	if m.tokenErrcode != 0 {
		writeJSONResp(w, map[string]any{"errcode": m.tokenErrcode, "errmsg": "injected error"})
		return
	}
	expIn := 7200
	if m.tokenExpireOverride != nil {
		expIn = *m.tokenExpireOverride
	}
	writeJSONResp(w, map[string]any{"errcode": 0, "errmsg": "ok", "access_token": "mock-token-" + m.expectCorpID, "expires_in": expIn})
}

func (m *mockWeCom) getUserInfo(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if m.openIDOnlyCodes[code] {
		writeJSONResp(w, map[string]any{"errcode": 0, "errmsg": "ok", "OpenId": "openid-" + code})
		return
	}
	uid, ok := m.codeToUser[code]
	if !ok {
		writeJSONResp(w, map[string]any{"errcode": 40029, "errmsg": "invalid code"})
		return
	}
	writeJSONResp(w, map[string]any{"errcode": 0, "errmsg": "ok", "UserId": uid})
}

func (m *mockWeCom) getUserDetail(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("userid")
	d, ok := m.userToDetail[uid]
	if !ok {
		writeJSONResp(w, map[string]any{"errcode": 60111, "errmsg": "userid not found"})
		return
	}
	writeJSONResp(w, map[string]any{"errcode": 0, "errmsg": "ok", "name": d.Name, "email": d.Email})
}

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---------- 测试 ----------

// resetWeComCache:清理 package-level cache(防测试间互相污染)。
func resetWeComCache(t *testing.T) {
	t.Helper()
	wecomTokenCache.Range(func(k, _ any) bool { wecomTokenCache.Delete(k); return true })
	wecomTokenLocks.Range(func(k, _ any) bool { wecomTokenLocks.Delete(k); return true })
}

func TestWeComAuthURL(t *testing.T) {
	resetWeComCache(t)
	m := newMockWeCom(t, "wcorp", "wsec")
	defer m.Close()
	a, err := NewWeCom(context.Background(), WeComConfig{
		CorpID: "wcorp", CorpSecret: "wsec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	if err != nil {
		t.Fatalf("NewWeCom: %v", err)
	}
	auth, err := a.AuthURL(context.Background(), "state-x", "ignored-pkce", "http://cb")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	u, _ := url.Parse(auth)
	q := u.Query()
	if q.Get("appid") != "wcorp" || q.Get("response_type") != "code" || q.Get("scope") != "snsapi_base" {
		t.Fatalf("auth URL 字段错: %s", auth)
	}
	if q.Get("state") != "state-x" {
		t.Fatalf("state 缺")
	}
	if !strings.HasSuffix(auth, "#wechat_redirect") {
		t.Fatalf("企微 authorize URL 必须以 #wechat_redirect 结尾(浏览器路由):%s", auth)
	}
	// **不应**含 PKCE 字段(企微不支持)
	if q.Get("code_challenge") != "" || q.Get("code_challenge_method") != "" {
		t.Fatalf("企微无 PKCE,authorize URL 不应含 code_challenge*:%s", auth)
	}
}

func TestWeComExchange(t *testing.T) {
	resetWeComCache(t)
	m := newMockWeCom(t, "wcorp", "wsec")
	defer m.Close()
	m.codeToUser["code-alice"] = "alice@corp"
	m.userToDetail["alice@corp"] = struct{ Name, Email string }{Name: "Alice", Email: "alice@corp.com"}

	a, err := NewWeCom(context.Background(), WeComConfig{
		CorpID: "wcorp", CorpSecret: "wsec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	if err != nil {
		t.Fatalf("NewWeCom: %v", err)
	}
	ui, err := a.Exchange(context.Background(), "code-alice", "", "http://cb")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ui.Subject != "alice@corp" || ui.Name != "Alice" || ui.Email != "alice@corp.com" {
		t.Fatalf("UserInfo 字段错: %+v", ui)
	}
}

func TestWeComTokenCache(t *testing.T) {
	resetWeComCache(t)
	m := newMockWeCom(t, "wcorp2", "wsec")
	defer m.Close()
	m.codeToUser["c1"] = "u1"
	m.codeToUser["c2"] = "u2"
	m.userToDetail["u1"] = struct{ Name, Email string }{"U1", ""}
	m.userToDetail["u2"] = struct{ Name, Email string }{"U2", ""}
	a, _ := NewWeCom(context.Background(), WeComConfig{
		CorpID: "wcorp2", CorpSecret: "wsec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	// 两次 Exchange 仅一次 gettoken(后者复用缓存)
	if _, err := a.Exchange(context.Background(), "c1", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Exchange(context.Background(), "c2", "", ""); err != nil {
		t.Fatal(err)
	}
	if n := m.getTokenCalls.Load(); n != 1 {
		t.Fatalf("access_token 缓存未生效:gettoken 调了 %d 次(应 1 次)", n)
	}
}

// TestWeComTokenSingleFlight:N 个并发 goroutine 同时 Exchange(缓存未命中),
// 双检 + 单飞 mutex 应使 /cgi-bin/gettoken 仅被调一次(B8)。
func TestWeComTokenSingleFlight(t *testing.T) {
	resetWeComCache(t)
	m := newMockWeCom(t, "wcorp-sf", "wsec")
	defer m.Close()
	for i := 0; i < 20; i++ {
		code := fmt.Sprintf("c%d", i)
		uid := fmt.Sprintf("u%d", i)
		m.codeToUser[code] = uid
		m.userToDetail[uid] = struct{ Name, Email string }{Name: uid, Email: ""}
	}
	a, _ := NewWeCom(context.Background(), WeComConfig{
		CorpID: "wcorp-sf", CorpSecret: "wsec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	const N = 20
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = a.Exchange(context.Background(), fmt.Sprintf("c%d", idx), "", "")
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("并发 Exchange[%d]: %v", i, e)
		}
	}
	if n := m.getTokenCalls.Load(); n != 1 {
		t.Fatalf("并发单飞失败:gettoken 调了 %d 次(应 1 次,双检+sync.Map 单飞 mutex 是否生效?)", n)
	}
}

// TestWeComExpireEdge:gettoken 返 expire=1(异常但合法)→ 走兜底最低 1min,不破缓存逻辑;
// expire=0 或 expire<0 → 返字段缺失错(对齐 Slice37b-1 评审 B6 follow-up)。
func TestWeComExpireEdge(t *testing.T) {
	resetWeComCache(t)
	for _, tc := range []struct {
		expire int
		wantOK bool
	}{
		{7200, true}, // 正常
		{1, true},    // 兜底最低 1min(代码 ttl < time.Minute → 1min)
		{0, false},   // 拒(返字段缺失错)
		{-1, false},  // 拒
	} {
		t.Run(fmt.Sprintf("expire=%d", tc.expire), func(t *testing.T) {
			resetWeComCache(t)
			corpID := fmt.Sprintf("wcorp-ex-%d", tc.expire)
			m := newMockWeCom(t, corpID, "wsec")
			defer m.Close()
			// 注入定制 gettoken response 覆盖默认(默认 7200)
			ex := tc.expire
			m.tokenExpireOverride = &ex
			m.codeToUser["c-x"] = "u-x"
			m.userToDetail["u-x"] = struct{ Name, Email string }{"X", ""}
			a, _ := NewWeCom(context.Background(), WeComConfig{
				CorpID: corpID, CorpSecret: "wsec", APIBase: m.URL(), AuthHost: m.URL(),
			})
			_, err := a.Exchange(context.Background(), "c-x", "", "")
			if tc.wantOK && err != nil {
				t.Fatalf("expire=%d 应成功,得 %v", tc.expire, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("expire=%d 应失败(字段缺失),得 nil", tc.expire)
			}
		})
	}
}

func TestWeComInvalidCode(t *testing.T) {
	resetWeComCache(t)
	m := newMockWeCom(t, "wcorp3", "wsec")
	defer m.Close()
	a, _ := NewWeCom(context.Background(), WeComConfig{
		CorpID: "wcorp3", CorpSecret: "wsec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	_, err := a.Exchange(context.Background(), "no-such-code", "", "")
	if err == nil {
		t.Fatal("非法 code 应失败")
	}
	var apiErr *wecomAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != 40029 {
		t.Fatalf("应是 wecomAPIError errcode=40029,得 %v", err)
	}
}

func TestWeComOpenIDOnlyRejected(t *testing.T) {
	resetWeComCache(t)
	m := newMockWeCom(t, "wcorp4", "wsec")
	defer m.Close()
	m.openIDOnlyCodes["code-external"] = true
	a, _ := NewWeCom(context.Background(), WeComConfig{
		CorpID: "wcorp4", CorpSecret: "wsec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	_, err := a.Exchange(context.Background(), "code-external", "", "")
	if !errors.Is(err, ErrExternalContact) {
		t.Fatalf("OpenId 外部联系人应被拒(ErrExternalContact),得 %v", err)
	}
}

func TestWeComInvalidCorpSecret(t *testing.T) {
	resetWeComCache(t)
	m := newMockWeCom(t, "wcorp5", "right-secret")
	defer m.Close()
	a, _ := NewWeCom(context.Background(), WeComConfig{
		CorpID: "wcorp5", CorpSecret: "wrong-secret", APIBase: m.URL(), AuthHost: m.URL(),
	})
	_, err := a.Exchange(context.Background(), "any-code", "", "")
	if err == nil {
		t.Fatal("错 corpsecret 应失败")
	}
	var apiErr *wecomAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != 40013 {
		t.Fatalf("应是 wecomAPIError errcode=40013,得 %v", err)
	}
}

// TestWeComCallbackEnd2End:走 LoginHandler/CallbackHandler 完整链路(state+factory dispatch+EnsureUser+IssueCredential),
// 验 DispatchFactory 按 cfg.Kind=wecom 派发到 WeComAdapter,并把 idpID 传入 EnsureUser(多 IdP 支持)。
func TestWeComCallbackEnd2End(t *testing.T) {
	resetWeComCache(t)
	mock := newMockWeCom(t, "wcorpE", "wsecE")
	defer mock.Close()
	mock.codeToUser["code-bob"] = "bob@corp"
	mock.userToDetail["bob@corp"] = struct{ Name, Email string }{"Bob", "bob@corp.com"}

	const (
		tid = "t-wecom"
		cid = "wecom-cfg-id"
	)
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: cid, TenantID: tid, Name: "wecom", Kind: KindWeCom, Endpoint: mock.URL(), ClientID: "wcorpE", Status: "active"},
		secret: []byte("wsecE"),
	}
	stubID := &stubIdentity{users: make(map[string]identity.User)}
	stateStore := NewInMemoryStateStore()
	defer stateStore.Stop()
	// **关键**:用 DispatchFactory(生产 factory),验证 cfg.Kind=wecom 派发到 NewWeCom
	// 注:DispatchFactory 对 wecom kind 调 NewWeCom,默认 AuthHost=https://open.weixin.qq.com(生产);
	// 测试此处用 APIBase=mock 走 token+userinfo+user/get,AuthURL 跳生产 host(测试不模拟浏览器跳转,可接受)。
	// 若希望 AuthURL 也指向 mock,需扩 IdPConfig 加 AuthHost 字段;Slice37b-1 不扩,作合规联调时人工配置。
	deps := &HandlerDeps{
		IDPSvc:      stubIDP,
		Identity:    stubID,
		StateStore:  stateStore,
		Factory:     DispatchFactory,
		CallbackURL: "http://localhost/api/v1/idp/callback",
	}

	// 直接走 callback(跳过 login 跳转,因为企微 AuthURL 不指 mock host)
	// 手工塞一个 state 记录,模拟 login 已发生
	stateID, err := stateStore.Put(context.Background(), StateRecord{
		TenantID: tid, IDPID: cid, RedirectURI: deps.CallbackURL,
	})
	if err != nil {
		t.Fatalf("state put: %v", err)
	}
	cbReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/idp/callback?code=code-bob&state=%s", stateID), nil)
	cbRec := httptest.NewRecorder()
	CallbackHandler(deps).ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusOK {
		t.Fatalf("/callback 期望 200,得 %d body=%s", cbRec.Code, cbRec.Body.String())
	}
	var resp CallbackResponse
	if err := json.Unmarshal(cbRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解响应: %v", err)
	}
	if resp.UserID != "u-bob@corp" {
		t.Fatalf("UserID 期望 u-bob@corp,得 %s", resp.UserID)
	}
	if resp.Email != "bob@corp.com" {
		t.Fatalf("Email 应来自 mock user/get,得 %s", resp.Email)
	}
	// 多 IdP 支持:EnsureUser key 含 idpID(cid)
	if _, ok := stubID.users[cid+":bob@corp"]; !ok {
		t.Fatalf("EnsureUser 应按 idpID:externalID 键,得 %v", stubID.users)
	}
}
