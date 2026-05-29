package oidc

// 飞书 adapter 端到端测试(Slice37b-2):
// httptest 模拟飞书 v3 API(三步链:app_access_token / oidc/access_token / user_info),验:
//   ① AuthURL 字段(无 PKCE,response_type=code,state);
//   ② Exchange 三步链成功;
//   ③ app_access_token 缓存复用(多次 Exchange 仅一次 app_token 调用);
//   ④ 并发 N=20 单飞验证(只换一次 app_access_token);
//   ⑤ 错码(business code != 0)经 feishuAPIError + errors.As 类型化;
//   ⑥ DispatchFactory 按 kind=feishu 派发到 NewFeishu。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// mockFeishu 模拟飞书 API。**httptest 多 goroutine 并发服务,所有 map 写须经 mu**。
type mockFeishu struct {
	srv               *httptest.Server
	expectAppID       string
	expectAppSec      string
	appTokenCalls     atomic.Int32 // app_access_token 端点调用计数(验单飞 + 缓存)
	mu                sync.Mutex   // 守护下方 map
	codeToUser        map[string]mockFeishuUser
	userTokenToUser   map[string]string // user_access_token → union_id
	userInfoByUnion   map[string]mockFeishuUser
	appAccessTokenVal string // app_access_token 注入值(不变,无需锁)
}

type mockFeishuUser struct {
	UnionID string
	OpenID  string
	Name    string
	Email   string
}

func newMockFeishu(t *testing.T, appID, appSec string) *mockFeishu {
	t.Helper()
	m := &mockFeishu{
		expectAppID:       appID,
		expectAppSec:      appSec,
		codeToUser:        make(map[string]mockFeishuUser),
		userTokenToUser:   make(map[string]string),
		userInfoByUnion:   make(map[string]mockFeishuUser),
		appAccessTokenVal: "app-tok-" + appID,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/open-apis/auth/v3/app_access_token/internal", m.appToken)
	mux.HandleFunc("/open-apis/authen/v1/oidc/access_token", m.userToken)
	mux.HandleFunc("/open-apis/authen/v1/user_info", m.userInfo)
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockFeishu) URL() string { return m.srv.URL }
func (m *mockFeishu) Close()      { m.srv.Close() }

func (m *mockFeishu) addUser(code string, u mockFeishuUser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codeToUser[code] = u
	m.userInfoByUnion[u.UnionID] = u
}

func (m *mockFeishu) appToken(w http.ResponseWriter, r *http.Request) {
	m.appTokenCalls.Add(1)
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		AppID     string `json:"app_id"`
		AppSecret string `json:"app_secret"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONStatus(w, http.StatusOK, map[string]any{"code": 10003, "msg": "bad json"})
		return
	}
	if req.AppID != m.expectAppID || req.AppSecret != m.expectAppSec {
		writeJSONStatus(w, http.StatusOK, map[string]any{"code": 10003, "msg": "invalid app_id/secret"})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"code": 0, "msg": "ok", "app_access_token": m.appAccessTokenVal, "expire": 7200})
}

func (m *mockFeishu) userToken(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != m.appAccessTokenVal {
		writeJSONStatus(w, http.StatusOK, map[string]any{"code": 99991663, "msg": "invalid app token"})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		GrantType string `json:"grant_type"`
		Code      string `json:"code"`
	}
	_ = json.Unmarshal(body, &req)
	m.mu.Lock()
	u, ok := m.codeToUser[req.Code]
	if !ok {
		m.mu.Unlock()
		writeJSONStatus(w, http.StatusOK, map[string]any{"code": 20007, "msg": "invalid code"})
		return
	}
	userTok := "user-tok-" + u.UnionID
	m.userTokenToUser[userTok] = u.UnionID
	m.mu.Unlock()
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"code": 0, "msg": "ok",
		"data": map[string]any{"access_token": userTok, "refresh_token": "rt", "expires_in": 7200},
	})
}

func (m *mockFeishu) userInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		writeJSONStatus(w, http.StatusOK, map[string]any{"code": 99991663, "msg": "no token"})
		return
	}
	m.mu.Lock()
	uid, ok := m.userTokenToUser[strings.TrimPrefix(auth, "Bearer ")]
	if !ok {
		m.mu.Unlock()
		writeJSONStatus(w, http.StatusOK, map[string]any{"code": 99991663, "msg": "invalid user token"})
		return
	}
	u := m.userInfoByUnion[uid]
	m.mu.Unlock()
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"code": 0, "msg": "ok",
		"data": map[string]any{
			"union_id": u.UnionID, "open_id": u.OpenID, "name": u.Name, "email": u.Email,
		},
	})
}

// ---------- 测试 ----------

// resetFeishuCache:清缓存(防测试间互染)。
func resetFeishuCache(t *testing.T) {
	t.Helper()
	feishuTokenCache.Range(func(k, _ any) bool { feishuTokenCache.Delete(k); return true })
	feishuTokenLocks.Range(func(k, _ any) bool { feishuTokenLocks.Delete(k); return true })
}

func TestFeishuAuthURL(t *testing.T) {
	a, err := NewFeishu(context.Background(), FeishuConfig{
		AppID: "fs-app", AppSecret: "fs-sec", APIBase: "http://x", AuthHost: "http://x",
	})
	if err != nil {
		t.Fatalf("NewFeishu: %v", err)
	}
	auth, err := a.AuthURL(context.Background(), "state-z", "ignored", "http://cb")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	u, _ := url.Parse(auth)
	q := u.Query()
	if q.Get("client_id") != "fs-app" || q.Get("response_type") != "code" || q.Get("state") != "state-z" {
		t.Fatalf("auth URL 字段错: %s", auth)
	}
	if !strings.Contains(auth, "/open-apis/authen/v1/authorize") {
		t.Fatalf("auth URL path 错: %s", auth)
	}
	if q.Get("code_challenge") != "" {
		t.Fatalf("飞书无 PKCE:%s", auth)
	}
}

func TestFeishuExchange(t *testing.T) {
	resetFeishuCache(t)
	m := newMockFeishu(t, "fs-app", "fs-sec")
	defer m.Close()
	m.addUser("code-bob", mockFeishuUser{UnionID: "uid-bob", Name: "Bob", Email: "bob@fs.com"})
	a, _ := NewFeishu(context.Background(), FeishuConfig{
		AppID: "fs-app", AppSecret: "fs-sec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	ui, err := a.Exchange(context.Background(), "code-bob", "", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ui.Subject != "uid-bob" || ui.Name != "Bob" || ui.Email != "bob@fs.com" {
		t.Fatalf("UserInfo 字段错: %+v", ui)
	}
}

func TestFeishuAppTokenCache(t *testing.T) {
	resetFeishuCache(t)
	m := newMockFeishu(t, "fs-app2", "fs-sec")
	defer m.Close()
	m.addUser("c1", mockFeishuUser{UnionID: "u1"})
	m.addUser("c2", mockFeishuUser{UnionID: "u2"})
	a, _ := NewFeishu(context.Background(), FeishuConfig{
		AppID: "fs-app2", AppSecret: "fs-sec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	if _, err := a.Exchange(context.Background(), "c1", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Exchange(context.Background(), "c2", "", ""); err != nil {
		t.Fatal(err)
	}
	if n := m.appTokenCalls.Load(); n != 1 {
		t.Fatalf("app_access_token 缓存未生效:app_token 调了 %d 次(应 1 次)", n)
	}
}

// TestFeishuTokenSingleFlight:N 个并发 Exchange,缓存未命中 → 应只换一次 app_access_token。
func TestFeishuTokenSingleFlight(t *testing.T) {
	resetFeishuCache(t)
	m := newMockFeishu(t, "fs-sf", "fs-sec")
	defer m.Close()
	for i := 0; i < 20; i++ {
		code := fmt.Sprintf("c%d", i)
		uid := fmt.Sprintf("u%d", i)
		m.addUser(code, mockFeishuUser{UnionID: uid})
	}
	a, _ := NewFeishu(context.Background(), FeishuConfig{
		AppID: "fs-sf", AppSecret: "fs-sec", APIBase: m.URL(), AuthHost: m.URL(),
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
	if n := m.appTokenCalls.Load(); n != 1 {
		t.Fatalf("并发单飞失败:app_token 调了 %d 次(应 1 次,双检+sync.Map 单飞 mutex 是否生效?)", n)
	}
}

func TestFeishuInvalidCode(t *testing.T) {
	resetFeishuCache(t)
	m := newMockFeishu(t, "fs-bad", "fs-sec")
	defer m.Close()
	a, _ := NewFeishu(context.Background(), FeishuConfig{
		AppID: "fs-bad", AppSecret: "fs-sec", APIBase: m.URL(), AuthHost: m.URL(),
	})
	_, err := a.Exchange(context.Background(), "no-such-code", "", "")
	var apiErr *feishuAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != 20007 {
		t.Fatalf("应是 feishuAPIError code=20007,得 %v", err)
	}
}

func TestFeishuInvalidAppSecret(t *testing.T) {
	resetFeishuCache(t)
	m := newMockFeishu(t, "fs-x", "right-secret")
	defer m.Close()
	a, _ := NewFeishu(context.Background(), FeishuConfig{
		AppID: "fs-x", AppSecret: "wrong-secret", APIBase: m.URL(), AuthHost: m.URL(),
	})
	_, err := a.Exchange(context.Background(), "any-code", "", "")
	var apiErr *feishuAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != 10003 {
		t.Fatalf("应是 feishuAPIError code=10003,得 %v", err)
	}
}

func TestFeishuDispatch(t *testing.T) {
	cfg := newIdpCfg(t, "feishu-id", "feishu", "http://nope", "fs-app")
	_, err := DispatchFactory(context.Background(), cfg, []byte("fs-sec"))
	if err != nil {
		t.Fatalf("DispatchFactory feishu: %v", err)
	}
}
