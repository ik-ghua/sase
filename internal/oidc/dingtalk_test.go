package oidc

// 钉钉 adapter 端到端测试(Slice37b-2):
// httptest 模拟钉钉 v1.0 API(POST /oauth2/userAccessToken + GET /contact/users/me),验:
//   ① AuthURL 字段(无 PKCE,scope=openid,prompt=consent);
//   ② Exchange 两步链(code→userAccessToken→users/me);
//   ③ stateCode=-1 / 0 / 缺失 均拒(fail-closed 仅企业内成员);
//   ④ 错码 API error 经 dingtalkAPIError + errors.As 类型化;
//   ⑤ DispatchFactory 按 kind=dingtalk 派发到 NewDingTalk。

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// mockDingTalk 模拟钉钉 v1.0 API。**httptest 多 goroutine 服务,map 写须经 mu**。
type mockDingTalk struct {
	srv             *httptest.Server
	expectClientID  string
	expectClientSec string
	mu              sync.Mutex // 守护下方 map
	// code → 一组用户身份(模拟 IdP 端用户授权产生的 code 与对应身份关联)
	codeToUser map[string]mockDingTalkUser
	// userToken → 用户 unionId(模拟钉钉的 per-user access token 到身份的映射)
	tokenToUser map[string]string
	// 已建立 token 的完整身份信息(供 users/me 端点查)
	userInfoByUnion map[string]mockDingTalkUser
	// 注入 userAccessToken 响应的 unionId 覆盖(测 S1 两源不一致用;空→走 codeToUser 默认)
	codeToTokenUnionOverride map[string]string
}

type mockDingTalkUser struct {
	UnionID   string
	OpenID    string
	Nick      string
	Email     string
	StateCode int // 1=企业内 / -1=外部 / 0=未知
}

func newMockDingTalk(t *testing.T, clientID, clientSec string) *mockDingTalk {
	t.Helper()
	m := &mockDingTalk{
		expectClientID:           clientID,
		expectClientSec:          clientSec,
		codeToUser:               make(map[string]mockDingTalkUser),
		tokenToUser:              make(map[string]string),
		userInfoByUnion:          make(map[string]mockDingTalkUser),
		codeToTokenUnionOverride: make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/oauth2/userAccessToken", m.userAccessToken)
	mux.HandleFunc("/v1.0/contact/users/me", m.usersMe)
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockDingTalk) URL() string { return m.srv.URL }
func (m *mockDingTalk) Close()      { m.srv.Close() }

// addUser:测试 helper:绑定一个 code 到一份身份(模拟 IdP 授权完成)。
func (m *mockDingTalk) addUser(code string, u mockDingTalkUser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codeToUser[code] = u
	m.userInfoByUnion[u.UnionID] = u
}

func (m *mockDingTalk) userAccessToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Code         string `json:"code"`
		GrantType    string `json:"grantType"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"code": "BadRequest", "message": "bad json"})
		return
	}
	if req.ClientID != m.expectClientID || req.ClientSecret != m.expectClientSec {
		writeJSONStatus(w, http.StatusForbidden, map[string]any{"code": "Forbidden.AccessDenied", "message": "invalid client"})
		return
	}
	m.mu.Lock()
	user, ok := m.codeToUser[req.Code]
	if !ok {
		m.mu.Unlock()
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"code": "Invalid.AuthCode", "message": "invalid code"})
		return
	}
	token := "tok-" + user.UnionID
	m.tokenToUser[token] = user.UnionID
	// S1 测试钩子:可注入 token 响应的 unionId 覆盖(模拟两跳间不一致)
	respUnionID := user.UnionID
	if override, ok := m.codeToTokenUnionOverride[req.Code]; ok {
		respUnionID = override
	}
	m.mu.Unlock()
	writeJSONStatus(w, http.StatusOK, map[string]any{"accessToken": token, "refreshToken": "rt-x", "expireIn": 7200, "unionId": respUnionID})
}

func (m *mockDingTalk) usersMe(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("x-acs-dingtalk-access-token")
	m.mu.Lock()
	uid, ok := m.tokenToUser[tok]
	if !ok {
		m.mu.Unlock()
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"code": "Unauthorized", "message": "invalid access token"})
		return
	}
	u := m.userInfoByUnion[uid]
	m.mu.Unlock()
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"unionId":   u.UnionID,
		"openId":    u.OpenID,
		"nick":      u.Nick,
		"email":     u.Email,
		"stateCode": u.StateCode,
	})
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------- 测试 ----------

func TestDingTalkAuthURL(t *testing.T) {
	a, err := NewDingTalk(context.Background(), DingTalkConfig{
		ClientID: "dt-app", ClientSecret: "dt-sec", APIBase: "http://x", OAuthHost: "http://x",
	})
	if err != nil {
		t.Fatalf("NewDingTalk: %v", err)
	}
	auth, err := a.AuthURL(context.Background(), "state-y", "ignored", "http://cb")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	u, _ := url.Parse(auth)
	q := u.Query()
	if q.Get("client_id") != "dt-app" || q.Get("response_type") != "code" || q.Get("scope") != "openid" || q.Get("prompt") != "consent" {
		t.Fatalf("auth URL 字段错: %s", auth)
	}
	if q.Get("state") != "state-y" {
		t.Fatalf("state 缺")
	}
	if q.Get("code_challenge") != "" {
		t.Fatalf("钉钉无 PKCE,authorize URL 不应含 code_challenge:%s", auth)
	}
}

func TestDingTalkExchange(t *testing.T) {
	m := newMockDingTalk(t, "dt-app", "dt-sec")
	defer m.Close()
	m.addUser("code-alice", mockDingTalkUser{UnionID: "uid-alice", Nick: "Alice", Email: "alice@dt.com", StateCode: 1})
	a, _ := NewDingTalk(context.Background(), DingTalkConfig{
		ClientID: "dt-app", ClientSecret: "dt-sec", APIBase: m.URL(), OAuthHost: m.URL(),
	})
	ui, err := a.Exchange(context.Background(), "code-alice", "", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ui.Subject != "uid-alice" || ui.Name != "Alice" || ui.Email != "alice@dt.com" {
		t.Fatalf("UserInfo 字段错: %+v", ui)
	}
}

// TestDingTalkExternalUserRejected:stateCode != 1 一律拒(fail-closed 仅企业内成员)。
func TestDingTalkExternalUserRejected(t *testing.T) {
	m := newMockDingTalk(t, "dt-app", "dt-sec")
	defer m.Close()
	m.addUser("code-ext", mockDingTalkUser{UnionID: "uid-ext", Nick: "Ext", Email: "x@y", StateCode: -1})
	m.addUser("code-unknown", mockDingTalkUser{UnionID: "uid-u", Nick: "U", StateCode: 0})
	a, _ := NewDingTalk(context.Background(), DingTalkConfig{
		ClientID: "dt-app", ClientSecret: "dt-sec", APIBase: m.URL(), OAuthHost: m.URL(),
	})
	for _, code := range []string{"code-ext", "code-unknown"} {
		_, err := a.Exchange(context.Background(), code, "", "")
		if !errors.Is(err, ErrDingTalkExternalUser) {
			t.Fatalf("code=%s 应被拒(ErrDingTalkExternalUser),得 %v", code, err)
		}
	}
}

func TestDingTalkInvalidCode(t *testing.T) {
	m := newMockDingTalk(t, "dt-app", "dt-sec")
	defer m.Close()
	a, _ := NewDingTalk(context.Background(), DingTalkConfig{
		ClientID: "dt-app", ClientSecret: "dt-sec", APIBase: m.URL(), OAuthHost: m.URL(),
	})
	_, err := a.Exchange(context.Background(), "no-such-code", "", "")
	if err == nil {
		t.Fatal("非法 code 应失败")
	}
	var apiErr *dingtalkAPIError
	if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Code, "AuthCode") {
		t.Fatalf("应是 dingtalkAPIError code 含 AuthCode,得 %v", err)
	}
}

func TestDingTalkInvalidClientSecret(t *testing.T) {
	m := newMockDingTalk(t, "dt-app", "right-secret")
	defer m.Close()
	a, _ := NewDingTalk(context.Background(), DingTalkConfig{
		ClientID: "dt-app", ClientSecret: "wrong-secret", APIBase: m.URL(), OAuthHost: m.URL(),
	})
	_, err := a.Exchange(context.Background(), "any-code", "", "")
	var apiErr *dingtalkAPIError
	if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Code, "Forbidden") {
		t.Fatalf("应是 dingtalkAPIError Forbidden,得 %v", err)
	}
}

// TestDingTalkUnionIDMismatch:userAccessToken 响应里的 unionId 与 users/me 返回的 unionId 不一致
// → ErrDingTalkUnionIDMismatch(S1 防御纵深)。
func TestDingTalkUnionIDMismatch(t *testing.T) {
	m := newMockDingTalk(t, "dt-mx", "dt-sec")
	defer m.Close()
	// users/me 端会返 uid-A(基于 addUser)
	m.addUser("code-mix", mockDingTalkUser{UnionID: "uid-A", Nick: "A", StateCode: 1})
	// 但 userAccessToken 响应中的 unionId 注入为 uid-B(模拟两跳不一致)
	m.mu.Lock()
	m.codeToTokenUnionOverride["code-mix"] = "uid-B"
	m.mu.Unlock()
	a, _ := NewDingTalk(context.Background(), DingTalkConfig{
		ClientID: "dt-mx", ClientSecret: "dt-sec", APIBase: m.URL(), OAuthHost: m.URL(),
	})
	_, err := a.Exchange(context.Background(), "code-mix", "", "")
	if !errors.Is(err, ErrDingTalkUnionIDMismatch) {
		t.Fatalf("两源 unionId 不一致应被拒(ErrDingTalkUnionIDMismatch),得 %v", err)
	}
}

func TestDingTalkDispatch(t *testing.T) {
	// 验 DispatchFactory 对 kind=dingtalk 派发到 NewDingTalk
	cfg := newIdpCfg(t, "dingtalk-id", "dingtalk", "http://nope", "dt-app")
	_, err := DispatchFactory(context.Background(), cfg, []byte("dt-sec"))
	if err != nil {
		t.Fatalf("DispatchFactory dingtalk: %v", err)
	}
}
