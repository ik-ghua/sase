package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
)

// 本测用 httptest 模拟标准 OIDC IdP(discovery / token / userinfo / JWKS):
//   - 验证 generic adapter 走完整 OAuth2 + PKCE + id_token 校验链路;
//   - 验证 LoginHandler 303 跳出 + state Put,CallbackHandler 取 state + 换 token + EnsureUser + IssueCredential。
//
// 不走真 dex(那是后续 e2e);此处用 RSA RS256 自签 id_token,coreos/go-oidc 经 JWKS 校验。

// ---------- mock OIDC server ----------

type mockOIDC struct {
	srv    *httptest.Server
	priv   *rsa.PrivateKey
	codes  map[string]mockAuthSession // code → session(用于 token 端点对账)
	tokens map[string]string          // access_token → subject(用于 userinfo)
	email  string                     // userinfo 端点返回的 email
	name   string                     // userinfo 端点返回的 name
}

type mockAuthSession struct {
	clientID      string
	codeChallenge string
	subject       string
	email         string
	name          string
}

func newMockOIDC(t *testing.T) *mockOIDC {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA: %v", err)
	}
	m := &mockOIDC{
		priv:   priv,
		codes:  make(map[string]mockAuthSession),
		tokens: make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.discovery)
	mux.HandleFunc("/keys", m.jwks)
	mux.HandleFunc("/token", m.token)
	mux.HandleFunc("/userinfo", m.userinfo)
	// /authorize 不被服务端直接 GET(浏览器跳)— 测试里我们直接拿 code,跳过浏览器
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockOIDC) URL() string { return m.srv.URL }
func (m *mockOIDC) Close()      { m.srv.Close() }

func (m *mockOIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	d := map[string]any{
		"issuer":                                m.srv.URL,
		"authorization_endpoint":                m.srv.URL + "/authorize",
		"token_endpoint":                        m.srv.URL + "/token",
		"userinfo_endpoint":                     m.srv.URL + "/userinfo",
		"jwks_uri":                              m.srv.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"code"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d)
}

func (m *mockOIDC) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := &m.priv.PublicKey
	jwk := map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"kid": "k1",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   "AQAB", // 65537
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
}

// issueCode 是测试 helper:跳过 /authorize 浏览器跳转,直接造一条 code session。
func (m *mockOIDC) issueCode(clientID, codeChallenge, subject, email, name string) string {
	code := fmt.Sprintf("code-%s", subject)
	m.codes[code] = mockAuthSession{clientID: clientID, codeChallenge: codeChallenge, subject: subject, email: email, name: name}
	return code
}

func (m *mockOIDC) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	sess, ok := m.codes[code]
	if !ok {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	delete(m.codes, code) // 一次性
	// 校 PKCE:S256(verifier) 应等于 challenge
	if codeChallengeS256(verifier) != sess.codeChallenge {
		http.Error(w, "invalid_grant: pkce", http.StatusBadRequest)
		return
	}
	// 签 id_token
	now := time.Now()
	idToken, err := signJWT(m.priv, "k1", map[string]any{
		"iss":   m.srv.URL,
		"sub":   sess.subject,
		"aud":   sess.clientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"email": sess.email,
		"name":  sess.name,
	})
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}
	access := "acc-" + sess.subject
	m.tokens[access] = sess.subject
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (m *mockOIDC) userinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "no token", http.StatusUnauthorized)
		return
	}
	sub, ok := m.tokens[strings.TrimPrefix(auth, "Bearer ")]
	if !ok {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":   sub,
		"email": m.email,
		"name":  m.name,
	})
}

// signJWT 手工 RS256 签名(避免引 go-jose 显式依赖,JWT 结构简单)。
func signJWT(priv *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	si := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	h := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return si + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ---------- mock IdP/Identity svc ----------

type stubIDPSvc struct {
	cfg    *idp.Config
	secret []byte
	err    error
}

func (s *stubIDPSvc) Get(_ context.Context, _, _ string) (*idp.Config, error) {
	return s.cfg, s.err
}

func (s *stubIDPSvc) GetClientSecret(_ context.Context, _, _ string) ([]byte, error) {
	// 返回拷贝(handler 会 zeroize,不希望影响后续测)
	cp := make([]byte, len(s.secret))
	copy(cp, s.secret)
	return cp, nil
}

type stubIdentity struct {
	users   map[string]identity.User // external_id → User
	lastJTI string
}

func (s *stubIdentity) EnsureUserByExternalID(_ context.Context, tenantID, idpID, externalID, email string) (identity.User, error) {
	// key 含 idpID,模拟多 IdP 同 external_id 分桶(Slice37b-1)
	key := idpID + ":" + externalID
	u, ok := s.users[key]
	if !ok {
		u = identity.User{ID: "u-" + externalID, TenantID: tenantID, ExternalID: externalID, Email: email, Status: "active"}
		s.users[key] = u
	}
	return u, nil
}

func (s *stubIdentity) IssueCredential(_ context.Context, tenantID, userID string, _ []string, _ string, _ time.Duration) (string, string, error) {
	jti := "jti-" + userID
	s.lastJTI = jti
	return "tok-" + userID + "-" + tenantID, jti, nil
}

// ---------- 端到端测试 ----------

func TestOIDCLoginCallback(t *testing.T) {
	mock := newMockOIDC(t)
	defer mock.Close()
	mock.email = "alice@example.com"
	mock.name = "Alice"

	const (
		tid          = "t-test"
		cid          = "c-test"
		clientID     = "sase-test"
		clientSecret = "shhh"
	)
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: cid, TenantID: tid, Name: "M", Kind: "oidc", Endpoint: mock.URL(), ClientID: clientID, Status: "active"},
		secret: []byte(clientSecret),
	}
	stubID := &stubIdentity{users: make(map[string]identity.User)}
	stateStore := NewInMemoryStateStore()
	defer stateStore.Stop()

	deps := &HandlerDeps{
		IDPSvc:      stubIDP,
		Identity:    stubID,
		StateStore:  stateStore,
		Factory:     GenericFactory,
		CallbackURL: "http://localhost/api/v1/idp/callback",
		SessionTTL:  10 * time.Minute,
	}

	// ① /login?tenant_id=&idp_id=:303 跳 IdP,state 已落 store
	loginReq := httptest.NewRequest(http.MethodGet, "/api/v1/idp/login?tenant_id="+tid+"&idp_id="+cid, nil)
	loginRec := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusSeeOther {
		t.Fatalf("/login 期望 303,得 %d body=%s", loginRec.Code, loginRec.Body.String())
	}
	loc := loginRec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("解析 Location: %v", err)
	}
	if !strings.HasPrefix(loc, mock.URL()+"/authorize") {
		t.Fatalf("Location 应指向 IdP/authorize:%s", loc)
	}
	stateID := u.Query().Get("state")
	codeChallenge := u.Query().Get("code_challenge")
	if stateID == "" || codeChallenge == "" {
		t.Fatalf("authorize URL 缺 state/code_challenge:%v", u.Query())
	}
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method 期望 S256")
	}
	if u.Query().Get("client_id") != clientID || u.Query().Get("redirect_uri") != deps.CallbackURL {
		t.Fatalf("authorize URL 字段错:%v", u.Query())
	}

	// ② mock IdP 签发 code(模拟用户在 IdP 端通过认证)
	code := mock.issueCode(clientID, codeChallenge, "alice-sub", "alice@example.com", "Alice")

	// ③ /callback?code=&state=:换 token + EnsureUser + IssueCredential
	cbReq := httptest.NewRequest(http.MethodGet, "/api/v1/idp/callback?code="+code+"&state="+stateID, nil)
	cbRec := httptest.NewRecorder()
	CallbackHandler(deps).ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusOK {
		t.Fatalf("/callback 期望 200,得 %d body=%s", cbRec.Code, cbRec.Body.String())
	}
	var resp CallbackResponse
	if err := json.Unmarshal(cbRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析回调响应: %v body=%s", err, cbRec.Body.String())
	}
	if resp.Token == "" || resp.JTI == "" || resp.UserID == "" {
		t.Fatalf("回调响应缺字段: %+v", resp)
	}
	if resp.UserID != "u-alice-sub" {
		t.Fatalf("UserID 期望 u-alice-sub,得 %s", resp.UserID)
	}
	// EnsureUser 已建用户(stub 内,key=idpID:externalID,Slice37b-1)
	if _, ok := stubID.users[cid+":alice-sub"]; !ok {
		t.Fatal("EnsureUserByExternalID 未被调")
	}
}

// TestStateOnce:同一 state 被回调消费后,再次回调应被拒(防 IdP 回调被截获 + 重放)。
func TestStateOnce(t *testing.T) {
	mock := newMockOIDC(t)
	defer mock.Close()
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: "c", TenantID: "t", Kind: "oidc", Endpoint: mock.URL(), ClientID: "cid", Status: "active"},
		secret: []byte("s"),
	}
	stubID := &stubIdentity{users: make(map[string]identity.User)}
	stateStore := NewInMemoryStateStore()
	defer stateStore.Stop()
	deps := &HandlerDeps{IDPSvc: stubIDP, Identity: stubID, StateStore: stateStore, Factory: GenericFactory, CallbackURL: "http://cb"}

	// 走完一次登录拿到 state
	r := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/v1/idp/login?tenant_id=t&idp_id=c", nil))
	loc := r.Header().Get("Location")
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")
	challenge := u.Query().Get("code_challenge")
	code := mock.issueCode("cid", challenge, "sub1", "", "")

	// 第一次回调成功
	r1 := httptest.NewRecorder()
	CallbackHandler(deps).ServeHTTP(r1, httptest.NewRequest(http.MethodGet, "/api/v1/idp/callback?code="+code+"&state="+state, nil))
	if r1.Code != http.StatusOK {
		t.Fatalf("首次回调期望 200,得 %d", r1.Code)
	}

	// 第二次相同 state 必须拒(state 已被 TakeOnce 删)
	r2 := httptest.NewRecorder()
	CallbackHandler(deps).ServeHTTP(r2, httptest.NewRequest(http.MethodGet, "/api/v1/idp/callback?code="+code+"&state="+state, nil))
	if r2.Code != http.StatusBadRequest {
		t.Fatalf("二次回调期望 400,得 %d body=%s", r2.Code, r2.Body.String())
	}
}

// TestIdPDisabled:IdP status=disabled 时 /login 返 403(避签发任何认证流程)。
func TestIdPDisabled(t *testing.T) {
	mock := newMockOIDC(t)
	defer mock.Close()
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: "c", TenantID: "t", Endpoint: mock.URL(), ClientID: "cid", Status: "disabled"},
		secret: []byte("s"),
	}
	deps := &HandlerDeps{IDPSvc: stubIDP, Identity: &stubIdentity{users: make(map[string]identity.User)}, StateStore: NewInMemoryStateStore(), Factory: GenericFactory, CallbackURL: "http://cb"}
	r := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/v1/idp/login?tenant_id=t&idp_id=c", nil))
	if r.Code != http.StatusForbidden {
		t.Fatalf("disabled IdP 期望 403,得 %d", r.Code)
	}
}

// TestMissingParams:缺 query 参数立即 400(不消耗后续依赖)。
func TestMissingParams(t *testing.T) {
	deps := &HandlerDeps{IDPSvc: &stubIDPSvc{}, Identity: &stubIdentity{}, StateStore: NewInMemoryStateStore(), Factory: GenericFactory, CallbackURL: "http://cb"}
	r := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/v1/idp/login", nil))
	if r.Code != http.StatusBadRequest {
		t.Fatalf("缺 query 期望 400,得 %d", r.Code)
	}
}

// TestIDTokenForgeRejected:若把 id_token 改成自签(IdP key 之外),adapter 必须拒(go-oidc verifier 校 JWKS)。
// 通过另起一个 mock(不同 RSA 私钥)证明跨 IdP 签发的 token 被拒。
func TestIDTokenForgeRejected(t *testing.T) {
	// genuine IdP
	genuine := newMockOIDC(t)
	defer genuine.Close()
	// forger:不同 RSA 私钥(jwks 不一致),但 issuer URL 仍是 genuine.URL()
	forger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("forge key: %v", err)
	}
	// 用 forger 私钥签 id_token,放进 genuine token 端点的响应?这要拦截 token endpoint。
	// 简化路线:直接让 verifier.Verify 校 forger 签的 id_token(走 adapter.Exchange 内的 verifier),
	// 应失败。这等价于 IdP 被中间人篡改 id_token 但 JWKS 不同的场景。
	adapter, err := NewGeneric(context.Background(), GenericConfig{
		IssuerURL: genuine.URL(), ClientID: "cid", ClientSecret: "s",
	})
	if err != nil {
		t.Fatalf("NewGeneric: %v", err)
	}
	// 注入 forger 签的 id_token 到 token 端点:覆盖 codes 后篡改私钥
	// 简化:直接调 adapter.(*genericAdapter).verifier.Verify(forgeToken) 应失败
	a := adapter.(*genericAdapter)
	forgeTok, err := signJWT(forger, "k1", map[string]any{
		"iss": genuine.URL(), "sub": "x", "aud": "cid", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("forge sign: %v", err)
	}
	if _, err := a.verifier.Verify(context.Background(), forgeTok); err == nil {
		t.Fatal("forger 签的 id_token 应被 JWKS 校验拒,但通过了")
	}
}

// ---------- 评审修复测试(H1/H3) ----------

// stubAudit 是测 audit hook 的 in-memory recorder。
type stubAudit struct {
	entries []audit.Entry
}

func (s *stubAudit) Record(_ context.Context, e audit.Entry) error {
	s.entries = append(s.entries, e)
	return nil
}

// TestUserDisabledRejected:H1 修复——IdP 认证通过的用户若被管理员手动 disabled,
// CallbackHandler 必须 403,不签发会话凭证(治理与登录路径对齐)。
func TestUserDisabledRejected(t *testing.T) {
	mock := newMockOIDC(t)
	defer mock.Close()
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: "c", TenantID: "t", Endpoint: mock.URL(), ClientID: "cid", Status: "active"},
		secret: []byte("s"),
	}
	// 预置一个 disabled 用户(EnsureUser 会找到这条,不重建;key=idpID:externalID,Slice37b-1)
	stubID := &stubIdentity{users: map[string]identity.User{
		"c:sub-disabled": {ID: "u-existing", TenantID: "t", ExternalID: "sub-disabled", Email: "x@x.com", Status: "disabled"},
	}}
	auditSvc := &stubAudit{}
	stateStore := NewInMemoryStateStore()
	defer stateStore.Stop()
	deps := &HandlerDeps{IDPSvc: stubIDP, Identity: stubID, StateStore: stateStore, Audit: auditSvc, Factory: GenericFactory, CallbackURL: "http://cb"}

	// 走完 login 拿 state + challenge
	r := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/v1/idp/login?tenant_id=t&idp_id=c", nil))
	loc := r.Header().Get("Location")
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")
	challenge := u.Query().Get("code_challenge")
	code := mock.issueCode("cid", challenge, "sub-disabled", "", "")

	// 回调 → 403(用户 disabled)+ 不应有会话凭证
	cb := httptest.NewRecorder()
	CallbackHandler(deps).ServeHTTP(cb, httptest.NewRequest(http.MethodGet, "/api/v1/idp/callback?code="+code+"&state="+state, nil))
	if cb.Code != http.StatusForbidden {
		t.Fatalf("disabled 用户期望 403,得 %d body=%s", cb.Code, cb.Body.String())
	}
	if stubID.lastJTI != "" {
		t.Fatal("disabled 用户不应签发凭证")
	}
	// H3:失败也写审计(OIDC_LOGIN_FAIL + reason=user disabled)
	foundDisabledAudit := false
	for _, e := range auditSvc.entries {
		if e.Action == "OIDC_LOGIN_FAIL" && strings.Contains(e.Detail, "user disabled") && e.Result == http.StatusForbidden {
			foundDisabledAudit = true
			break
		}
	}
	if !foundDisabledAudit {
		t.Fatalf("disabled 失败应有审计记录,得 %+v", auditSvc.entries)
	}
}

// TestAuditOnSuccess:H3 修复——回调成功也写审计(OIDC_LOGIN + result=200,detail 含 jti 但绝不含 token)。
func TestAuditOnSuccess(t *testing.T) {
	mock := newMockOIDC(t)
	defer mock.Close()
	stubIDP := &stubIDPSvc{
		cfg:    &idp.Config{ID: "c", TenantID: "t", Endpoint: mock.URL(), ClientID: "cid", Status: "active"},
		secret: []byte("s"),
	}
	stubID := &stubIdentity{users: make(map[string]identity.User)}
	auditSvc := &stubAudit{}
	stateStore := NewInMemoryStateStore()
	defer stateStore.Stop()
	deps := &HandlerDeps{IDPSvc: stubIDP, Identity: stubID, StateStore: stateStore, Audit: auditSvc, Factory: GenericFactory, CallbackURL: "http://cb"}

	r := httptest.NewRecorder()
	LoginHandler(deps).ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/v1/idp/login?tenant_id=t&idp_id=c", nil))
	u, _ := url.Parse(r.Header().Get("Location"))
	state := u.Query().Get("state")
	challenge := u.Query().Get("code_challenge")
	code := mock.issueCode("cid", challenge, "sub-ok", "", "")

	cb := httptest.NewRecorder()
	CallbackHandler(deps).ServeHTTP(cb, httptest.NewRequest(http.MethodGet, "/api/v1/idp/callback?code="+code+"&state="+state, nil))
	if cb.Code != http.StatusOK {
		t.Fatalf("回调期望 200,得 %d body=%s", cb.Code, cb.Body.String())
	}
	var got CallbackResponse
	_ = json.Unmarshal(cb.Body.Bytes(), &got)
	if got.Token == "" {
		t.Fatal("回调响应缺 token")
	}
	// 成功审计
	var sawSuccess bool
	for _, e := range auditSvc.entries {
		if e.Action == "OIDC_LOGIN" && e.Result == http.StatusOK {
			sawSuccess = true
			if strings.Contains(e.Detail, got.Token) {
				t.Fatal("审计 detail 不应含 token(防泄漏,同 Slice33e 口径)")
			}
			if !strings.Contains(e.Detail, "jti="+got.JTI) {
				t.Errorf("审计 detail 应含 jti=%s,得 %s", got.JTI, e.Detail)
			}
		}
	}
	if !sawSuccess {
		t.Fatalf("成功登录应有 OIDC_LOGIN 审计,得 %+v", auditSvc.entries)
	}
}
