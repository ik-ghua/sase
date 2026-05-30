package agentd

// Slice80 daemon 侧 per-user IdP 入网(idpEnroll)单测:用 fake SystemIntegration.OpenBrowser 模拟
// 浏览器+IdP redirect(从 authorize URL 取 redirect_uri/state,GET 回 daemon loopback 带 code+state),
// + httptest TLS 服务模拟管理面 /api/v1/agent/enroll(返回真 CA 签的 cert + 会话凭证)。
// 断言:idpEnroll 拿到 cert(可装载 CertRotator)+ session_token/jti;PKCE code_challenge 进了 authorize URL。
//
// 不连真 IdP(那是 oidc/agentenroll 包自测);此处只验 daemon 编排:loopback+PKCE+落盘+POST 接通。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/devpki"
)

// fakeBrowserSys 是模拟「壳拉起浏览器 + IdP 同意 + redirect 回 loopback」的 SystemIntegration。
// OpenBrowser 收到 authorize URL → 解析 redirect_uri/state → 异步 GET loopback?code=...&state=... 把 code 送回 daemon。
type fakeBrowserSys struct {
	code           string // 模拟 IdP 回的授权码
	gotChallenge   string // 捕获 authorize URL 里的 code_challenge(验 PKCE 进了 URL)
	gotMethod      string // 捕获 code_challenge_method
	corruptedState bool   // true=回错 state(验 daemon 拒)
}

func (f *fakeBrowserSys) Notify(string, string) error { return nil }
func (f *fakeBrowserSys) Autostart(bool) error        { return nil }
func (f *fakeBrowserSys) OpenBrowser(authURL string) error {
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	q := u.Query()
	f.gotChallenge = q.Get("code_challenge")
	f.gotMethod = q.Get("code_challenge_method")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	if f.corruptedState {
		state = "wrong-state"
	}
	// 异步模拟 IdP redirect(daemon 此刻正阻塞等 loopback callback)。
	go func() {
		cb := redirectURI + "?code=" + url.QueryEscape(f.code) + "&state=" + url.QueryEscape(state)
		resp, gerr := http.Get(cb) //nolint:noctx // 测试模拟浏览器跳转
		if gerr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	return nil
}

// startFakeAgentEnrollServer 起一个 TLS httptest 服务,模拟管理面 /api/v1/agent/enroll:
// 收到 POST 后用 ca 给请求里的 csr_pem 签证,返回 {cert_pem, session_token, session_jti, user_id}。
// 返回 (enrollURL[host 改 localhost 以匹配 server 证书 SAN], CA cert PEM)。
func startFakeAgentEnrollServer(t *testing.T, ca *devpki.CA, tenant string) (string, []byte) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSRPem   string `json:"csr_pem"`
			DeviceID string `json:"device_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		certPEM, err := ca.SignCSR([]byte(body.CSRPem), tenant, body.DeviceID)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cert_pem":      string(certPEM),
			"session_token": "fake-session-token",
			"session_jti":   "fake-jti",
			"expires_in":    1800,
			"user_id":       "user-123",
		})
	})
	srv := httptest.NewUnstartedServer(mux)
	// server-only TLS(不要求客户端证书:/agent/enroll 是公开引导端点,daemon 用 ClientTLSServerOnly 连)。
	srvTLS, err := ca.ServerTLSServerOnly("localhost")
	if err != nil {
		t.Fatalf("ServerTLSServerOnly: %v", err)
	}
	srv.TLS = srvTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// httptest 给 https://127.0.0.1:port;改 host 为 localhost 以匹配 server 证书 SAN + daemon ServerName。
	u, _ := url.Parse(srv.URL)
	enrollURL := "https://localhost:" + u.Port() + "/api/v1/agent/enroll"
	return enrollURL, ca.CertPEM()
}

func writeCATo(t *testing.T, dir string, caPEM []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o600); err != nil {
		t.Fatalf("写 ca.crt: %v", err)
	}
}

func TestIDPEnrollHappyPath(t *testing.T) {
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	tenant := "tenant-abc"
	enrollURL, caPEM := startFakeAgentEnrollServer(t, ca, tenant)
	tlsDir := t.TempDir()
	writeCATo(t, tlsDir, caPEM)

	sys := &fakeBrowserSys{code: "code-from-idp"}
	d := New(Config{
		Tenant:          tenant,
		Identity:        "agent-device-1",
		EnrollMode:      EnrollModeIDP,
		IDPID:           "idp-1",
		AgentEnrollURL:  enrollURL,
		IDPAuthorizeURL: "https://idp.example/authorize?client_id=cid&scope=openid",
		ServerName:      "localhost",
		TLSDir:          tlsDir,
	}, &stubNetCapture{}, &fakeProbe{}, sys, fakeProber{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := d.idpEnroll(ctx)
	if err != nil {
		t.Fatalf("idpEnroll: %v", err)
	}
	if res.sessionTok != "fake-session-token" || res.sessionJTI != "fake-jti" {
		t.Fatalf("应拿到会话凭证,得 tok=%q jti=%q", res.sessionTok, res.sessionJTI)
	}
	if res.userID != "user-123" {
		t.Fatalf("应拿到 user_id,得 %q", res.userID)
	}
	if res.rotator == nil || res.tlsConf == nil {
		t.Fatal("应拿到 CertRotator + mTLS 配置(可进 runWithCert)")
	}
	// PKCE:authorize URL 应携 S256 code_challenge(daemon 持 verifier、只暴露 challenge)。
	if sys.gotChallenge == "" || sys.gotMethod != "S256" {
		t.Fatalf("authorize URL 应携 PKCE S256 challenge,得 challenge=%q method=%q", sys.gotChallenge, sys.gotMethod)
	}
	// 证书已落盘(0600)+ 私钥本地(永不离设备)。
	if _, serr := os.Stat(filepath.Join(tlsDir, "agent.crt")); serr != nil {
		t.Fatalf("证书应落盘 agent.crt: %v", serr)
	}
	if _, serr := os.Stat(filepath.Join(tlsDir, "agent.key")); serr != nil {
		t.Fatalf("私钥应落盘 agent.key(本地生成永不离设备): %v", serr)
	}
}

// TestIDPEnrollStateMismatchRejected 验 loopback 收到错误 state(CSRF)→ idpEnroll 失败(不交付 code)。
func TestIDPEnrollStateMismatchRejected(t *testing.T) {
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	enrollURL, caPEM := startFakeAgentEnrollServer(t, ca, "tenant-x")
	tlsDir := t.TempDir()
	writeCATo(t, tlsDir, caPEM)

	sys := &fakeBrowserSys{code: "c", corruptedState: true}
	d := New(Config{
		Tenant: "tenant-x", Identity: "dev-x", EnrollMode: EnrollModeIDP,
		IDPID: "idp-1", AgentEnrollURL: enrollURL,
		IDPAuthorizeURL: "https://idp.example/authorize?client_id=cid",
		ServerName:      "localhost", TLSDir: tlsDir,
	}, &stubNetCapture{}, &fakeProbe{}, sys, fakeProber{})

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, err = d.idpEnroll(ctx)
	if err == nil {
		t.Fatal("错误 state 应使 idpEnroll 失败(CSRF 防护)")
	}
	if !strings.Contains(err.Error(), "state") && !strings.Contains(err.Error(), "回调") {
		t.Fatalf("失败应与 state 校验相关,得 %v", err)
	}
}
