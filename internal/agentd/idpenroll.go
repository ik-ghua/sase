package agentd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/oidc"
)

// idpenroll 实现真 OS 级 ZTNA Agent 的 per-user IdP 入网(EnrollMode="idp",L2 §3.10.1)。
//
// 流程(daemon 侧,引导态无设备证书):
//  1. 本地生成 device key + CSR(devpki.GenerateCSR(deviceID);**私钥永不离设备**)。
//  2. 起 127.0.0.1:<ephemeral>/callback loopback listener(RFC8252 native-app loopback redirect)。
//  3. 生成 PKCE code_verifier(daemon 持有)+ 一次性随机 state(防 CSRF/注入)。
//  4. 壳 OpenBrowser(authorizeURL + redirect_uri=loopback + code_challenge=S256 + state)→ 用户 IdP 登录。
//  5. loopback 收 IdP 回的 code(校 state)。
//  6. 经引导 transport(devpki.ClientTLSServerOnly 预置 CA pin)POST /api/v1/agent/enroll
//     提交 {code, code_verifier, redirect_uri, tenant_id, idp_id, device_id, csr_pem, posture}
//     → **控制面持 client_secret 完成令牌交换**(client_secret 永不下发设备)。
//  7. 落盘签发证书(0600)+ 装载为 CertRotator(热轮换)→ 返回 (tlsConf, rotator, sessionTok, sessionJTI)。
//
// **client_secret 如何不下发**:daemon 只持 PKCE code_verifier(防 code 截获)+ 公开的 authorize URL;
// IdP token 交换(需 client_secret)在控制面 /agent/enroll 内执行(adapter.Exchange)。daemon 永不见 client_secret。

// idpEnrollResult 是 idpEnroll 的成功产物(daemon 据此进 runWithCert + 填运行态会话凭证)。
type idpEnrollResult struct {
	tlsConf    *tls.Config
	rotator    *enroll.CertRotator
	sessionTok string
	sessionJTI string
	userID     string
}

// agentEnrollResponse 镜像 /agent/enroll 的 JSON 响应(daemon 侧解析)。
type agentEnrollResponse struct {
	CertPEM      string `json:"cert_pem"`
	SessionToken string `json:"session_token"`
	SessionJTI   string `json:"session_jti"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       string `json:"user_id"`
}

// idpCallbackTimeout 是等待用户在浏览器完成 IdP 登录的上限(交互窗口;超时即降级重试整个入网)。
const idpCallbackTimeout = 3 * time.Minute

// idpEnroll 执行 per-user IdP 入网(见文件注释)。返回 result 或 err(失败由 daemon 进降级重试)。
// deviceID 为本地稳定设备身份(=证书 CN;cmd 给定本地随机 UUID,与私钥同源)。
func (d *Daemon) idpEnroll(ctx context.Context) (*idpEnrollResult, error) {
	if d.cfg.IDPID == "" {
		return nil, fmt.Errorf("agentd/idp: 未配 IDP_ID")
	}
	if d.cfg.AgentEnrollURL == "" {
		return nil, fmt.Errorf("agentd/idp: 未配 AGENT_ENROLL_URL")
	}
	if d.cfg.IDPAuthorizeURL == "" {
		return nil, fmt.Errorf("agentd/idp: 未配 IDP_AUTHORIZE_URL(IdP authorize 端点 + client_id + scope)")
	}
	deviceID := d.cfg.Identity
	if deviceID == "" {
		return nil, fmt.Errorf("agentd/idp: 未配 device id(Identity)")
	}

	// ① 本地生成 device key + CSR(私钥永不离设备)。
	csrPEM, keyPEM, err := devpki.GenerateCSR(deviceID)
	if err != nil {
		return nil, fmt.Errorf("agentd/idp 生成 CSR: %w", err)
	}

	// ② loopback listener(127.0.0.1:<ephemeral>;RFC8252 native-app loopback)。
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("agentd/idp loopback 监听: %w", err)
	}
	defer lis.Close()
	redirectURI := "http://" + lis.Addr().String() + "/callback"

	// ③ PKCE verifier(daemon 持有)+ 一次性 state。
	verifier, err := oidc.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("agentd/idp code_verifier: %w", err)
	}
	state, err := randToken()
	if err != nil {
		return nil, fmt.Errorf("agentd/idp state: %w", err)
	}

	// loopback handler:收 code(校 state),经 codeCh 送出。
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{
		Handler:           loopbackHandler(state, codeCh, errCh),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(lis) }()
	// 关停 loopback 用独立短 ctx(入网 ctx 此刻可能已取消/超时;关停须独立于它,故不派生 r ctx,同 OIDC handler 审计独立 ctx 模式)。
	defer func() { //nolint:contextcheck // 关停独立于入网 ctx
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	// ④ 拉起浏览器到 IdP authorize URL(壳 OpenBrowser;失败降级打印让用户手动打开)。
	authURL := buildAuthorizeURL(d.cfg.IDPAuthorizeURL, redirectURI, state, verifier)
	if d.sys != nil {
		if oerr := d.sys.OpenBrowser(authURL); oerr != nil {
			log.Printf("[agentd/idp] 自动拉起浏览器失败(请手动打开):%v", oerr)
		}
	}
	log.Printf("[agentd/idp] 请在浏览器完成 IdP 登录(loopback=%s)", redirectURI)

	// ⑤ 等 code(超时/ctx 取消即失败)。
	var code string
	select {
	case code = <-codeCh:
	case cberr := <-errCh:
		return nil, fmt.Errorf("agentd/idp 回调错误: %w", cberr)
	case <-time.After(idpCallbackTimeout):
		return nil, fmt.Errorf("agentd/idp 等待 IdP 登录超时(%s)", idpCallbackTimeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// ⑥ POST /agent/enroll(引导 transport=预置 CA pin,server-TLS;非 mTLS——引导态无设备证书)。
	bootTLS, err := devpki.ClientTLSServerOnly(d.cfg.TLSDir, d.cfg.ServerName)
	if err != nil {
		return nil, fmt.Errorf("agentd/idp 引导 TLS: %w", err)
	}
	var posture string
	if d.posture != nil {
		if f, ok := d.posture.Latest(); ok {
			posture = f.Summary()
		}
	}
	resp, err := postAgentEnroll(ctx, d.cfg.AgentEnrollURL, bootTLS, agentEnrollReq{
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  redirectURI,
		TenantID:     d.cfg.Tenant,
		IDPID:        d.cfg.IDPID,
		DeviceID:     deviceID,
		CSRPem:       string(csrPEM),
		Posture:      posture,
	})
	if err != nil {
		return nil, err
	}

	// ⑦ 落盘证书(0600)+ 装载 CertRotator(热轮换;私钥本地已有,不落 /agent/enroll)。
	if werr := writeAgentCert(d.cfg.TLSDir, []byte(resp.CertPEM), keyPEM); werr != nil {
		log.Printf("[agentd/idp] 证书落盘失败(不致命,内存仍可用):%v", werr)
	}
	rotator, err := enroll.NewCertRotator([]byte(resp.CertPEM), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("agentd/idp 装载证书: %w", err)
	}
	tlsConf, err := enroll.RotatingClientTLS(rotator, d.cfg.TLSDir, d.cfg.ServerName)
	if err != nil {
		return nil, fmt.Errorf("agentd/idp mTLS 配置: %w", err)
	}
	log.Printf("[agentd/idp] 入网成功 user=%s session_jti=%s(证书 Org=tenant、CN=device)", resp.UserID, resp.SessionJTI)
	return &idpEnrollResult{
		tlsConf:    tlsConf,
		rotator:    rotator,
		sessionTok: resp.SessionToken,
		sessionJTI: resp.SessionJTI,
		userID:     resp.UserID,
	}, nil
}

// loopbackHandler 处理 IdP 回调:校 state、提取 code、回浏览器一句友好提示、经 channel 送出 code。
func loopbackHandler(wantState string, codeCh chan<- string, errCh chan<- error) http.HandlerFunc {
	delivered := false
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			writeLoopbackPage(w, "登录失败,可关闭本页返回 Agent。")
			if !delivered {
				delivered = true
				errCh <- fmt.Errorf("IdP 返回 error=%s", sanitizeLoopback(e))
			}
			return
		}
		code := q.Get("code")
		state := q.Get("state")
		if code == "" || state == "" {
			writeLoopbackPage(w, "缺 code/state。")
			return
		}
		if state != wantState {
			// state 不匹配 = CSRF/注入,拒(不交付 code)。
			writeLoopbackPage(w, "state 校验失败(请重新发起登录)。")
			if !delivered {
				delivered = true
				errCh <- fmt.Errorf("state 不匹配(CSRF 防护)")
			}
			return
		}
		writeLoopbackPage(w, "登录成功,可关闭本页返回 Agent。")
		if !delivered {
			delivered = true
			codeCh <- code
		}
	}
}

func writeLoopbackPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<html><body><p>"+msg+"</p></body></html>")
}

// buildAuthorizeURL 把 daemon 的 loopback redirect_uri + PKCE challenge + state 拼到运营给定的 authorize URL
// (base 已含 IdP authorize 端点 + client_id + scope=openid 等公开参数;**不含 client_secret**)。
func buildAuthorizeURL(base, redirectURI, state, verifier string) string {
	u, err := url.Parse(base)
	if err != nil {
		// base 非法 → 退回原样附 query(daemon 会在 OpenBrowser/IdP 端失败,降级重试)
		return base
	}
	q := u.Query()
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("state", state)
	q.Set("code_challenge", oidc.CodeChallengeS256(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

type agentEnrollReq struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	TenantID     string `json:"tenant_id"`
	IDPID        string `json:"idp_id"`
	DeviceID     string `json:"device_id"`
	CSRPem       string `json:"csr_pem"`
	Posture      string `json:"posture"`
}

// postAgentEnroll 经引导 server-TLS(CA pin)POST /agent/enroll,解析会话凭证 + 证书。
func postAgentEnroll(ctx context.Context, enrollURL string, tlsConf *tls.Config, req agentEnrollReq) (*agentEnrollResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConf}}
	hresp, err := hc.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("agentd/idp POST /agent/enroll: %w", err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agentd/idp /agent/enroll 返回 %d(IdP 认证/用户状态/参数错)", hresp.StatusCode)
	}
	var out agentEnrollResponse
	if derr := json.NewDecoder(io.LimitReader(hresp.Body, 1<<20)).Decode(&out); derr != nil {
		return nil, fmt.Errorf("agentd/idp 解析 /agent/enroll 响应: %w", derr)
	}
	if out.CertPEM == "" || out.SessionToken == "" {
		return nil, fmt.Errorf("agentd/idp /agent/enroll 响应缺证书/会话凭证")
	}
	return &out, nil
}

// writeAgentCert 把 per-user 入网证书 + 本地私钥落盘(0600;私钥本就在设备生成,落盘便重启复用)。
func writeAgentCert(dir string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(filepath.Join(dir, "agent.crt"), certPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "agent.key"), keyPEM, 0o600)
}

// randToken 生成 256bit 随机 b64url(loopback state)。
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sanitizeLoopback 限 IdP error 参数到短打印 ASCII(回浏览器/log,防注入)。
func sanitizeLoopback(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}
