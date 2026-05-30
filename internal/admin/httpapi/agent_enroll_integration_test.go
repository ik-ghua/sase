package httpapi_test

// Slice80 真 OS 级 ZTNA Agent per-user 入网端点 /api/v1/agent/enroll 端到端(经真实 Admin HTTP 栈:
// csrf + authz + 真 services + 真 enroll CA + 真 identity 签发器 + stub oidc.Adapter[IdP 链路由 oidc/agentenroll 自测]):
//   ① agentEnrollSvc=nil → 503(端点存在但未配置,守路由清单);
//   ② 公开 + CSRF skip:**无 Bearer、无 csrf_token cookie/X-CSRF-Token** 也能 POST → 200(引导态信任来自 IdP token);
//   ③ 成功响应:cert_pem(Org=tenant、CN=device、role:device)+ session_token(可验签,Subject=user.ID、Groups=IdP 组)
//      + user_id;**响应不含 client_secret/私钥**;
//   ④ device_enrollments 落 kind='agent' + user_id;
//   ⑤ IdP 认证失败 → 401;用户停用 → 403;参数缺失 → 400。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:migrations 0001-0025。

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/admin/httpapi"
	"github.com/ikuai8/sase/internal/agentenroll"
	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/fw"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/oidc"
	"github.com/ikuai8/sase/internal/platform"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

// ---- 本测 stub(IdP 真链路在 oidc/agentenroll 包自测;此处只验端点 wiring + 编排接通) ----

type aeStubIDP struct {
	cfg    *idp.Config
	getErr error
}

func (s aeStubIDP) Get(context.Context, string, string) (*idp.Config, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.cfg, nil
}
func (aeStubIDP) GetClientSecret(context.Context, string, string) ([]byte, error) {
	return []byte("dummy"), nil
}

type aeStubAdapter struct {
	info    oidc.UserInfo
	exchErr error
}

func (aeStubAdapter) AuthURL(context.Context, string, string, string) (string, error) {
	return "https://idp/authorize", nil
}
func (a aeStubAdapter) Exchange(context.Context, string, string, string) (oidc.UserInfo, error) {
	if a.exchErr != nil {
		return oidc.UserInfo{}, a.exchErr
	}
	return a.info, nil
}

// buildAgentEnrollTestSvc 装配真 identity(签发器)+ 真 enroll CA + stub IdP/adapter 的编排 Service。
func buildAgentEnrollTestSvc(t *testing.T, store data.Store, signer *cred.Signer, idpSvc agentenroll.IDPSvc, adapter oidc.Adapter) *agentenroll.Service {
	t.Helper()
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	identitySvc := identity.NewService(store, identity.WithSigner(signer))
	return agentenroll.New(agentenroll.Config{
		IDPSvc:  idpSvc,
		Ensurer: identitySvc,
		Issuer:  identitySvc,
		Enroll:  enroll.NewService(store, ca),
		Factory: func(context.Context, *idp.Config, []byte) (oidc.Adapter, error) { return adapter, nil },
	})
}

// registerWithAgentEnroll 装配 Admin 路由,agentEnrollSvc 由参数注入(nil 测 503)。
func registerWithAgentEnroll(t *testing.T, store data.Store, signer *cred.Signer, verifier *cred.Verifier, agentEnrollSvc *agentenroll.Service) *httptest.Server {
	t.Helper()
	identitySvc := identity.NewService(store, identity.WithSigner(signer))
	secSvc := testSecretSvc(t, store)
	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store),
		nil, nil, nil,
		testIDPSvc(t, store, secSvc),
		nil,            // oidc deps:本测不走 OIDC 浏览器登录
		agentEnrollSvc, // Slice80:Agent 入网编排(nil → 503)
		nil, verifier, nil, nil,
		nil,
	)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// postAgentEnroll 直接 POST /api/v1/agent/enroll(不带任何 Bearer / csrf 头,验公开 + CSRF skip)。
func postAgentEnroll(t *testing.T, baseURL string, body map[string]any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/agent/enroll", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求: %v", err)
	}
	return resp
}

func TestAgentEnrollEndpointEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 /agent/enroll 端到端测试")
	}
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

	tid := uuid.NewString()
	idpID := uuid.NewString()
	// 满足 users.idp_id FK
	if err := store.InTx(ctx, tid, func(q data.Queries) error {
		_, e := q.Exec(ctx,
			`INSERT INTO idp_configs (id, tenant_id, name, kind, endpoint, client_id, encrypted_client_secret, status)
			 VALUES ($1,$2,'t','oidc','https://idp','cid',$3,'active')`, idpID, tid, []byte("x"))
		return e
	}); err != nil {
		t.Fatalf("插 idp_configs: %v", err)
	}

	sub := "idp-sub-" + uuid.NewString()
	adapter := aeStubAdapter{info: oidc.UserInfo{Subject: sub, Email: "u@corp.example", Groups: []string{"eng"}}}
	idpStub := aeStubIDP{cfg: &idp.Config{Status: "active", Kind: "oidc"}}

	// ── ① nil → 503 ──
	srvNil := registerWithAgentEnroll(t, store, signer, verifier, nil)
	respNil := postAgentEnroll(t, srvNil.URL, map[string]any{"code": "c"})
	respNil.Body.Close()
	if respNil.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("agentEnrollSvc=nil 应 503,得 %d", respNil.StatusCode)
	}

	// ── ②③ 成功(无 Bearer/无 csrf 头 → CSRF skip + authz 白名单)──
	svc := buildAgentEnrollTestSvc(t, store, signer, idpStub, adapter)
	srv := registerWithAgentEnroll(t, store, signer, verifier, svc)

	deviceID := "agent-dev-" + uuid.NewString()
	csrPEM, _, _ := devpki.GenerateCSR(deviceID)
	resp := postAgentEnroll(t, srv.URL, map[string]any{
		"code": "c", "code_verifier": "v", "redirect_uri": "http://127.0.0.1:1/cb",
		"tenant_id": tid, "idp_id": idpID, "device_id": deviceID, "csr_pem": string(csrPEM), "posture": "compliant",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("成功入网应 200(公开 + CSRF skip),得 %d", resp.StatusCode)
	}
	var out struct {
		CertPEM      string `json:"cert_pem"`
		SessionToken string `json:"session_token"`
		SessionJTI   string `json:"session_jti"`
		ExpiresIn    int    `json:"expires_in"`
		UserID       string `json:"user_id"`
		// 安全:绝不应出现的字段(若 handler 误塞会被这里捕获)
		ClientSecret string `json:"client_secret"`
		Key          string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("解析响应: %v", err)
	}
	if out.CertPEM == "" || out.SessionToken == "" || out.UserID == "" {
		t.Fatalf("响应应含 cert_pem/session_token/user_id,得 %+v", out)
	}
	if out.ClientSecret != "" || out.Key != "" {
		t.Fatal("响应绝不应含 client_secret/私钥")
	}
	// cert:Org=tenant、CN=device、role:device
	blk, _ := pem.Decode([]byte(out.CertPEM))
	cert, perr := x509.ParseCertificate(blk.Bytes)
	if perr != nil {
		t.Fatalf("解析证书: %v", perr)
	}
	if got, _ := devpki.TenantFromCert(cert); got != tid {
		t.Fatalf("证书 Org 应=tenant,得 %q", got)
	}
	if cert.Subject.CommonName != deviceID {
		t.Fatalf("证书 CN 应=device,得 %q", cert.Subject.CommonName)
	}
	// cred:Subject=user.ID、Groups=IdP 组
	claims, verr := verifier.Verify(out.SessionToken, time.Now())
	if verr != nil {
		t.Fatalf("验签 session_token: %v", verr)
	}
	if claims.Subject != out.UserID {
		t.Fatalf("cred Subject 应=user_id %q,得 %q", out.UserID, claims.Subject)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "eng" {
		t.Fatalf("cred Groups 应=[eng],得 %v", claims.Groups)
	}
	// ④ device_enrollments 落 kind='agent' + user_id
	var gotKind, gotUID string
	if rerr := store.InTxRO(ctx, tid, func(q data.Queries) error {
		return q.QueryRow(ctx, `SELECT kind, COALESCE(user_id::text,'') FROM device_enrollments WHERE identity=$1`, deviceID).Scan(&gotKind, &gotUID)
	}); rerr != nil {
		t.Fatalf("查 device_enrollments: %v", rerr)
	}
	if gotKind != "agent" || gotUID != out.UserID {
		t.Fatalf("device_enrollments 应 kind=agent+user_id=%q,得 kind=%q user_id=%q", out.UserID, gotKind, gotUID)
	}

	// ── ⑤ 错误分流 ──
	// IdP 认证失败 → 401
	svcAuthFail := buildAgentEnrollTestSvc(t, store, signer, idpStub, aeStubAdapter{exchErr: errors.New("verify fail")})
	srvAF := registerWithAgentEnroll(t, store, signer, verifier, svcAuthFail)
	rAF := postAgentEnroll(t, srvAF.URL, map[string]any{
		"code": "c", "code_verifier": "v", "redirect_uri": "http://127.0.0.1:1/cb",
		"tenant_id": tid, "idp_id": idpID, "device_id": "d2", "csr_pem": string(csrPEM),
	})
	rAF.Body.Close()
	if rAF.StatusCode != http.StatusUnauthorized {
		t.Fatalf("IdP 认证失败应 401,得 %d", rAF.StatusCode)
	}
	// 参数缺失(缺 csr_pem)→ 400
	rBad := postAgentEnroll(t, srv.URL, map[string]any{
		"code": "c", "code_verifier": "v", "redirect_uri": "http://127.0.0.1:1/cb",
		"tenant_id": tid, "idp_id": idpID, "device_id": "d3",
	})
	rBad.Body.Close()
	if rBad.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺 csr_pem 应 400,得 %d", rBad.StatusCode)
	}
}
