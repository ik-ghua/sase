package credrefresh_test

// 会话凭证静默刷新端到端(Slice81,L2 §3.6.1)。需 SASE_DB_RW_DSN(users/device_enrollments 走 RLS);
// 未设则 SKIP。前置:已应用 migrations 0001-0025。
//
// 拓扑(镜像 enroll/renew_integration_test):真 PG(RLS upsert + FK)+ 真 enroll CA(签设备证书)+ 真
// identity(签会话凭证)+ 真 credrefresh.Service + httpapi.RegisterDevice 挂在 RequireAndVerifyClientCert 的
// :8444 设备 mTLS httptest server。设备出示**租户绑定设备证书 + 当前会话 cred** 刷新。断言:
//   - 刷新成功:新 cred 过验签、Subject==user_id、exp 延后、**groups==验签 cred 的组(非 body)**;
//   - **停用 user(UPDATE users status=disabled)→ 刷新 403**;
//   - RevokeDevice → 刷新 403;
//   - **body 谎报 groups 被忽略**(新 cred 组==验签 cred 组,不受 body 影响)。

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/admin/httpapi"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/credrefresh"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/identity"
)

type refreshReq struct {
	CurrentCredToken string `json:"current_cred_token"`
	Posture          string `json:"posture"`
	Groups           []any  `json:"groups,omitempty"` // 谎报字段(本设计 body 无 groups;测试用于验被忽略)
}

type refreshResp struct {
	SessionToken string `json:"session_token"`
	SessionJTI   string `json:"session_jti"`
	ExpiresIn    int    `json:"expires_in"`
}

// doRefresh 经设备 mTLS POST /api/v1/agent/session/refresh,返回 (resp, statusCode)。
func doRefresh(t *testing.T, baseURL string, hc *http.Client, body refreshReq) (*refreshResp, int) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/api/v1/agent/session/refresh", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("刷新请求: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out refreshResp
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	return &out, resp.StatusCode
}

func TestAgentSessionRefreshEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过会话凭证刷新端到端测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	// 签发器/验证器(签当前 cred + 验新 cred)。
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	identitySvc := identity.NewService(store, identity.WithSigner(signer))

	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	enrollSvc := enroll.NewService(store, ca)

	tid := uuid.NewString()
	// 建用户(device_enrollments.user_id FK)。idp_id=NULL(手建路径)。
	uid := uuid.NewString()
	if ierr := store.InTx(ctx, tid, func(q data.Queries) error {
		_, e := q.Exec(ctx,
			`INSERT INTO users (id, tenant_id, external_id, email, status) VALUES ($1,$2,$3,'u@corp.example','active')`,
			uid, tid, "ext-"+uid)
		return e
	}); ierr != nil {
		t.Fatalf("建用户: %v", ierr)
	}

	// Agent 入网:RedeemAgent 写 user_id + 签设备证书(role:device,Org=tenant,CN=device-id)。
	deviceID := "agent-dev-" + uuid.NewString()
	csrPEM, keyPEM, err := devpki.GenerateCSR(deviceID)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	certPEM, err := enrollSvc.RedeemAgent(ctx, tid, deviceID, uid, csrPEM)
	if err != nil {
		t.Fatalf("RedeemAgent: %v", err)
	}

	// 当前会话 cred(Subject=uid,Groups=可信组)。
	credGroups := []string{"eng", "vpn-users"}
	curTok, curJTI, err := identitySvc.IssueCredential(ctx, tid, uid, credGroups, "compliant", 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}
	_ = curJTI

	// credrefresh 编排 + 设备 mTLS 端点(RequireAndVerifyClientCert,挂真实 RegisterDevice)。
	refreshSvc := credrefresh.New(credrefresh.Config{
		Verifier: verifier, Enroll: enrollSvc, Users: identitySvc, Issuer: identitySvc, RevChk: identitySvc,
	})
	srvTLS, err := ca.ServerTLS("localhost")
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	mux := http.NewServeMux()
	httpapi.RegisterDevice(mux, enrollSvc, nil, refreshSvc, nil) // nil 限流器=不限流(测试)
	dev := httptest.NewUnstartedServer(mux)
	dev.TLS = srvTLS
	dev.StartTLS()
	defer dev.Close()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	mtlsClient := func(cPEM, kPEM []byte) *http.Client {
		c, _ := tls.X509KeyPair(cPEM, kPEM)
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{c}, RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13},
		}}
	}
	client := mtlsClient(certPEM, keyPEM)

	// ① 刷新成功:设备 mTLS + 当前 cred → 新 cred 过验签 + Subject 一致 + exp 延后 + groups==验签 cred 组。
	//    body **谎报 groups**(高权限组)→ 应被忽略(新 cred 组==验签 cred 组 [eng vpn-users])。
	out, code := doRefresh(t, dev.URL, client, refreshReq{
		CurrentCredToken: curTok,
		Posture:          "still-compliant",
		Groups:           []any{"platform_admin", "superuser"}, // 谎报,必须被忽略
	})
	if code != http.StatusOK {
		t.Fatalf("刷新应 200,得 %d", code)
	}
	newClaims, verr := verifier.Verify(out.SessionToken, time.Now())
	if verr != nil {
		t.Fatalf("新 cred 应过验签: %v", verr)
	}
	if newClaims.Subject != uid {
		t.Fatalf("新 cred Subject 应=%q,得 %q", uid, newClaims.Subject)
	}
	// groups 必须==验签 cred 组(非 body 谎报)。
	if len(newClaims.Groups) != 2 || newClaims.Groups[0] != "eng" || newClaims.Groups[1] != "vpn-users" {
		t.Fatalf("新 cred groups 必须来自验签 cred [eng vpn-users](body 谎报应被忽略),得 %v", newClaims.Groups)
	}
	if newClaims.JTI == "" || newClaims.JTI == curJTI {
		t.Fatalf("新 cred 应有新 jti(≠旧 %q),得 %q", curJTI, newClaims.JTI)
	}
	if newClaims.Posture != "still-compliant" {
		t.Fatalf("新 cred posture 应透传 body,得 %q", newClaims.Posture)
	}

	// ② 停用 user → 刷新 403(自愈式注销生效,§3.6.1)。
	if uerr := store.InTx(ctx, tid, func(q data.Queries) error {
		_, e := q.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, uid)
		return e
	}); uerr != nil {
		t.Fatalf("停用 user: %v", uerr)
	}
	if _, code := doRefresh(t, dev.URL, client, refreshReq{CurrentCredToken: curTok}); code != http.StatusForbidden {
		t.Fatalf("停用 user 后刷新应 403,得 %d", code)
	}

	// 恢复 active,验 ③ 撤销设备路径独立(避免 ② 的 disabled 干扰)。
	if uerr := store.InTx(ctx, tid, func(q data.Queries) error {
		_, e := q.Exec(ctx, `UPDATE users SET status='active' WHERE id=$1`, uid)
		return e
	}); uerr != nil {
		t.Fatalf("恢复 user: %v", uerr)
	}
	// 先确认恢复后刷新又 200(证明 ② 是 user 状态门禁而非别的)。
	if _, code := doRefresh(t, dev.URL, client, refreshReq{CurrentCredToken: curTok}); code != http.StatusOK {
		t.Fatalf("恢复 user 后刷新应 200,得 %d", code)
	}

	// ③ RevokeDevice → 刷新 403(设备撤销门禁)。
	if rerr := enrollSvc.RevokeDevice(ctx, tid, deviceID); rerr != nil {
		t.Fatalf("RevokeDevice: %v", rerr)
	}
	if _, code := doRefresh(t, dev.URL, client, refreshReq{CurrentCredToken: curTok}); code != http.StatusForbidden {
		t.Fatalf("撤销设备后刷新应 403,得 %d", code)
	}
}

// TestAgentSessionRefreshSubjectMismatch:设备关联 userA,但出示 userB 的 cred → 401(主体不符,防凭证盗用)。
func TestAgentSessionRefreshSubjectMismatch(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	signer, _ := cred.GenerateSigner()
	verifier, _ := cred.NewVerifier(signer.Public())
	identitySvc := identity.NewService(store, identity.WithSigner(signer))
	ca, _ := devpki.NewCA()
	enrollSvc := enroll.NewService(store, ca)

	tid := uuid.NewString()
	userA := uuid.NewString()
	userB := uuid.NewString()
	if ierr := store.InTx(ctx, tid, func(q data.Queries) error {
		for i, u := range []string{userA, userB} {
			if _, e := q.Exec(ctx,
				`INSERT INTO users (id, tenant_id, external_id, email, status) VALUES ($1,$2,$3,'u@x','active')`,
				u, tid, "ext"+string(rune('a'+i))+u); e != nil {
				return e
			}
		}
		return nil
	}); ierr != nil {
		t.Fatalf("建用户: %v", ierr)
	}

	deviceID := "dev-" + uuid.NewString()
	csrPEM, keyPEM, _ := devpki.GenerateCSR(deviceID)
	certPEM, err := enrollSvc.RedeemAgent(ctx, tid, deviceID, userA, csrPEM) // 设备绑 userA
	if err != nil {
		t.Fatalf("RedeemAgent: %v", err)
	}
	// 出示 userB 的 cred(与设备绑定 userA 不符)。
	credB, _, err := identitySvc.IssueCredential(ctx, tid, userB, nil, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}

	refreshSvc := credrefresh.New(credrefresh.Config{Verifier: verifier, Enroll: enrollSvc, Users: identitySvc, Issuer: identitySvc, RevChk: identitySvc})
	srvTLS, _ := ca.ServerTLS("localhost")
	mux := http.NewServeMux()
	httpapi.RegisterDevice(mux, enrollSvc, nil, refreshSvc, nil)
	dev := httptest.NewUnstartedServer(mux)
	dev.TLS = srvTLS
	dev.StartTLS()
	defer dev.Close()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	c, _ := tls.X509KeyPair(certPEM, keyPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{c}, RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13},
	}}

	if _, code := doRefresh(t, dev.URL, client, refreshReq{CurrentCredToken: credB}); code != http.StatusUnauthorized {
		t.Fatalf("主体不符应 401,得 %d", code)
	}
}
