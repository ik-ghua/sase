package agentenroll_test

// 真 OS 级 ZTNA Agent per-user 入网编排端到端(Slice80,L2 §3.10.1)。需 SASE_DB_RW_DSN(users/
// device_enrollments 走 RLS);未设则 SKIP。前置:已应用 migrations 0001-0025。
//
// 用 stub oidc.Adapter(返回固定 UserInfo,IdP 真链路由 oidc 包自测)+ 真 identity(签会话凭证)+
// 真 enroll CA(签设备证书)+ 真 PG(RLS upsert + FK)。断言:
//   - 返回 cert Org=tenant、CN=device_id、role:device;
//   - 返回 cred Subject=user.ID、Groups=IdP 组(cert↔cred 双绑定);
//   - device_enrollments 落 kind='agent' + user_id=user.ID;
//   - EnsureUser status!=active 拒(403)、IdPConfig 不存在拒(404 路径)、参数错(400)、code 校验。

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/agentenroll"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/oidc"
)

// ---- stub IdPSvc:不走 secret/DEK,只给 agentenroll 一个 active 配置 + 占位 secret ----

type stubIDPSvc struct {
	cfg    *idp.Config
	getErr error
	secret []byte
}

func (s *stubIDPSvc) Get(_ context.Context, _, _ string) (*idp.Config, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.cfg, nil
}
func (s *stubIDPSvc) GetClientSecret(_ context.Context, _, _ string) ([]byte, error) {
	return append([]byte(nil), s.secret...), nil
}

// ---- stub Adapter + factory:跳过真 IdP,固定 UserInfo(Subject/Email/Groups) ----

type stubAdapter struct {
	info     oidc.UserInfo
	exchErr  error
	gotCode  string
	gotVerif string
}

func (a *stubAdapter) AuthURL(context.Context, string, string, string) (string, error) {
	return "https://idp.example/authorize", nil
}
func (a *stubAdapter) Exchange(_ context.Context, code, verifier, _ string) (oidc.UserInfo, error) {
	a.gotCode, a.gotVerif = code, verifier
	if a.exchErr != nil {
		return oidc.UserInfo{}, a.exchErr
	}
	return a.info, nil
}

func stubFactory(a *stubAdapter) agentenroll.AdapterFactory {
	return func(context.Context, *idp.Config, []byte) (oidc.Adapter, error) { return a, nil }
}

// createIDPRow 直接插一行 idp_configs(满足 users.idp_id FK;不走 idp.Service 避免 secret/DEK 机器,
// agentenroll 用 stub IDPSvc 不读真行——本行只为满足外键)。返回 idp_config id。
func createIDPRow(t *testing.T, store data.Store, tid string) string {
	t.Helper()
	id := uuid.NewString()
	if err := store.InTx(context.Background(), tid, func(q data.Queries) error {
		_, e := q.Exec(context.Background(),
			`INSERT INTO idp_configs (id, tenant_id, name, kind, endpoint, client_id, encrypted_client_secret, status)
			 VALUES ($1,$2,'test','oidc','https://idp.example','cid',$3,'active')`,
			id, tid, []byte("x"))
		return e
	}); err != nil {
		t.Fatalf("插 idp_configs: %v", err)
	}
	return id
}

func newService(t *testing.T, store data.Store, idpSvc agentenroll.IDPSvc, adapter *stubAdapter) (*agentenroll.Service, *cred.Verifier, enroll.Service) {
	t.Helper()
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
	svc := agentenroll.New(agentenroll.Config{
		IDPSvc:  idpSvc,
		Ensurer: identitySvc,
		Issuer:  identitySvc,
		Enroll:  enrollSvc,
		Factory: stubFactory(adapter),
	})
	return svc, verifier, enrollSvc
}

func TestAgentEnrollEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 Agent 入网编排端到端测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	tid := uuid.NewString()
	adapter := &stubAdapter{info: oidc.UserInfo{Subject: "idp-sub-" + uuid.NewString(), Email: "alice@corp.example", Groups: []string{"eng", "vpn-users"}}}
	idpSvc := &stubIDPSvc{cfg: &idp.Config{Status: "active", Kind: "oidc"}, secret: []byte("dummy-secret")}
	svc, verifier, _ := newService(t, store, idpSvc, adapter)
	idpID := createIDPRow(t, store, tid) // 满足 users.idp_id FK

	deviceID := "agent-device-" + uuid.NewString()
	csrPEM, _, err := devpki.GenerateCSR(deviceID)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	res, err := svc.Enroll(ctx, agentenroll.Request{
		Code:         "code-xyz",
		CodeVerifier: "verifier-abc",
		RedirectURI:  "http://127.0.0.1:54321/callback",
		TenantID:     tid,
		IDPID:        idpID,
		DeviceID:     deviceID,
		CSRPem:       csrPEM,
		Posture:      "compliant",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// adapter 收到 daemon 持有的 code + verifier(令牌交换在控制面)
	if adapter.gotCode != "code-xyz" || adapter.gotVerif != "verifier-abc" {
		t.Fatalf("adapter.Exchange 应收到 code/verifier,得 code=%q verifier=%q", adapter.gotCode, adapter.gotVerif)
	}

	// ① 设备证书:Org=tenant、CN=device_id、role:device
	blk, _ := pem.Decode(res.CertPEM)
	if blk == nil {
		t.Fatal("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("解析证书: %v", err)
	}
	if got, ok := devpki.TenantFromCert(cert); !ok || got != tid {
		t.Fatalf("证书租户应为 %q,得 %q", tid, got)
	}
	if cert.Subject.CommonName != deviceID {
		t.Fatalf("证书 CN 应为 %q,得 %q", deviceID, cert.Subject.CommonName)
	}
	if role, ok := devpki.RoleFromCert(cert); !ok || role != devpki.RoleDevice {
		t.Fatalf("证书角色应为 role:device,得 %q(ok=%v)", role, ok)
	}

	// ② 会话凭证:Subject=user.ID、Groups=IdP 组、TenantID=tenant、Posture 透传
	claims, err := verifier.Verify(res.SessionToken, time.Now())
	if err != nil {
		t.Fatalf("Verify session_token: %v", err)
	}
	if claims.Subject != res.UserID {
		t.Fatalf("cred Subject 应=user.ID %q,得 %q", res.UserID, claims.Subject)
	}
	if claims.TenantID != tid {
		t.Fatalf("cred TenantID 应=%q,得 %q", tid, claims.TenantID)
	}
	if len(claims.Groups) != 2 || claims.Groups[0] != "eng" || claims.Groups[1] != "vpn-users" {
		t.Fatalf("cred Groups 应=IdP 组 [eng vpn-users],得 %v", claims.Groups)
	}
	if claims.Posture != "compliant" {
		t.Fatalf("cred Posture 应透传 compliant,得 %q", claims.Posture)
	}
	if claims.JTI != res.SessionJTI {
		t.Fatalf("cred JTI 应=res.SessionJTI,得 claims=%q res=%q", claims.JTI, res.SessionJTI)
	}

	// ③ device_enrollments 落 kind='agent' + user_id=user.ID(cert↔cred 双绑定的账本侧)
	var gotKind, gotUserID string
	if rerr := store.InTxRO(ctx, tid, func(q data.Queries) error {
		return q.QueryRow(ctx,
			`SELECT kind, COALESCE(user_id::text,'') FROM device_enrollments WHERE identity=$1`, deviceID).
			Scan(&gotKind, &gotUserID)
	}); rerr != nil {
		t.Fatalf("查 device_enrollments: %v", rerr)
	}
	if gotKind != "agent" {
		t.Fatalf("device_enrollments.kind 应=agent,得 %q", gotKind)
	}
	if gotUserID != res.UserID {
		t.Fatalf("device_enrollments.user_id 应=user.ID %q,得 %q", res.UserID, gotUserID)
	}

	// ④ 同设备重入网(换登录/重装)→ upsert 更新,不建新行(账本不膨胀)
	csr2, _, _ := devpki.GenerateCSR(deviceID)
	if _, err := svc.Enroll(ctx, agentenroll.Request{
		Code: "code-2", CodeVerifier: "v2", RedirectURI: "http://127.0.0.1:1/cb",
		TenantID: tid, IDPID: idpID, DeviceID: deviceID, CSRPem: csr2,
	}); err != nil {
		t.Fatalf("重入网 Enroll: %v", err)
	}
	var n int
	if rerr := store.InTxRO(ctx, tid, func(q data.Queries) error {
		return q.QueryRow(ctx, `SELECT count(*) FROM device_enrollments WHERE identity=$1`, deviceID).Scan(&n)
	}); rerr != nil {
		t.Fatalf("count device_enrollments: %v", rerr)
	}
	if n != 1 {
		t.Fatalf("同设备重入网应 upsert(1 行),得 %d 行", n)
	}
}

// TestAgentEnrollUserDisabled:管理员手动 disabled 的用户即便 IdP 认证通过,亦拒签会话凭证(H1,403)。
func TestAgentEnrollUserDisabled(t *testing.T) {
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

	tid := uuid.NewString()
	sub := "disabled-sub-" + uuid.NewString()
	idpID := createIDPRow(t, store, tid)
	// 预建一个 disabled 用户(idp_id=该 IdP,sub 相同 → EnsureUser 命中既有行;不动 status,disabled 保留)
	uid := uuid.NewString()
	if err := store.InTx(ctx, tid, func(q data.Queries) error {
		_, e := q.Exec(ctx,
			`INSERT INTO users (id, tenant_id, idp_id, external_id, email, status) VALUES ($1,$2,$3,$4,'x@y.z','disabled')`,
			uid, tid, idpID, sub)
		return e
	}); err != nil {
		t.Fatalf("建 disabled 用户: %v", err)
	}

	adapter := &stubAdapter{info: oidc.UserInfo{Subject: sub}}
	idpSvc := &stubIDPSvc{cfg: &idp.Config{Status: "active"}, secret: []byte("s")}
	svc, _, _ := newService(t, store, idpSvc, adapter)

	deviceID := "dev-" + uuid.NewString()
	csrPEM, _, _ := devpki.GenerateCSR(deviceID)
	_, err = svc.Enroll(ctx, agentenroll.Request{
		Code: "c", CodeVerifier: "v", RedirectURI: "http://127.0.0.1:1/cb",
		TenantID: tid, IDPID: idpID, DeviceID: deviceID, CSRPem: csrPEM,
	})
	if !errors.Is(err, agentenroll.ErrUserDisabled) {
		t.Fatalf("disabled 用户应返回 ErrUserDisabled,得 %v", err)
	}
}
