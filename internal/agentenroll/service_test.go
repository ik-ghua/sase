package agentenroll_test

// 纯逻辑单测(无 DB):覆盖 agentenroll 编排的错误分流分支 —— IdPConfig 不存在/禁用、IdP 认证失败、
// 参数缺失、subject 空。用全 stub 依赖(不碰 PG/CA)。端到端正确性(cert/cred 双绑定)由 *_integration_test.go 覆盖。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/agentenroll"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/oidc"
)

// stub Ensurer / Issuer / Enroll(不碰 DB)。
type stubEnsurer struct {
	user identity.User
	err  error
}

func (s stubEnsurer) EnsureUserByExternalID(context.Context, string, string, string, string) (identity.User, error) {
	return s.user, s.err
}

type stubIssuer struct{}

func (stubIssuer) IssueCredential(context.Context, string, string, []string, string, time.Duration) (string, string, error) {
	return "tok", "jti", nil
}

type stubEnroll struct{ called bool }

func (s *stubEnroll) RedeemAgent(context.Context, string, string, string, []byte) ([]byte, error) {
	s.called = true
	return []byte("CERT"), nil
}

func newStubSvc(t *testing.T, idpSvc agentenroll.IDPSvc, adapter *stubAdapter, ens stubEnsurer, en *stubEnroll) *agentenroll.Service {
	t.Helper()
	return agentenroll.New(agentenroll.Config{
		IDPSvc:  idpSvc,
		Ensurer: ens,
		Issuer:  stubIssuer{},
		Enroll:  en,
		Factory: stubFactory(adapter),
	})
}

func validReq() agentenroll.Request {
	return agentenroll.Request{
		Code: "c", CodeVerifier: "v", RedirectURI: "http://127.0.0.1:1/cb",
		TenantID: "11111111-1111-1111-1111-111111111111", IDPID: "22222222-2222-2222-2222-222222222222",
		DeviceID: "dev-1", CSRPem: []byte("CSR"),
	}
}

func TestEnrollBadRequest(t *testing.T) {
	svc := newStubSvc(t, &stubIDPSvc{cfg: &idp.Config{Status: "active"}, secret: []byte("s")}, &stubAdapter{}, stubEnsurer{}, &stubEnroll{})
	cases := map[string]agentenroll.Request{
		"缺 code":          func() agentenroll.Request { r := validReq(); r.Code = ""; return r }(),
		"缺 code_verifier": func() agentenroll.Request { r := validReq(); r.CodeVerifier = ""; return r }(),
		"缺 redirect_uri":  func() agentenroll.Request { r := validReq(); r.RedirectURI = ""; return r }(),
		"缺 tenant_id":     func() agentenroll.Request { r := validReq(); r.TenantID = ""; return r }(),
		"缺 idp_id":        func() agentenroll.Request { r := validReq(); r.IDPID = ""; return r }(),
		"缺 device_id":     func() agentenroll.Request { r := validReq(); r.DeviceID = ""; return r }(),
		"缺 csr_pem":       func() agentenroll.Request { r := validReq(); r.CSRPem = nil; return r }(),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Enroll(context.Background(), req); !errors.Is(err, agentenroll.ErrBadRequest) {
				t.Fatalf("%s 应返回 ErrBadRequest,得 %v", name, err)
			}
		})
	}
}

func TestEnrollIDPConfigNotFound(t *testing.T) {
	svc := newStubSvc(t, &stubIDPSvc{getErr: idp.ErrNotFound}, &stubAdapter{}, stubEnsurer{}, &stubEnroll{})
	if _, err := svc.Enroll(context.Background(), validReq()); !errors.Is(err, agentenroll.ErrIDPConfig) {
		t.Fatalf("IdPConfig 不存在应返回 ErrIDPConfig,得 %v", err)
	}
}

func TestEnrollIDPConfigDisabled(t *testing.T) {
	svc := newStubSvc(t, &stubIDPSvc{cfg: &idp.Config{Status: "disabled"}, secret: []byte("s")}, &stubAdapter{}, stubEnsurer{}, &stubEnroll{})
	if _, err := svc.Enroll(context.Background(), validReq()); !errors.Is(err, agentenroll.ErrIDPConfig) {
		t.Fatalf("IdP 禁用应返回 ErrIDPConfig,得 %v", err)
	}
}

func TestEnrollIDPAuthFail(t *testing.T) {
	adapter := &stubAdapter{exchErr: errors.New("id_token verify failed")}
	en := &stubEnroll{}
	svc := newStubSvc(t, &stubIDPSvc{cfg: &idp.Config{Status: "active"}, secret: []byte("s")}, adapter, stubEnsurer{}, en)
	if _, err := svc.Enroll(context.Background(), validReq()); !errors.Is(err, agentenroll.ErrIDPAuth) {
		t.Fatalf("Exchange 失败应返回 ErrIDPAuth,得 %v", err)
	}
	if en.called {
		t.Fatal("Exchange 失败后不应继续签设备证书(应在 IdP 认证阶段短路)")
	}
}

func TestEnrollEmptySubjectRejected(t *testing.T) {
	adapter := &stubAdapter{info: oidc.UserInfo{Subject: ""}} // IdP 未返回 subject
	en := &stubEnroll{}
	svc := newStubSvc(t, &stubIDPSvc{cfg: &idp.Config{Status: "active"}, secret: []byte("s")}, adapter, stubEnsurer{}, en)
	if _, err := svc.Enroll(context.Background(), validReq()); !errors.Is(err, agentenroll.ErrIDPAuth) {
		t.Fatalf("空 subject 应返回 ErrIDPAuth,得 %v", err)
	}
	if en.called {
		t.Fatal("空 subject 不应继续签证书")
	}
}
