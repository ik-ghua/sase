package enroll_test

// ZTP 证书续期 + 设备撤销:enroll 得证书 A → 经设备 mTLS 端点(出示 A)续期得 B(同租户/身份、延期)
// → admin 撤销设备 → 再续期(出示 B)被拒。验 client.RenewCert + httpapi.RegisterDevice(从对端证书取身份)
// + service.Renew/RevokeDevice 续期闸。需 SASE_DB_RW_DSN;未设则 SKIP。前置:migrations 0001-0008。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/admin/httpapi"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/enroll"
)

func TestZTPRenewAndRevoke(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 ZTP 续期/撤销测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	svc := enroll.NewService(store, ca)
	tid := uuid.NewString()

	// 初始入网得证书 A
	code, err := svc.CreateEnrollment(ctx, tid, enroll.KindConnector, "web")
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}
	csrA, keyA, _ := devpki.GenerateCSR("web")
	certA, err := svc.Redeem(ctx, code, csrA)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	// 设备 mTLS 端点(RequireAndVerifyClientCert),挂真实 RegisterDevice
	srvTLS, err := ca.ServerTLS("localhost")
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	mux := http.NewServeMux()
	httpapi.RegisterDevice(mux, svc, nil) // nil 限流器=不限流(测试)
	dev := httptest.NewUnstartedServer(mux)
	dev.TLS = srvTLS
	dev.StartTLS()
	defer dev.Close()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	mtlsClient := func(certPEM, keyPEM []byte) *http.Client {
		cert, _ := tls.X509KeyPair(certPEM, keyPEM)
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13},
		}}
	}

	// 续期:出示证书 A → 得证书 B(密钥轮换)
	certB, keyB, err := enroll.RenewCert(ctx, dev.URL, mtlsClient(certA, keyA), "web")
	if err != nil {
		t.Fatalf("RenewCert: %v", err)
	}
	aLeaf := parseLeaf(t, certA)
	bLeaf := parseLeaf(t, certB)
	if got, _ := devpki.TenantFromCert(bLeaf); got != tid {
		t.Fatalf("续期证书租户应为 %q,得 %q", tid, got)
	}
	if bLeaf.Subject.CommonName != "web" {
		t.Fatalf("续期证书 CN 应为 web,得 %q", bLeaf.Subject.CommonName)
	}
	if bLeaf.NotAfter.Before(aLeaf.NotAfter) {
		t.Fatalf("续期证书到期 %v 不应早于原证书 %v", bLeaf.NotAfter, aLeaf.NotAfter)
	}

	// admin 撤销设备 → 出示证书 B 续期应被拒(续期闸)
	if err := svc.RevokeDevice(ctx, tid, "web"); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, _, err := enroll.RenewCert(ctx, dev.URL, mtlsClient(certB, keyB), "web"); err == nil {
		t.Fatal("设备撤销后续期应失败,却成功")
	}
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("解析证书: %v", err)
	}
	return cert
}
