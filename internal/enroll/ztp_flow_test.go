package enroll_test

// ZTP 设备入网全链路:管理面预置 → 设备 FetchCert(本地 CSR + 取证书)→ 用所得租户绑定证书在
// require-cert-tenant(生产档)的 revtunnel 注册成功,且自报他租户被拒。串起 client.FetchCert +
// devpki.ClientTLSFromPEM + revtunnel W9 require 模式。需 SASE_DB_RW_DSN;未设则 SKIP。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/revtunnel"
)

func TestZTPDeviceFlow(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 ZTP 设备全链路测试")
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
	code, err := svc.CreateEnrollment(ctx, tid, enroll.KindConnector, "web")
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}

	// 管理面 /api/v1/enroll(server-TLS,等价 httpapi.redeemEnrollment)
	srvTLS, err := ca.ServerTLSServerOnly("localhost")
	if err != nil {
		t.Fatalf("ServerTLSServerOnly: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ActivationCode string `json:"activation_code"`
			CSRPEM         string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		certPEM, rerr := svc.Redeem(r.Context(), body.ActivationCode, []byte(body.CSRPEM))
		if rerr != nil {
			http.Error(w, "enrollment failed", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(certPEM)})
	})
	mgmt := httptest.NewUnstartedServer(mux)
	mgmt.TLS = srvTLS
	mgmt.StartTLS()
	defer mgmt.Close()

	// 设备侧:以预置 CA 验管理面服务端,FetchCert 本地生成 CSR 并取证书
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13},
	}}
	certPEM, keyPEM, err := enroll.FetchCert(ctx, mgmt.URL, hc, code, "web")
	if err != nil {
		t.Fatalf("FetchCert: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("ZTP 证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("解析 ZTP 证书: %v", err)
	}
	if got, ok := devpki.TenantFromCert(cert); !ok || got != tid {
		t.Fatalf("ZTP 证书租户应为 %q,得 %q(ok=%v)", tid, got, ok)
	}

	// PoP 反向通道(生产档:WithRequireCertTenant),设备用 ZTP 证书注册
	popTLS, err := ca.ServerTLS("xds-server")
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	reg := revtunnel.NewRegistry(revtunnel.WithRequireCertTenant())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = reg.Accept(rctx, tls.NewListener(lis, popTLS)) }()

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	ztpTLS := &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool, ServerName: "xds-server", MinVersion: tls.VersionTLS13}

	// 相符:Hello.Tenant=证书租户 → 注册成功
	go func() {
		_ = revtunnel.Serve(rctx, lis.Addr().String(), ztpTLS,
			revtunnel.Hello{Tenant: tid, App: "web"},
			func(_ revtunnel.Request) revtunnel.Response { return revtunnel.Response{Status: 200, Body: "ok"} })
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := reg.RoundTrip(tid, "web", revtunnel.Request{Method: "GET", Path: "/"}); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("ZTP 证书在 require 模式应注册成功,却 %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 不符:自报他租户 → 被拒(证书租户=tid)
	other := uuid.NewString()
	go func() {
		_ = revtunnel.Serve(rctx, lis.Addr().String(), ztpTLS,
			revtunnel.Hello{Tenant: other, App: "web"},
			func(_ revtunnel.Request) revtunnel.Response { return revtunnel.Response{Status: 200, Body: "ok"} })
	}()
	time.Sleep(600 * time.Millisecond)
	if _, err := reg.RoundTrip(other, "web", revtunnel.Request{Method: "GET", Path: "/"}); err != revtunnel.ErrNoConnector {
		t.Fatalf("自报他租户应被拒(期望 ErrNoConnector),却 err=%v", err)
	}
}
