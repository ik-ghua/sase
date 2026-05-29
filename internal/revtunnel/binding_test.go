package revtunnel_test

// W9:revtunnel 注册的租户身份绑定。验证 PoP 侧 register 把"客户端自报的 Hello.Tenant"约束为
// "⊆ 连接 mTLS 证书所属租户"(ZTP 证书把 tenant 编进 Subject.Organization)。无需 DB,纯 mTLS 回环。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/revtunnel"
)

func echoOK(req revtunnel.Request) revtunnel.Response {
	return revtunnel.Response{Status: 200, Body: "ok:" + req.Path}
}

// ztpClientTLS 用 CA 给 (tenant, cn) 签一张 ZTP 客户端证书,返回携该证书的 client TLS 配置。
func ztpClientTLS(t *testing.T, ca *devpki.CA, tenant, cn, serverName string) *tls.Config {
	t.Helper()
	csrPEM, keyPEM, err := devpki.GenerateCSR(cn) // 私钥设备本地生成
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	certPEM, err := ca.SignCSR(csrPEM, tenant, cn)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
}

// waitRegistered 轮询 RoundTrip 直到注册生效或超时。
func waitRegistered(reg *revtunnel.Registry, tenant, app string) (revtunnel.Response, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := reg.RoundTrip(tenant, app, revtunnel.Request{Method: "GET", Path: "/p"})
		if err == nil || time.Now().After(deadline) {
			return resp, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRegisterTenantBinding(t *testing.T) {
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	srvTLS, err := ca.ServerTLS("xds-server") // mTLS:RequireAndVerifyClientCert
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}

	reg := revtunnel.NewRegistry()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLis := tls.NewListener(lis, srvTLS)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = reg.Accept(ctx, tlsLis) }()
	addr := lis.Addr().String()

	// 用例 1:ZTP 证书租户=A,Hello.Tenant=A(相符)→ 注册成功,可反向 RoundTrip。
	tlsA := ztpClientTLS(t, ca, "tenant-A", "web", "xds-server")
	go func() {
		_ = revtunnel.Serve(ctx, addr, tlsA, revtunnel.Hello{Tenant: "tenant-A", App: "web"}, echoOK)
	}()
	if resp, err := waitRegistered(reg, "tenant-A", "web"); err != nil {
		t.Fatalf("相符注册应成功,却 %v", err)
	} else if resp.Body != "ok:/p" {
		t.Fatalf("反向 RoundTrip 响应异常: %q", resp.Body)
	}

	// 用例 2:ZTP 证书租户=A,Hello.Tenant=B(不符)→ register 拒绝,B/web 始终无连接器。
	tlsMismatch := ztpClientTLS(t, ca, "tenant-A", "svc", "xds-server")
	go func() {
		_ = revtunnel.Serve(ctx, addr, tlsMismatch, revtunnel.Hello{Tenant: "tenant-B", App: "svc"}, echoOK)
	}()
	time.Sleep(600 * time.Millisecond) // 给足注册尝试时间;被拒后不应登记
	if _, err := reg.RoundTrip("tenant-B", "svc", revtunnel.Request{Method: "GET", Path: "/p"}); err != revtunnel.ErrNoConnector {
		t.Fatalf("自报租户与证书不符的注册应被拒(期望 ErrNoConnector),却 err=%v", err)
	}

	// 用例 3(向后兼容):dev 共享证书无租户标记(Organization 空)→ 不施加约束,正常注册。
	sharedTLS, err := ca.ClientTLS("xds-server")
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
	go func() {
		_ = revtunnel.Serve(ctx, addr, sharedTLS, revtunnel.Hello{Tenant: "tenant-X", App: "legacy"}, echoOK)
	}()
	if _, err := waitRegistered(reg, "tenant-X", "legacy"); err != nil {
		t.Fatalf("无租户标记的共享证书应不受约束、注册成功,却 %v", err)
	}
}

// TestRegisterRequireCertTenant 验证 fail-closed 模式(生产):无租户标记的证书一律被拒。
func TestRegisterRequireCertTenant(t *testing.T) {
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	srvTLS, err := ca.ServerTLS("xds-server")
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	reg := revtunnel.NewRegistry(revtunnel.WithRequireCertTenant())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = reg.Accept(ctx, tls.NewListener(lis, srvTLS)) }()
	addr := lis.Addr().String()

	// 共享证书(无租户)在 require 模式下应被拒:tenant-X/legacy 始终无连接器。
	sharedTLS, err := ca.ClientTLS("xds-server")
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
	go func() {
		_ = revtunnel.Serve(ctx, addr, sharedTLS, revtunnel.Hello{Tenant: "tenant-X", App: "legacy"}, echoOK)
	}()
	time.Sleep(600 * time.Millisecond)
	if _, err := reg.RoundTrip("tenant-X", "legacy", revtunnel.Request{Method: "GET", Path: "/p"}); err != revtunnel.ErrNoConnector {
		t.Fatalf("require 模式下无租户证书应被拒(期望 ErrNoConnector),却 err=%v", err)
	}

	// ZTP 证书(带租户)在 require 模式下正常注册。
	tlsA := ztpClientTLS(t, ca, "tenant-A", "web", "xds-server")
	go func() {
		_ = revtunnel.Serve(ctx, addr, tlsA, revtunnel.Hello{Tenant: "tenant-A", App: "web"}, echoOK)
	}()
	if _, err := waitRegistered(reg, "tenant-A", "web"); err != nil {
		t.Fatalf("require 模式下 ZTP 证书应注册成功,却 %v", err)
	}
}
