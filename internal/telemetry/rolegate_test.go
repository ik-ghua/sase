package telemetry

// W11 角色门控测试:遥测 Ingest 在 require-pop-role 下,只接受 PoP 角色证书的调用方,拒设备角色(防边缘冒充)。
// authorizeReport 纯函数单测 + mTLS 回环端到端(role:pop 通过 / role:device 拒)。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	telemetrypb "github.com/ikuai8/sase/api/proto/sase/telemetry/v1"
	"github.com/ikuai8/sase/internal/devpki"
)

func TestAuthorizeReport(t *testing.T) {
	// 关闭门控:任何角色(含无角色)放行
	if err := authorizeReport(false, "", false); err != nil {
		t.Fatalf("门控关闭应放行: %v", err)
	}
	// 开启门控:PoP 角色放行;设备/无角色拒
	if err := authorizeReport(true, devpki.RolePoP, true); err != nil {
		t.Fatalf("PoP 角色应放行: %v", err)
	}
	for _, c := range []struct {
		role string
		has  bool
	}{{devpki.RoleDevice, true}, {"", false}, {"admin", true}} {
		if err := authorizeReport(true, c.role, c.has); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("role=%q has=%v 应被拒(PermissionDenied),得 %v", c.role, c.has, err)
		}
	}
}

// clientTLSWithCert 用给定证书/密钥 + CA 池构造 mTLS 客户端配置。
func clientTLSWithCert(t *testing.T, ca *devpki.CA, certPEM, keyPEM []byte) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
}

// 端到端 mTLS:require-pop-role 下,PoP 角色证书 Report 成功,设备角色证书被拒。
func TestIngestRoleGateMTLS(t *testing.T) {
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	srvTLS, err := ca.ServerTLS("localhost") // mTLS,RequireAndVerifyClientCert
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
	telemetrypb.RegisterTelemetryServer(gs, NewIngest(true, SinkFunc(func(Event) {}))) // require-pop-role 开
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	// PoP 角色证书 → 放行
	popCSR, popKey, _ := devpki.GenerateCSR("pop-1")
	popCert, _ := ca.SignPoP(popCSR, "pop-1")
	if err := report(t, lis.Addr().String(), clientTLSWithCert(t, ca, popCert, popKey)); err != nil {
		t.Fatalf("PoP 角色应放行,却 %v", err)
	}

	// 设备角色证书(同 CA,role:device)→ 拒
	devCSR, devKey, _ := devpki.GenerateCSR("web")
	devCert, _ := ca.SignCSR(devCSR, "t1", "web") // role:device
	if err := report(t, lis.Addr().String(), clientTLSWithCert(t, ca, devCert, devKey)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("设备角色应被拒(PermissionDenied),却 %v", err)
	}
}

// 端到端 W11 启用:WritePEM 产出的 PoP 角色证书(pop.crt)经 LoadPoPClientTLS 加载 → 门控放行;
// 共享 client.crt(role-less)→ 被拒。证明 PoP 角色证书签发 → 加载 → 门控 整条链路打通。
func TestRoleGateWithProvisionedCerts(t *testing.T) {
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	dir := t.TempDir()
	if err := ca.WritePEM(dir, func(name string, b []byte) error { return os.WriteFile(name, b, 0o600) }); err != nil {
		t.Fatalf("WritePEM: %v", err)
	}
	srvTLS, _ := ca.ServerTLS("localhost")
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
	telemetrypb.RegisterTelemetryServer(gs, NewIngest(true, SinkFunc(func(Event) {})))
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	popTLS, err := devpki.LoadPoPClientTLS(dir, "localhost")
	if err != nil {
		t.Fatalf("LoadPoPClientTLS: %v", err)
	}
	if err := report(t, lis.Addr().String(), popTLS); err != nil {
		t.Fatalf("PoP 角色证书(pop.crt)应放行,却 %v", err)
	}
	cliTLS, _ := devpki.LoadClientTLS(dir, "localhost")
	if err := report(t, lis.Addr().String(), cliTLS); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("共享 client.crt(无角色)应被拒,却 %v", err)
	}
}

func report(t *testing.T, addr string, tlsConf *tls.Config) error {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = telemetrypb.NewTelemetryClient(conn).Report(ctx, &telemetrypb.ReportRequest{
		Events: []*telemetrypb.Event{{Kind: KindDLPFinding}},
	})
	return err
}
