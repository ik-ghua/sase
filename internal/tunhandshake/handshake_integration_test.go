package tunhandshake_test

// Slice30 端到端:**真实握手**(mutual TLS1.3 + RFC5705 密钥导出 + ZTP 证书身份)驱动 dptunnel 数据面。
// 不预置密钥——CPE/PoP 经握手各自导出同一会话密钥;PoP 从已认证证书取 (tenant,site) 登记 Router;
// FWaaS L3/L4 在真数据面裁决。验:① 真握手密钥端到端可达 ② FWaaS deny 丢包 ③ 跨租户隔离
// ④ 防降级(alg 不符拒)⑤ 非 ZTP 证书(无租户)握手被拒。本机/容器可跑(localhost TCP+UDP,无需 root)。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/tunhandshake"
)

// ── 测试脚手架(内存 CA + 按 tenant/site 签设备证书 + PoP 握手栈)─────────────────────

func newCA(t *testing.T) *devpki.CA {
	t.Helper()
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

// deviceTLS 签一张 ZTP 设备证书(tenant 进 Organization、site 进 CN),产 CPE 侧 mutual-TLS 客户端配置。
func deviceTLS(t *testing.T, ca *devpki.CA, tenant, site string) *tls.Config {
	t.Helper()
	csrPEM, keyPEM, err := devpki.GenerateCSR(site)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	certPEM, err := ca.SignCSR(csrPEM, tenant, site)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
}

func udpConn(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	return n
}

// ipv4TCP 造 IPv4+TCP 包(IHL=5)设目的端口,供 5 元组/FWaaS 测试。
func ipv4TCP(src, dst string, dstPort uint16) []byte {
	p := make([]byte, 24)
	p[0] = 0x45
	p[9] = 6 // TCP
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	p[22] = byte(dstPort >> 8)
	p[23] = byte(dstPort)
	return p
}

func waitPacket(ch <-chan []byte, within time.Duration) []byte {
	select {
	case p := <-ch:
		return p
	case <-time.After(within):
		return nil
	}
}

// fwTCP80 是测试 FWaaS:本租户仅放行 tcp:80(其余默认拒)。
type fwTCP80 struct{}

func (fwTCP80) Allow(_ string, p dptunnel.Packet5Tuple) bool { return p.Proto == 6 && p.DstPort == 80 }

// popStack 起一个 PoP:UDP 数据面 + Router(挂 FWaaS)+ 握手 TLS 监听。返回握手地址。
type popStack struct {
	handshakeAddr string
	router        *dptunnel.Router
	cidrs         map[string][]*net.IPNet // tenant|site → 子网(模拟 SiteConfig 下发)
}

func startPoP(t *testing.T, ctx context.Context, ca *devpki.CA, cidrs map[string][]*net.IPNet) *popStack {
	t.Helper()
	dataConn := udpConn(t)
	router := dptunnel.NewRouter()
	router.SetFirewall(fwTCP80{})
	go router.Serve(ctx, dataConn)

	ps := &popStack{router: router, cidrs: cidrs}
	srv := tunhandshake.NewServer(dataConn.LocalAddr().String(), dptunnel.AlgChaCha20Poly1305, func(e tunhandshake.Established) {
		sess, err := e.Session()
		if err != nil {
			t.Errorf("PoP 建会话: %v", err)
			return
		}
		// 身份权威=证书:tenant/site 来自 e(已认证证书),cidrs 来自"SiteConfig"。
		router.Register(e.Tenant, e.Site, sess, e.CPEDataAddr, cidrs[e.Tenant+"|"+e.Site])
	})

	popServerCfg, err := ca.ServerTLS("localhost")
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ln := tls.NewListener(tcpLn, popServerCfg)
	go func() { _ = srv.Serve(ctx, ln) }()
	ps.handshakeAddr = ln.Addr().String()
	return ps
}

// dialCPE 完成握手并起 Endpoint(TUN=MemIO);返回注入/接收用的 MemIO。
func dialCPE(t *testing.T, ctx context.Context, ps *popStack, ca *devpki.CA, tenant, site string) *dptunnel.MemIO {
	t.Helper()
	dataConn := udpConn(t)
	res, err := tunhandshake.Dial(ctx, ps.handshakeAddr, deviceTLS(t, ca, tenant, site),
		dptunnel.AlgChaCha20Poly1305, dataConn.LocalAddr().String(), tenant, site)
	if err != nil {
		t.Fatalf("CPE %s/%s 握手: %v", tenant, site, err)
	}
	sess, err := res.Session()
	if err != nil {
		t.Fatalf("CPE 建会话: %v", err)
	}
	mem := dptunnel.NewMemIO(8)
	ep := dptunnel.NewEndpoint(sess, mem, dataConn, res.PoPDataAddr)
	go ep.Run(ctx)
	return mem
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

func TestHandshakeEndToEndWithFirewallAndIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)

	// 同 CIDR 10.2.0.0/24 在两租户:t1/siteB 与 t2/siteC。源 t1/siteA → 目的应只到 t1/siteB。
	cidrs := map[string][]*net.IPNet{
		"t1|siteA": {cidr(t, "10.1.0.0/24")},
		"t1|siteB": {cidr(t, "10.2.0.0/24")},
		"t2|siteC": {cidr(t, "10.2.0.0/24")},
	}
	ps := startPoP(t, ctx, ca, cidrs)

	memA := dialCPE(t, ctx, ps, ca, "t1", "siteA")
	memB := dialCPE(t, ctx, ps, ca, "t1", "siteB")
	memC := dialCPE(t, ctx, ps, ca, "t2", "siteC")

	// ① 真握手密钥端到端:t1/siteA → 10.2.0.9 tcp:80 → 经 PoP 选路到 t1/siteB(FWaaS 放行)
	pkt80 := ipv4TCP("10.1.0.5", "10.2.0.9", 80)
	memA.Inject(pkt80)
	if got := waitPacket(memB.Out(), 3*time.Second); got == nil {
		t.Fatal("t1/siteB 应收到 tcp:80(真握手密钥 + 证书身份选路 + FWaaS 放行)")
	}
	// ③ 跨租户隔离:t2/siteC 同 CIDR 但不同租户,不应收到 t1 的包
	if leak := waitPacket(memC.Out(), 500*time.Millisecond); leak != nil {
		t.Fatalf("跨租户隔离失败:t2/siteC 收到了 t1 的包 %v", leak)
	}

	// ② FWaaS L4 deny:tcp:22 被防火墙丢,siteB 不应收到
	memA.Inject(ipv4TCP("10.1.0.5", "10.2.0.9", 22))
	if got := waitPacket(memB.Out(), 500*time.Millisecond); got != nil {
		t.Fatalf("tcp:22 应被 FWaaS 丢弃,siteB 却收到 %v", got)
	}
}

func TestHandshakeDowngradeRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)
	ps := startPoP(t, ctx, ca, map[string][]*net.IPNet{"t1|siteA": {cidr(t, "10.1.0.0/24")}})

	dataConn := udpConn(t)
	// CPE 期望国密档 sm4gcm,但 PoP 服务 chacha20poly1305 → 防降级:Dial 应拒。
	_, err := tunhandshake.Dial(ctx, ps.handshakeAddr, deviceTLS(t, ca, "t1", "siteA"),
		dptunnel.AlgSM4GCM, dataConn.LocalAddr().String(), "t1", "siteA")
	if err == nil {
		t.Fatal("算法档不符(期望 sm4gcm,PoP chacha)应拒(防降级),却成功")
	}
}

func TestHandshakeNonZTPCertRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)
	ps := startPoP(t, ctx, ca, map[string][]*net.IPNet{})

	// 用 CA 签的**无租户**客户端证书(dev 共享证书形态)→ TLS 通过但 PoP 取不到租户 → 握手被拒。
	noTenant, err := ca.ClientTLS("localhost")
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
	dataConn := udpConn(t)
	_, err = tunhandshake.Dial(ctx, ps.handshakeAddr, noTenant,
		dptunnel.AlgChaCha20Poly1305, dataConn.LocalAddr().String(), "t1", "siteA")
	if err == nil {
		t.Fatal("非 ZTP 绑定证书(无租户)应被 PoP 拒(身份权威=证书),却握手成功")
	}
}
