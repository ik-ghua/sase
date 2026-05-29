package dptunnel

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// 端到端集成(回环 UDP,无需 root/握手,预置密钥):站点A → PoP → 站点B 经隧道送达,
// 跨租户/无路由的包被 PoP 丢弃。验 UDP 载体 + Endpoint + Router 按内层目的 IP 的租户内选路。

func mustAEAD(t *testing.T, key []byte) AEAD {
	t.Helper()
	a, err := NewAEAD(AlgChaCha20Poly1305, key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	return a
}

func udpConn(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
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

func ipv4(src, dst string, payload string) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	copy(p[20:], payload)
	return p
}

func key32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func waitPacket(t *testing.T, ch <-chan []byte, within time.Duration) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(within):
		return nil
	}
}

func TestTunnelEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connA, connB, connP := udpConn(t), udpConn(t), udpConn(t)
	kA, kB := key32(0xA1), key32(0xB2)

	// PoP 路由:租户 t1,站点A(10.1.0.0/24)、站点B(10.2.0.0/24)
	router := NewRouter()
	router.Register("t1", "siteA", NewSession(mustAEAD(t, kA), 1, 1, 0), connA.LocalAddr(), []*net.IPNet{cidr(t, "10.1.0.0/24")})
	router.Register("t1", "siteB", NewSession(mustAEAD(t, kB), 1, 1, 0), connB.LocalAddr(), []*net.IPNet{cidr(t, "10.2.0.0/24")})
	go router.Serve(ctx, connP)

	// 站点端点(各自 TUN=MemIO),PoP 地址 = connP
	memA, memB := NewMemIO(8), NewMemIO(8)
	epA := NewEndpoint(NewSession(mustAEAD(t, kA), 1, 0, 1), memA, connA, connP.LocalAddr())
	epB := NewEndpoint(NewSession(mustAEAD(t, kB), 1, 0, 1), memB, connB, connP.LocalAddr())
	go epA.Run(ctx)
	go epB.Run(ctx)

	// 站点A 发往 站点B 子网内一个 IP → 应到达 站点B 的 TUN
	pkt := ipv4("10.1.0.5", "10.2.0.9", "site-to-site")
	memA.Inject(pkt)
	got := waitPacket(t, memB.Out(), 2*time.Second)
	if got == nil || !bytes.Equal(got, pkt) {
		t.Fatalf("站点B 应收到原样内层包;got=%v", got)
	}

	// 站点A 发往无路由目的(本租户无站点含该网段)→ PoP 丢弃,站点B 不应收到
	memA.Inject(ipv4("10.1.0.5", "10.9.0.9", "nowhere"))
	if extra := waitPacket(t, memB.Out(), 400*time.Millisecond); extra != nil {
		t.Fatalf("无路由的包不应送达任何站点,却收到 %v", extra)
	}
}

func TestTunnelTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connA, connB, connC, connP := udpConn(t), udpConn(t), udpConn(t), udpConn(t)
	kA, kB, kC := key32(0xA1), key32(0xB2), key32(0xC3)

	// 同一 CIDR 10.2.0.0/24 在两个租户:t1 的 siteB 与 t2 的 siteC。源在 t1,目的应只到 t1 的 B。
	router := NewRouter()
	router.Register("t1", "siteA", NewSession(mustAEAD(t, kA), 1, 1, 0), connA.LocalAddr(), []*net.IPNet{cidr(t, "10.1.0.0/24")})
	router.Register("t1", "siteB", NewSession(mustAEAD(t, kB), 1, 1, 0), connB.LocalAddr(), []*net.IPNet{cidr(t, "10.2.0.0/24")})
	router.Register("t2", "siteC", NewSession(mustAEAD(t, kC), 1, 1, 0), connC.LocalAddr(), []*net.IPNet{cidr(t, "10.2.0.0/24")})
	go router.Serve(ctx, connP)

	memA, memB, memC := NewMemIO(8), NewMemIO(8), NewMemIO(8)
	go NewEndpoint(NewSession(mustAEAD(t, kA), 1, 0, 1), memA, connA, connP.LocalAddr()).Run(ctx)
	go NewEndpoint(NewSession(mustAEAD(t, kB), 1, 0, 1), memB, connB, connP.LocalAddr()).Run(ctx)
	go NewEndpoint(NewSession(mustAEAD(t, kC), 1, 0, 1), memC, connC, connP.LocalAddr()).Run(ctx)

	memA.Inject(ipv4("10.1.0.5", "10.2.0.9", "cross-tenant?"))
	if got := waitPacket(t, memB.Out(), 2*time.Second); got == nil {
		t.Fatal("同租户(t1)站点B 应收到")
	}
	if leak := waitPacket(t, memC.Out(), 400*time.Millisecond); leak != nil {
		t.Fatalf("跨租户隔离失败:t2 站点C 收到了 t1 的包 %v", leak)
	}
}

// 伪造 UDP 源地址(冒充已注册站点)注入垃圾 → 源站点会话 AEAD 认证失败,Router 丢弃、不转发(坐实 S1)。
func TestRouterForgedSourceDropped(t *testing.T) {
	router := NewRouter()
	addrA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
	addrB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}
	router.Register("t1", "siteA", NewSession(mustAEAD(t, key32(0xA1)), 1, 1, 0), addrA, []*net.IPNet{cidr(t, "10.1.0.0/24")})
	router.Register("t1", "siteB", NewSession(mustAEAD(t, key32(0xB2)), 1, 1, 0), addrB, []*net.IPNet{cidr(t, "10.2.0.0/24")})

	// 用错误密钥封装一个发往 10.2 的包,冒充 siteA 的源地址投递
	forged := NewSession(mustAEAD(t, key32(0xFF)), 1, 0, 1)
	frames, _ := forged.Seal(ipv4("10.1.0.5", "10.2.0.9", "forged"))
	out := router.Handle(frames[0], addrA)
	if len(out) != 0 {
		t.Fatalf("伪造源/错误密钥的包应 AEAD 失败被丢,却产生 %d 条转发", len(out))
	}
}

// 重复 Register 同站点(新会话/新地址)→ 旧条目被替换,选路用新条目(坐实 S2)。
func TestRouterReRegisterReplaces(t *testing.T) {
	router := NewRouter()
	addrOld := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41001}
	addrNew := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41002}
	router.Register("t1", "siteB", NewSession(mustAEAD(t, key32(0xB2)), 1, 1, 0), addrOld, []*net.IPNet{cidr(t, "10.2.0.0/24")})
	router.Register("t1", "siteB", NewSession(mustAEAD(t, key32(0xB2)), 1, 1, 0), addrNew, []*net.IPNet{cidr(t, "10.2.0.0/24")})
	router.mu.RLock()
	defer router.mu.RUnlock()
	if n := len(router.byTenant["t1"]); n != 1 {
		t.Fatalf("重复登记同站点应只剩 1 条,得 %d(byTenant 残留旧条目)", n)
	}
	if router.byTenant["t1"][0].addr != addrNew {
		t.Fatal("应保留新地址条目")
	}
	if _, ok := router.bySrc[addrOld.String()]; ok {
		t.Fatal("旧地址的解复用条目应被清除")
	}
}

// 混合 v4/v6 CIDR 的同租户选路:v4 目的只匹配 v4 站点,不被 v6 站点误选(坐实 S3)。
func TestRouteMixedFamily(t *testing.T) {
	router := NewRouter()
	a4 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42001}
	a6 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42002}
	router.Register("t1", "v4site", NewSession(mustAEAD(t, key32(1)), 1, 1, 0), a4, []*net.IPNet{cidr(t, "10.2.0.0/24")})
	router.Register("t1", "v6site", NewSession(mustAEAD(t, key32(2)), 1, 1, 0), a6, []*net.IPNet{cidr(t, "2001:db8::/32")})

	if e := router.route("t1", net.ParseIP("10.2.0.9")); e == nil || e.site != "v4site" {
		t.Fatalf("v4 目的应选 v4site,得 %v", e)
	}
	if e := router.route("t1", net.ParseIP("2001:db8::1")); e == nil || e.site != "v6site" {
		t.Fatalf("v6 目的应选 v6site,得 %v", e)
	}
	if e := router.route("t1", net.ParseIP("10.9.0.9")); e != nil {
		t.Fatal("无匹配 CIDR 应返回 nil")
	}
}

// ipv4TCP 造一个 IPv4+TCP 包(IHL=5),设目的端口,供 5 元组/防火墙测试。
func ipv4TCP(src, dst string, dstPort uint16) []byte {
	p := make([]byte, 24) // 20 IP + 4(够 TCP 端口)
	p[0] = 0x45
	p[9] = 6 // proto = TCP
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	p[22] = byte(dstPort >> 8)
	p[23] = byte(dstPort)
	return p
}

// fwAllow80 是测试用 dptunnel.Firewall:本租户仅放行 tcp 目的端口 80(其余默认拒)。
type fwAllow80 struct{}

func (fwAllow80) Allow(_ string, p Packet5Tuple) bool { return p.Proto == 6 && p.DstPort == 80 }

// FWaaS 在 dptunnel Router 包路径上做 L3/L4 分段:tcp:80 放行转发,tcp:22 被防火墙丢弃(不转发)。
func TestRouterFirewallSegmentation(t *testing.T) {
	router := NewRouter()
	router.SetFirewall(fwAllow80{})
	addrA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43001}
	addrB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43002}
	router.Register("t1", "siteA", NewSession(mustAEAD(t, key32(0xA1)), 1, 1, 0), addrA, []*net.IPNet{cidr(t, "10.1.0.0/24")})
	router.Register("t1", "siteB", NewSession(mustAEAD(t, key32(0xB2)), 1, 1, 0), addrB, []*net.IPNet{cidr(t, "10.2.0.0/24")})

	// 站点A 的发送会话(与 PoP-for-A 镜像)
	sendA := NewSession(mustAEAD(t, key32(0xA1)), 1, 0, 1)

	// tcp:80 → 允许 → 转发到 siteB(1 条 Outbound)
	f80, _ := sendA.Seal(ipv4TCP("10.1.0.5", "10.2.0.9", 80))
	if out := router.Handle(f80[0], addrA); len(out) != 1 || out[0].Addr != addrB {
		t.Fatalf("tcp:80 应放行并转发到 siteB,得 %d 条", len(out))
	}
	// tcp:22 → 防火墙拒 → 不转发(0 条)
	f22, _ := sendA.Seal(ipv4TCP("10.1.0.5", "10.2.0.9", 22))
	if out := router.Handle(f22[0], addrA); len(out) != 0 {
		t.Fatalf("tcp:22 应被防火墙丢弃,却转发 %d 条", len(out))
	}
}
