package ztnaterm

// Slice78 透明代理单测(平台无关部分):
//   - parseOrigDst:SO_ORIGINAL_DST 返回的 sockaddr 字节解析(纯函数,构造字节验证)。
//   - proxyConn fail-closed:无 byInnerIP 表项的源被关连接(无握手 → 无 principal)。

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/pop"
)

// buildSockaddrIn4 造一个 sockaddr_in(IPv4)字节:Family(native uint16)+Port(BE)+Addr(4)+Zero(8)。
func buildSockaddrIn4(ip string, port uint16) []byte {
	b := make([]byte, 16)
	nativeByteOrder.PutUint16(b[0:2], afInet)
	binary.BigEndian.PutUint16(b[2:4], port)
	copy(b[4:8], net.ParseIP(ip).To4())
	return b
}

// buildSockaddrIn6 造一个 sockaddr_in6(IPv6)字节:Family+Port(BE)+Flowinfo(4)+Addr(16)+Scope(4)。
func buildSockaddrIn6(ip string, port uint16) []byte {
	b := make([]byte, 28)
	nativeByteOrder.PutUint16(b[0:2], afInet6)
	binary.BigEndian.PutUint16(b[2:4], port)
	copy(b[8:24], net.ParseIP(ip).To16())
	return b
}

func TestParseOrigDstIPv4(t *testing.T) {
	od, err := parseOrigDst(buildSockaddrIn4("10.123.0.50", 9000))
	if err != nil {
		t.Fatalf("parseOrigDst v4: %v", err)
	}
	if od.IP.String() != "10.123.0.50" || od.Port != 9000 {
		t.Fatalf("v4 解析错:%+v", od)
	}
	if od.String() != "10.123.0.50:9000" {
		t.Fatalf("String() 错:%q", od.String())
	}
}

func TestParseOrigDstIPv6(t *testing.T) {
	od, err := parseOrigDst(buildSockaddrIn6("2001:db8::5", 443))
	if err != nil {
		t.Fatalf("parseOrigDst v6: %v", err)
	}
	if !od.IP.Equal(net.ParseIP("2001:db8::5")) || od.Port != 443 {
		t.Fatalf("v6 解析错:%+v", od)
	}
}

func TestParseOrigDstBad(t *testing.T) {
	// 太短。
	if _, err := parseOrigDst([]byte{0, 0}); err == nil {
		t.Fatal("短 sockaddr 应失败")
	}
	// 未知族。
	bad := make([]byte, 16)
	nativeByteOrder.PutUint16(bad[0:2], 99)
	if _, err := parseOrigDst(bad); err == nil {
		t.Fatal("未知 family 应失败")
	}
	// v4 族但长度不足 addr。
	short4 := make([]byte, 5)
	nativeByteOrder.PutUint16(short4[0:2], afInet)
	if _, err := parseOrigDst(short4); err == nil {
		t.Fatal("v4 长度不足应失败")
	}
	// v6 族但长度不足。
	short6 := make([]byte, 10)
	nativeByteOrder.PutUint16(short6[0:2], afInet6)
	if _, err := parseOrigDst(short6); err == nil {
		t.Fatal("v6 长度不足应失败")
	}
}

// pipeConnSrc 实现 net.Conn,RemoteAddr 返回指定源(测试 fail-closed lookup)。
type fakeProxyConn struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *fakeProxyConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeProxyConn) Close() error         { c.closed = true; return nil }
func (c *fakeProxyConn) Read([]byte) (int, error) {
	return 0, net.ErrClosed // 不会被读到(fail-closed 前就关)
}
func (c *fakeProxyConn) Write(b []byte) (int, error) { return len(b), nil }

func TestProxyConnFailClosedNoSession(t *testing.T) {
	// 无 byInnerIP 表项(从未握手)→ proxyConn 必须 fail-closed 关连接,绝不放过。
	_, v := newSignerVerifier(t)
	bundles := pop.NewBundleStore()
	bundles.Set(allowBundle("internal-app"))
	term := New(v, bundles, pop.NewRevocationStore(), NewAppResolver(), dptunnel.NewMemIO(4), nil, time.Hour)

	conn := &fakeProxyConn{remote: &net.TCPAddr{IP: net.ParseIP("10.88.0.99"), Port: 5000}}
	term.proxyConn(conn, origDst{IP: net.ParseIP("10.123.0.50"), Port: 9000})
	if !conn.closed {
		t.Fatal("无终结表项的源应被 fail-closed 关连接")
	}
}

func TestProxyConnFailClosedDeny(t *testing.T) {
	// 有 session 但 PEP deny(目的 resource 不在 allow 集)→ 关连接,不出站。
	signer, v := newSignerVerifier(t)
	// bundle 放行 other-app,但目的解析为 internal-app → default-deny。
	b := allowBundle("other-app")
	term, _, _, _ := newTerm(t, signer, v, &b, "10.123.0.50/32", "internal-app")
	// 手动把 Agent 内层 IP 注册进 byInnerIP(模拟已学到)。
	ts := term.bySrc["10.0.0.9:5000"]
	if ts == nil {
		t.Fatal("session 应在 bySrc")
	}
	term.learnInnerIP(ts, net.ParseIP("10.0.0.9"))

	conn := &fakeProxyConn{remote: &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5000}}
	term.proxyConn(conn, origDst{IP: net.ParseIP("10.123.0.50"), Port: 9000})
	if !conn.closed {
		t.Fatal("PEP deny 应关连接")
	}
}

func TestProxyConnNoConnector(t *testing.T) {
	// PEP allow 但未配 connector(reg=nil)→ 关连接(无出站路径)。
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	term, _, _, _ := newTerm(t, signer, v, &b, "10.123.0.50/32", "internal-app")
	ts := term.bySrc["10.0.0.9:5000"]
	term.learnInnerIP(ts, net.ParseIP("10.0.0.9"))

	conn := &fakeProxyConn{remote: &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5000}}
	term.proxyConn(conn, origDst{IP: net.ParseIP("10.123.0.50"), Port: 9000})
	if !conn.closed {
		t.Fatal("allow 但无 connector 应关连接")
	}
}
