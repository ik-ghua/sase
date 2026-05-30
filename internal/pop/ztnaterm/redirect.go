package ztnaterm

// redirect.go 是 Slice78 透明代理(零暴露面出站)的平台无关部分:SO_ORIGINAL_DST 的 sockaddr 字节解析
// (纯函数,可在任意平台单测)+ 单连接代理逻辑(fail-closed lookup → PEP → OpenStream → 双向 io.Copy)。
//
// 平台相关的 Accept 循环 + getsockopt(SO_ORIGINAL_DST)在 redirect_linux.go(linux)/ redirect_other.go(stub)。
//
// 安全核心(§3.4.1,务必严守):
//   - REDIRECT 流被内核终结、**不经包级 decide**,透明代理是其唯一授权检查点。
//   - accept 后**第一件事** lookupInnerIP(源 IP),找不到即 fail-closed 关连接(无握手 → 无 principal,防伪造源蹭)。
//   - PEP 必做完整(decideResource:查吊销 + pep.Decide,与包路径同一逻辑);deny 关连接。
//   - OpenStream(tenant, app, dst):key 含 tenant → 跨租户隔离。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"unsafe"
)

// nativeByteOrder 是本机字节序(sockaddr.sa_family 以主机字节序存放;Port/Addr 才是网络序)。
// 经 unsafe 探测一次(amd64/arm64 Linux 均小端;保持可移植不写死)。
var nativeByteOrder = func() binary.ByteOrder {
	x := uint16(1)
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

// nativeUint16 按本机字节序读 2 字节(用于 sa_family)。
func nativeUint16(b []byte) uint16 { return nativeByteOrder.Uint16(b) }

// origDst 是 SO_ORIGINAL_DST 取回的原始目的(被 REDIRECT 改写前的 app IP:port)。
type origDst struct {
	IP   net.IP
	Port uint16
}

func (o origDst) String() string { return net.JoinHostPort(o.IP.String(), fmt.Sprintf("%d", o.Port)) }

// errBadSockaddr 表示 SO_ORIGINAL_DST 返回的 sockaddr 字节无法解析(长度/族不符)。
var errBadSockaddr = errors.New("ztnaterm: SO_ORIGINAL_DST sockaddr 解析失败")

// sockaddr 族常量(与内核 AF_INET/AF_INET6 一致;Linux 上 AF_INET=2、AF_INET6=10)。
const (
	afInet  = 2
	afInet6 = 10
)

// parseOrigDst 把 getsockopt(SO_ORIGINAL_DST) 返回的 sockaddr 字节解析为原目的 IP:port(纯函数,可单测)。
//
// 布局(Linux,Family 为主机字节序 uint16;Port/Addr 为网络字节序):
//
//	sockaddr_in  (IPv4): Family(2) Port(2,BE) Addr(4) Zero(8)            —— 共 16 字节
//	sockaddr_in6 (IPv6): Family(2) Port(2,BE) Flowinfo(4) Addr(16) Scope(4) —— 共 28 字节
//
// Family 用主机字节序读(内核以主机序写 sa_family);Port/Addr 是网络序(大端)。坏字节 → errBadSockaddr。
func parseOrigDst(buf []byte) (origDst, error) {
	if len(buf) < 4 {
		return origDst{}, errBadSockaddr
	}
	family := nativeUint16(buf[0:2])
	port := binary.BigEndian.Uint16(buf[2:4]) // sin_port / sin6_port 是网络字节序
	switch family {
	case afInet:
		if len(buf) < 8 {
			return origDst{}, errBadSockaddr
		}
		ip := make(net.IP, 4)
		copy(ip, buf[4:8])
		return origDst{IP: ip, Port: port}, nil
	case afInet6:
		if len(buf) < 24 { // Family(2)+Port(2)+Flowinfo(4)+Addr(16) = 24(Scope 可选不强制)
			return origDst{}, errBadSockaddr
		}
		ip := make(net.IP, 16)
		copy(ip, buf[8:24])
		return origDst{IP: ip, Port: port}, nil
	default:
		return origDst{}, fmt.Errorf("%w: 未知 family %d", errBadSockaddr, family)
	}
}

// proxyConn 处理一条被 REDIRECT 终结的 TCP 连接(平台无关,linux Accept 循环调用):
//
//	① lookupInnerIP(conn 源 IP) —— fail-closed:找不到关连接(§3.4.1,绝不放过无握手的源)。
//	② orig = 原始目的(SO_ORIGINAL_DST,由平台层取好传入)。
//	③ appResolver.Resolve(ts.tenant, orig) —— 只在本租户域;解不出 → 关连接。
//	④ decideResource(ts, appKey) —— 查吊销 + PEP;deny 关连接。
//	⑤ reg.OpenStream(ts.tenant, appKey, dst) —— 经 connector 反向出站;无 connector 关连接。
//	⑥ 双向 io.Copy(conn ↔ stream)。
func (tm *Terminator) proxyConn(conn net.Conn, orig origDst) {
	defer conn.Close()

	// ① fail-closed:无 byInnerIP 表项(无有效 dptunnel 握手)→ 无 principal → 立即关连接。
	srcIP := connSrcIP(conn)
	ts, ok := tm.lookupInnerIP(srcIP)
	if !ok {
		tm.drop(reasonProxyNoSession)
		log.Printf("[ztnaterm] 透明代理拒绝:源 %s 无终结表项(无握手 → fail-closed)", srcIP)
		return
	}

	// 兜底闸:session deadline 到期 → 拆 session + 关连接(强制重握手)。
	if !tm.now().Before(ts.deadline) {
		tm.evictSession(ts.srcAddr.String(), ts, reasonExpired)
		return
	}

	// ③ 原目的在本租户域内解析为 resource;**强制 @connector 标志为代码不变量**(reviewer B1):
	// 透明代理是零暴露 connector 出站专用路径——只有标了 @connector 的 resource 才允许经此出站。
	// 若一条 SNAT-only(connector==false)规则的 CIDR 被运维误配进 ZTNA_REDIRECT_CIDRS,流量会被
	// REDIRECT 到本代理;此处据 connector 标志关连接,杜绝 env 配错导致 SNAT-only resource 误走 connector。
	appKey, connector, ok := tm.apps.ResolveRule(ts.tenant, orig.IP, orig.Port)
	if !ok {
		tm.drop(reasonProxyNoApp)
		log.Printf("[ztnaterm] 透明代理拒绝:tenant=%s 原目的 %s 解析不出 resource", ts.tenant, orig)
		return
	}
	if !connector {
		tm.drop(reasonProxyNoApp)
		log.Printf("[ztnaterm] 透明代理拒绝:tenant=%s app=%s 非 @connector 资源(REDIRECT CIDR 与 @connector 标志须对齐)", ts.tenant, appKey)
		return
	}

	// ④ 连接级 PEP(查吊销 + pep.Decide,与包路径同一逻辑零行为漂移)。deny 关连接。
	allow, _, reason := tm.decideResource(ts, appKey)
	if !allow {
		dr := reasonProxyDeny
		if reason == reasonRevoked {
			dr = reasonRevoked // 撤销已在 decideResource 拆 session
		}
		tm.drop(dr)
		log.Printf("[ztnaterm] 透明代理 DENY tenant=%s sub=%s app=%s dst=%s (%s)", ts.tenant, ts.claims.Subject, appKey, orig, reason)
		return
	}

	// ⑤ 经 connector 反向出站(零暴露面)。无 connector → 关连接。
	if tm.reg == nil {
		tm.drop(reasonNoConnector)
		log.Printf("[ztnaterm] 透明代理拒绝:未配 connector 注册表 tenant=%s app=%s", ts.tenant, appKey)
		return
	}
	stream, err := tm.reg.OpenStream(ts.tenant, appKey, orig.String())
	if err != nil {
		tm.drop(reasonNoConnector)
		log.Printf("[ztnaterm] 透明代理:tenant=%s app=%s 无 connector(%v)", ts.tenant, appKey, err)
		return
	}
	defer stream.Close()
	tm.drop(reasonProxyEstablished) // 复用 TunnelDrop 计数器记一次流建立(可观测;非真丢弃)
	log.Printf("[ztnaterm] 透明代理 ALLOW tenant=%s sub=%s app=%s dst=%s → connector", ts.tenant, ts.claims.Subject, appKey, orig)

	// ⑥ 双向泵(代理 conn ↔ connector 反向流)。任一向结束即收尾另一向。
	pipeBidir(conn, stream)
}

// pipeBidir 在两个 io.ReadWriteCloser 间双向拷贝,任一向 EOF/出错即关两端(解除另一向阻塞)。
func pipeBidir(a net.Conn, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a) // 客户端(Agent)→ connector → app
		_ = b.Close()
		_ = closeRead(a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b) // app → connector → 客户端(Agent)
		_ = closeWrite(a)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// closeRead/closeWrite 尽量半关(TCP CloseRead/CloseWrite);非 TCP 退化为全关。
func closeRead(c net.Conn) error {
	if t, ok := c.(interface{ CloseRead() error }); ok {
		return t.CloseRead()
	}
	return nil
}

func closeWrite(c net.Conn) error {
	if t, ok := c.(interface{ CloseWrite() error }); ok {
		return t.CloseWrite()
	}
	return nil
}

// connSrcIP 取连接对端(Agent 内层)源 IP。
func connSrcIP(conn net.Conn) net.IP {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
