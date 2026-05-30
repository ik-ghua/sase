//go:build linux

package ztnaterm

// redirect_linux.go 是透明代理(Slice78 零暴露面出站)的 linux 实现:在被内核 iptables REDIRECT 终结的
// listener 上 Accept TCP 连接 → getsockopt(SO_ORIGINAL_DST) 取被改写前的原始 app 目的 → proxyConn
// (fail-closed lookup + 连接级 PEP + OpenStream + 双向 io.Copy)。
//
// 内核侧约定(deploy/pop-entrypoint.sh 配):
//
//	iptables -t nat -A PREROUTING -i <ZTNA_TUN> -p tcp -d <connector_app_cidr> -j REDIRECT --to-ports <proxyPort>
//
// 仅 connector-backed CIDR 被 REDIRECT(非 connector 网段仍走 PoP-TUN SNAT);故到本 listener 的流
// 天然都是 connector-backed,proxyConn 经 reg.OpenStream 反向出站。

import (
	"context"
	"log"
	"net"
	"syscall"
	"unsafe"
)

// getsockopt 的 optname(iptables 头:SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST 均为 80)。
const (
	soOriginalDst   = 80   // SOL_IP   级:IPv4 原始目的
	ip6tOriginalDst = 80   // SOL_IPV6 级:IPv6 原始目的
	solIP           = 0x0  // SOL_IP
	solIPv6         = 0x29 // SOL_IPV6
	sockaddrBufLen  = 64   // sockaddr_in6 (28B) 足够;给足余量
)

// RunRedirectProxy 在 lis 上接受被 REDIRECT 终结的连接,对每条取 SO_ORIGINAL_DST 后 proxyConn。
// 阻塞到 ctx 取消(lis 关闭 → Accept 出错退出)。每条连接独立 goroutine(proxyConn 自管生命周期)。
func (tm *Terminator) RunRedirectProxy(ctx context.Context, lis net.Listener) {
	go func() { <-ctx.Done(); _ = lis.Close() }()
	for {
		conn, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[ztnaterm] 透明代理 Accept: %v", err)
			return
		}
		go tm.serveRedirected(conn)
	}
}

// serveRedirected 对一条已 accept 的 REDIRECT 连接:取原始目的 → proxyConn。取目的失败即关连接(fail-closed)。
func (tm *Terminator) serveRedirected(conn net.Conn) {
	orig, err := originalDst(conn)
	if err != nil {
		tm.drop(reasonProxyOrigDstFail)
		log.Printf("[ztnaterm] 透明代理:取 SO_ORIGINAL_DST 失败,关连接: %v", err)
		_ = conn.Close()
		return
	}
	tm.proxyConn(conn, orig) // proxyConn 内 defer conn.Close()
}

// originalDst 经 getsockopt(SO_ORIGINAL_DST) 取被 REDIRECT 改写前的原始目的(app IP:port)。
// 经 conn 的 SyscallConn().Control 拿 fd 调原始 getsockopt;sockaddr 字节交平台无关 parseOrigDst 解析。
func originalDst(conn net.Conn) (origDst, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return origDst{}, errBadSockaddr
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return origDst{}, err
	}

	// 先按 IPv4(SOL_IP/SO_ORIGINAL_DST)取;family 不符再按 IPv6(SOL_IPV6)取。
	var (
		buf     [sockaddrBufLen]byte
		bufLen  = uint32(len(buf))
		ctrlErr error
		gotV4   bool
		v4err   error
	)
	ctrlErr = raw.Control(func(fd uintptr) {
		l := bufLen
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
			uintptr(solIP), uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0)
		if errno != 0 {
			v4err = errno
			return
		}
		gotV4 = true
	})
	if ctrlErr != nil {
		return origDst{}, ctrlErr
	}
	if gotV4 {
		if od, perr := parseOrigDst(buf[:]); perr == nil {
			return od, nil
		}
		// IPv4 取回但解析不出(如双栈 socket 返回 IPv6)→ 落到 IPv6 路径重取。
	}

	// IPv6 路径(SOL_IPV6/IP6T_SO_ORIGINAL_DST)。
	var (
		buf6  [sockaddrBufLen]byte
		got6  bool
		v6err error
	)
	ctrlErr = raw.Control(func(fd uintptr) {
		l := uint32(len(buf6))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
			uintptr(solIPv6), uintptr(ip6tOriginalDst),
			uintptr(unsafe.Pointer(&buf6[0])), uintptr(unsafe.Pointer(&l)), 0)
		if errno != 0 {
			v6err = errno
			return
		}
		got6 = true
	})
	if ctrlErr != nil {
		return origDst{}, ctrlErr
	}
	if got6 {
		if od, perr := parseOrigDst(buf6[:]); perr == nil {
			return od, nil
		}
	}
	if v4err != nil {
		return origDst{}, v4err
	}
	if v6err != nil {
		return origDst{}, v6err
	}
	return origDst{}, errBadSockaddr
}
