//go:build darwin

package dptunnel

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// macOS utun PacketIO:经 AF_SYSTEM / SYSPROTO_CONTROL socket + com.apple.net.utun_control 创建系统原生
// utun L3 隧道设备(L2 §3.2「macOS utun via root daemon」)。与 Linux 内核 TUN 平级,统一为 dptunnel.PacketIO
// 接缝,核心 Endpoint/CPE/PoP 零改复用。需 root(开 utun_control 控制 socket 需特权,同 SD-WAN CPE 形态)。
//
// **与 Linux IFF_NO_PI 的契约差异(macOS utun 关键)**:macOS utun 每个收发的包前置 4 字节网络序协议族头
// (AF_INET=2 / AF_INET6=30)。Linux 经 IFF_NO_PI 去掉了包信息头,PacketIO 契约 = 裸 L3 包(无头)。
// 为使三平台 PacketIO 契约一致(Endpoint/ztnaterm 零改):
//   - ReadPacket 剥掉前 4 字节族头,返回裸 L3 包(与 Linux 一致)。
//   - WritePacket 按内层 IP 版本(L3 包首字节高 4 位)前置 4 字节族头再写。
//
// 族头加/剥抽成纯函数(afHeaderFor / stripAFHeader)便于单测。
//
// **fd 可 poll**:与 Linux /dev/net/tun 的 "not pollable"(Slice75 教训,故 Linux 用裸 syscall 阻塞 fd)不同,
// macOS utun fd 是 socket,与 Go netpoller 兼容。本实现仍用裸 unix.Read/Write(阻塞 fd,各自在独立 pump
// goroutine,语义与 Linux tunIO 一致;不必引 os.File)。

const (
	// macOS utun socket 选项常量(见 <sys/kern_control.h> / <net/if_utun.h>)。
	utunControlName = "com.apple.net.utun_control"
	// SYSPROTO_CONTROL = 2(AF_SYSTEM 下的 control 协议)。
	sysprotoControl = 2
	// utun socket option level = SYSPROTO_CONTROL;UTUN_OPT_IFNAME = 2(getsockopt 取设备名)。
	utunOptIfname = 2

	// macOS utun 4 字节协议族头取值(网络序;AF_INET=2、AF_INET6=30)。
	afInet   = unix.AF_INET  // 2
	afInet6  = unix.AF_INET6 // 30
	afHdrLen = 4
)

type utunIO struct {
	fd        int
	closeOnce sync.Once
}

// OpenTUN 打开/创建 macOS utun 设备(签名/契约与 tun_linux.go 完全一致)。
//
// name 解析:空 → Unit=0(内核自动分配 utunN);"utunN" → 指定单元 Unit=N+1(macOS SockaddrCtl.Unit
// 约定:Unit=N+1 对应 utunN,Unit=0 自动分配)。无法解析为 utunN 的 name → 退回自动分配(诚实降级,不报错)。
// 返回实际设备名(由 UTUN_OPT_IFNAME 读出,权威)。
func OpenTUN(name string) (PacketIO, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, "", fmt.Errorf("dptunnel: utun AF_SYSTEM socket(需 root): %w", err)
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("dptunnel: utun IoctlCtlInfo(%s): %w", utunControlName, err)
	}

	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: ctlInfo.Id, Unit: utunUnit(name)}); err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("dptunnel: utun connect(unit %s): %w", name, err)
	}

	// 权威设备名:从内核读回(自动分配时由内核确定 utunN)。
	actual, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("dptunnel: utun GetsockoptString(IFNAME): %w", err)
	}
	return &utunIO{fd: fd}, actual, nil
}

// utunUnit 把期望设备名解析为 SockaddrCtl.Unit:""/无法解析 → 0(自动分配);"utunN" → N+1。
func utunUnit(name string) uint32 {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "utun") {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimPrefix(name, "utun"))
	if err != nil || n < 0 {
		return 0
	}
	return uint32(n) + 1
}

// afHeaderFor 返回内层 L3 包对应的 4 字节 macOS utun 协议族头(网络序大端)。
// 据 L3 包首字节高 4 位判 IP 版本:4 → AF_INET、6 → AF_INET6。空/未知版本 → 默认 AF_INET(IPv4)。
func afHeaderFor(pkt []byte) [afHdrLen]byte {
	af := uint32(afInet)
	if len(pkt) > 0 {
		switch pkt[0] >> 4 {
		case 6:
			af = uint32(afInet6)
		case 4:
			af = uint32(afInet)
		}
	}
	// 网络序(大端)。
	return [afHdrLen]byte{byte(af >> 24), byte(af >> 16), byte(af >> 8), byte(af)}
}

// stripAFHeader 剥掉 macOS utun 帧前 4 字节协议族头,返回裸 L3 包。
// 短于 4 字节(无法含完整族头)→ ok=false(调用方降级丢弃,不 panic)。
func stripAFHeader(frame []byte) (pkt []byte, ok bool) {
	if len(frame) < afHdrLen {
		return nil, false
	}
	return frame[afHdrLen:], true
}

// ReadPacket 阻塞读一个 utun 帧并剥掉 4 字节族头,返回裸 L3 包(与 Linux IFF_NO_PI 契约一致)。
// 返回切片是新分配的(独立 buf),调用方可安全持有/转发。坏帧(短于族头/空)降级返错,不 panic。
func (t *utunIO) ReadPacket() ([]byte, error) {
	buf := make([]byte, maxDatagram)
	for {
		n, err := unix.Read(t.fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue // 被信号打断 → 重试(标准阻塞 I/O 约定)
			}
			return nil, fmt.Errorf("dptunnel: utun 读: %w", err)
		}
		if n <= 0 {
			return nil, fmt.Errorf("dptunnel: utun 读返回 %d 字节", n)
		}
		pkt, ok := stripAFHeader(buf[:n])
		if !ok {
			// 短帧(不含完整 4 字节族头)→ 降级丢弃,继续读下一个(数据面绝不 panic/中断)。
			continue
		}
		// 复制成独立切片(buf 复用,转发方可安全持有)。
		out := make([]byte, len(pkt))
		copy(out, pkt)
		return out, nil
	}
}

// WritePacket 按内层 IP 版本前置 4 字节族头后写入 utun(本地协议栈收到裸 L3 包)。空包降级丢弃,不报错。
func (t *utunIO) WritePacket(p []byte) error {
	if len(p) == 0 {
		return nil // 空包无意义,丢弃(不 panic)
	}
	hdr := afHeaderFor(p)
	frame := make([]byte, afHdrLen+len(p))
	copy(frame[:afHdrLen], hdr[:])
	copy(frame[afHdrLen:], p)
	for {
		_, err := unix.Write(t.fd, frame)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("dptunnel: utun 写: %w", err)
		}
		return nil
	}
}

// Close 关闭 utun fd(幂等:Endpoint.Run defer 与另一 pump 可能各调一次)。
func (t *utunIO) Close() error {
	var err error
	t.closeOnce.Do(func() { err = unix.Close(t.fd) })
	return err
}
