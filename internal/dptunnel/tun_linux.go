//go:build linux

package dptunnel

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// Linux TUN PacketIO:经 /dev/net/tun + TUNSETIFF 创建 L3 隧道设备,收发原始 IP 包(IFF_NO_PI 去包信息头)。
// 需 CAP_NET_ADMIN(与 PoP 共享 Envoy 同要求,PoC-1)。生产 CPE 的本地包源/汇。
//
// **不经 os.File**:os.OpenFile 会把 fd 设为非阻塞并注册进 Go 运行时 netpoller(epoll),而 /dev/net/tun
// 字符设备的 epoll 语义与 Go netpoller 不兼容,真实环境下 os.File.Read 会返回 "read /dev/net/tun: not pollable"
// (loopback/MemIO 单测掩盖了此路径,真 TUN 容器实跑才暴露)。故直接用 syscall.Open(阻塞 fd,不入 netpoller)
// + 原始 syscall.Read/Write:阻塞读写各自在独立 pump goroutine 里跑,语义与设计一致。
const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunSetIff = 0x400454ca
	ifreqSize = 40 // struct ifreq
	ifNameLen = 16
)

type tunIO struct {
	fd        int
	closeOnce sync.Once
}

// OpenTUN 打开/创建名为 name 的 TUN 设备(name 空则内核分配,如 tunN),返回 PacketIO 与实际设备名。
func OpenTUN(name string) (PacketIO, string, error) {
	// 阻塞模式打开(syscall.Open 默认阻塞、不入 Go netpoller),避免 "not pollable"。
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("dptunnel: 打开 /dev/net/tun(需 CAP_NET_ADMIN): %w", err)
	}
	var ifr [ifreqSize]byte       // struct ifreq(假设 64-bit Linux)
	copy(ifr[:ifNameLen-1], name) // 留末字节 NUL
	flags := uint16(iffTUN | iffNoPI)
	ifr[ifNameLen] = byte(flags) // ifr_flags(short),手写小端(x86_64/arm64 Linux 均 LE)
	ifr[ifNameLen+1] = byte(flags >> 8)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		_ = syscall.Close(fd)
		return nil, "", fmt.Errorf("dptunnel: TUNSETIFF: %w", errno)
	}
	actual := string(trimNUL(ifr[:ifNameLen]))
	return &tunIO{fd: fd}, actual, nil
}

func trimNUL(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// ReadPacket 阻塞读一个 L3 包(原始 syscall.Read;fd 阻塞 → 无数据时让出 OS 线程,不占 CPU)。
// 返回切片是新分配的(每次独立 buf),调用方可安全持有/转发。
func (t *tunIO) ReadPacket() ([]byte, error) {
	buf := make([]byte, maxDatagram)
	for {
		n, err := syscall.Read(t.fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue // 被信号打断 → 重试(标准阻塞 I/O 约定)
			}
			return nil, fmt.Errorf("dptunnel: TUN 读: %w", err)
		}
		if n <= 0 {
			return nil, fmt.Errorf("dptunnel: TUN 读返回 %d 字节", n)
		}
		return buf[:n], nil
	}
}

// WritePacket 写一个 L3 包到本地协议栈(原始 syscall.Write)。
func (t *tunIO) WritePacket(p []byte) error {
	for {
		_, err := syscall.Write(t.fd, p)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("dptunnel: TUN 写: %w", err)
		}
		return nil
	}
}

// Close 关闭 TUN fd(幂等:Close 一次,Endpoint.Run 的 defer 与另一 pump 可能各调一次)。
func (t *tunIO) Close() error {
	var err error
	t.closeOnce.Do(func() { err = syscall.Close(t.fd) })
	return err
}
