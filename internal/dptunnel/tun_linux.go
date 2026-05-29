//go:build linux

package dptunnel

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux TUN PacketIO:经 /dev/net/tun + TUNSETIFF 创建 L3 隧道设备,收发原始 IP 包(IFF_NO_PI 去包信息头)。
// 需 CAP_NET_ADMIN(与 PoP 共享 Envoy 同要求,PoC-1)。生产 CPE 的本地包源/汇。
const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunSetIff = 0x400454ca
	ifreqSize = 40 // struct ifreq
	ifNameLen = 16
)

type tunIO struct {
	f *os.File
}

// OpenTUN 打开/创建名为 name 的 TUN 设备(name 空则内核分配,如 tunN),返回 PacketIO 与实际设备名。
func OpenTUN(name string) (PacketIO, string, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("dptunnel: 打开 /dev/net/tun(需 CAP_NET_ADMIN): %w", err)
	}
	var ifr [ifreqSize]byte       // struct ifreq(假设 64-bit Linux)
	copy(ifr[:ifNameLen-1], name) // 留末字节 NUL
	flags := uint16(iffTUN | iffNoPI)
	ifr[ifNameLen] = byte(flags) // ifr_flags(short),手写小端(x86_64/arm64 Linux 均 LE)
	ifr[ifNameLen+1] = byte(flags >> 8)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIff, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		_ = f.Close()
		return nil, "", fmt.Errorf("dptunnel: TUNSETIFF: %w", errno)
	}
	actual := string(trimNUL(ifr[:ifNameLen]))
	return &tunIO{f: f}, actual, nil
}

func trimNUL(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

func (t *tunIO) ReadPacket() ([]byte, error) {
	buf := make([]byte, maxDatagram)
	n, err := t.f.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *tunIO) WritePacket(p []byte) error {
	_, err := t.f.Write(p)
	return err
}

func (t *tunIO) Close() error { return t.f.Close() }
