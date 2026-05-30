//go:build darwin

package dptunnel

import (
	"bytes"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAFHeaderFor 验 macOS utun 4 字节族头按内层 IP 版本生成(纯函数,无需特权)。
func TestAFHeaderFor(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want [afHdrLen]byte
	}{
		// IPv4 包(首字节高 4 位 = 4)→ AF_INET = 2 → 网络序 00 00 00 02。
		{"ipv4", []byte{0x45, 0x00, 0x00, 0x14}, [afHdrLen]byte{0, 0, 0, byte(afInet)}},
		// IPv6 包(首字节高 4 位 = 6)→ AF_INET6 = 30(0x1e)→ 网络序 00 00 00 1e。
		{"ipv6", []byte{0x60, 0x00, 0x00, 0x00}, [afHdrLen]byte{0, 0, 0, byte(afInet6)}},
		// 空包 → 默认 AF_INET(不 panic)。
		{"empty", nil, [afHdrLen]byte{0, 0, 0, byte(afInet)}},
		// 未知版本(高 4 位非 4/6)→ 默认 AF_INET。
		{"unknown_version", []byte{0xF0}, [afHdrLen]byte{0, 0, 0, byte(afInet)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := afHeaderFor(c.pkt)
			if got != c.want {
				t.Fatalf("afHeaderFor(%x) = %v, want %v", c.pkt, got, c.want)
			}
		})
	}
	// 显式确认取值正确(防常量漂移):AF_INET=2、AF_INET6=30。
	if afInet != 2 {
		t.Fatalf("afInet 应为 2,实为 %d", afInet)
	}
	if afInet6 != 30 {
		t.Fatalf("afInet6 应为 30,实为 %d", afInet6)
	}
}

// TestStripAFHeader 验剥头还原裸 L3 包 + 短包降级(纯函数,无需特权)。
func TestStripAFHeader(t *testing.T) {
	// 完整帧(4 字节族头 + L3 包)→ 剥出原始 L3 包。
	l3 := []byte{0x45, 0x11, 0x22, 0x33, 0x44}
	frame := append([]byte{0, 0, 0, byte(afInet)}, l3...)
	pkt, ok := stripAFHeader(frame)
	if !ok {
		t.Fatal("完整帧应剥头成功")
	}
	if !bytes.Equal(pkt, l3) {
		t.Fatalf("剥头后 = %x,want %x", pkt, l3)
	}

	// 恰好 4 字节(只有族头无 payload)→ 剥出空切片(ok=true,合法零长包)。
	if p, ok := stripAFHeader([]byte{0, 0, 0, 2}); !ok || len(p) != 0 {
		t.Fatalf("4 字节帧应 ok=true len=0,实 ok=%v len=%d", ok, len(p))
	}

	// 短包(< 4 字节,不含完整族头)→ 降级 ok=false,不 panic。
	for _, short := range [][]byte{nil, {}, {0}, {0, 0}, {0, 0, 0}} {
		if _, ok := stripAFHeader(short); ok {
			t.Fatalf("短帧 %x 应 ok=false", short)
		}
	}
}

// TestAFHeaderRoundTrip 验「加头→剥头」往返还原(纯函数闭环)。
func TestAFHeaderRoundTrip(t *testing.T) {
	for _, l3 := range [][]byte{
		{0x45, 0x00, 0x00, 0x14, 0x01, 0x02}, // v4
		{0x60, 0x00, 0x00, 0x00, 0xAA, 0xBB}, // v6
	} {
		hdr := afHeaderFor(l3)
		frame := append(hdr[:], l3...)
		got, ok := stripAFHeader(frame)
		if !ok || !bytes.Equal(got, l3) {
			t.Fatalf("往返 %x: ok=%v got=%x", l3, ok, got)
		}
	}
}

// TestUtunUnit 验设备名 → SockaddrCtl.Unit 解析(""/非法 → 0 自动分配;utunN → N+1)。
func TestUtunUnit(t *testing.T) {
	cases := []struct {
		name string
		want uint32
	}{
		{"", 0},
		{"utun3", 4},
		{"utun0", 1},
		{"tun0", 0},      // 非 utun 前缀 → 自动分配
		{"utunX", 0},     // 无法解析数字 → 自动分配
		{"  utun5  ", 6}, // 容忍空白
	}
	for _, c := range cases {
		if got := utunUnit(c.name); got != c.want {
			t.Fatalf("utunUnit(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestOpenUtunSmoke 真 utun 冒烟(需 root):创建 utun → 写一个含族头的 IPv4 包 → 读回验剥头 → Close。
// 非 root 环境 Skip(诚实:真 utun 创建需 root 特权)。
func TestOpenUtunSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("非 root(真 utun 创建需 root 特权),跳过 utun 设备冒烟")
	}
	pio, name, err := OpenTUN("")
	if err != nil {
		t.Fatalf("OpenTUN: %v", err)
	}
	defer pio.Close()
	if name == "" {
		t.Fatal("内核应分配 utun 设备名")
	}
	t.Logf("utun 设备已创建: %s", name)

	// 直接对底层 fd 写入一个带 AF_INET 族头的环回 IPv4 包,验证 ReadPacket 能剥头读回裸 L3 包。
	io, ok := pio.(*utunIO)
	if !ok {
		t.Fatalf("PacketIO 应为 *utunIO,实为 %T", pio)
	}
	// 最小 IPv4 头(20 字节,version=4 IHL=5),src/dst 任意环回。
	l3 := make([]byte, 20)
	l3[0] = 0x45
	frame := append([]byte{0, 0, 0, byte(afInet)}, l3...)
	if _, err := unix.Write(io.fd, frame); err != nil {
		t.Fatalf("写 utun 帧: %v", err)
	}
	got, err := io.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(got, l3) {
		t.Fatalf("读回 L3 包 = %x,want %x(族头应已剥)", got, l3)
	}
}
