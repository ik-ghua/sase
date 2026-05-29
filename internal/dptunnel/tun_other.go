//go:build !linux

package dptunnel

import "fmt"

// 非 Linux 平台无 TUN 实现(开发机 macOS 仅编译;TUN 端点在 Linux PoP/CPE 运行)。
func OpenTUN(string) (PacketIO, string, error) {
	return nil, "", fmt.Errorf("dptunnel: TUN 仅 Linux 支持")
}
