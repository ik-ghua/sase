//go:build !linux && !darwin

package dptunnel

import "fmt"

// 非 Linux/darwin 平台无 TUN 实现(Linux 见 tun_linux.go、macOS utun 见 tun_darwin.go;
// 其余平台 Windows wintun 等 = 后续刀,本桩占位保 go build 过)。
func OpenTUN(string) (PacketIO, string, error) {
	return nil, "", fmt.Errorf("dptunnel: TUN 暂仅 Linux/macOS 支持(其余平台为后续刀)")
}
