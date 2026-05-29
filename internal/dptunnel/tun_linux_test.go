//go:build linux

package dptunnel

import (
	"os"
	"testing"
)

// TestOpenTUNDevice 验真实 TUN 设备创建(需 CAP_NET_ADMIN + /dev/net/tun)。普通 CI/harness 无权限,
// 故默认 SKIP;在特权容器(--cap-add NET_ADMIN --device /dev/net/tun)设 SASE_TUN_TEST=1 跑。
func TestOpenTUNDevice(t *testing.T) {
	if os.Getenv("SASE_TUN_TEST") != "1" {
		t.Skip("未设 SASE_TUN_TEST=1(需特权容器),跳过 TUN 设备创建验证")
	}
	io, name, err := OpenTUN("")
	if err != nil {
		t.Fatalf("OpenTUN: %v", err)
	}
	defer io.Close()
	if name == "" {
		t.Fatal("内核应分配 TUN 设备名")
	}
	t.Logf("TUN 设备已创建: %s", name)
}
