//go:build darwin

package agentd

import (
	"net"
	"testing"
)

// TestDarwinPostureCollect 验 macOS 姿态采集:os="macos"、os_version 经 sw_vers 真取(macOS 本机可跑)、
// 无简易 API 的字段诚实留 Unknown(fail-closed,对齐 Linux Collect)。
func TestDarwinPostureCollect(t *testing.T) {
	f, err := darwinPostureProbe{}.Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.OS != "macos" {
		t.Fatalf("OS = %q,want macos", f.OS)
	}
	// sw_vers 在 macOS 本机应取到非空产品版本(如 14.x);若环境裁剪导致空,至少 PatchLevel 与 OSVersion 一致。
	if f.OSVersion == "" {
		t.Log("sw_vers 未取到 productVersion(环境裁剪?),OSVersion 留空(诚实)")
	} else if f.PatchLevel != "macos "+f.OSVersion {
		t.Fatalf("PatchLevel = %q,want %q", f.PatchLevel, "macos "+f.OSVersion)
	}
	// 无简易特权-无关 API 的字段 fail-closed 留 Unknown。
	if f.DiskEncryption != FactUnknown || f.AVEDR != FactUnknown || f.Firewall != FactUnknown || f.ScreenLock != FactUnknown {
		t.Fatalf("无 API 字段应留 Unknown,实: disk=%q av=%q fw=%q lock=%q",
			f.DiskEncryption, f.AVEDR, f.Firewall, f.ScreenLock)
	}
	if f.DeviceCertValid != TriUnknown {
		t.Fatalf("DeviceCertValid 应由 PoP 背书 → 本端 Unknown,实 %q", f.DeviceCertValid)
	}
	if f.JailbrokenRooted != TriNo {
		t.Fatalf("JailbrokenRooted 应为 No,实 %q", f.JailbrokenRooted)
	}
	// AgentVersion 由核心 PostureScheduler 盖,壳不填。
	if f.AgentVersion != "" {
		t.Fatalf("AgentVersion 应由核心盖,壳留空,实 %q", f.AgentVersion)
	}
}

// TestDarwinRouteArgs 验 BSD route 参数构造:v4 不带 -inet6、v6 带 -inet6(纯函数)。
func TestDarwinRouteArgs(t *testing.T) {
	_, v4, _ := net.ParseCIDR("10.1.0.0/16")
	args := routeArgs("add", v4, "utun7")
	if hasFlag(args, "-inet6") {
		t.Fatalf("v4 路由不应带 -inet6: %v", args)
	}
	if !hasFlag(args, "-net") || !hasFlag(args, "utun7") || !hasFlag(args, "10.1.0.0/16") {
		t.Fatalf("v4 路由参数缺项: %v", args)
	}

	_, v6, _ := net.ParseCIDR("fd00::/8")
	args6 := routeArgs("delete", v6, "utun7")
	if !hasFlag(args6, "-inet6") {
		t.Fatalf("v6 路由应带 -inet6: %v", args6)
	}
	if !hasFlag(args6, "delete") {
		t.Fatalf("op 应为 delete: %v", args6)
	}
}

func hasFlag(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// TestNewPlatformShellsDarwin 验 macOS 工厂返回三个 darwin 壳(非 nil、类型正确)。
func TestNewPlatformShellsDarwin(t *testing.T) {
	ncap, probe, sys := NewPlatformShells("utun9", 1400)
	if _, ok := ncap.(*darwinNetCapture); !ok {
		t.Fatalf("NetCapture 应为 *darwinNetCapture,实 %T", ncap)
	}
	if _, ok := probe.(*darwinPostureProbe); !ok {
		t.Fatalf("PostureProbe 应为 *darwinPostureProbe,实 %T", probe)
	}
	if _, ok := sys.(*darwinSystemIntegration); !ok {
		t.Fatalf("SystemIntegration 应为 *darwinSystemIntegration,实 %T", sys)
	}
	// 未打开 utun 时 ConfigureRoutes 应返错(不 panic)。
	_, v4, _ := net.ParseCIDR("10.0.0.0/8")
	if err := ncap.ConfigureRoutes([]*net.IPNet{v4}); err == nil {
		t.Fatal("未打开 utun 时 ConfigureRoutes 应返错")
	}
	// ConfigureDNS / Close 最小桩不应报错。
	if err := ncap.ConfigureDNS(DNSRules{InternalSuffixes: []string{"corp.example.com"}}); err != nil {
		t.Fatalf("ConfigureDNS: %v", err)
	}
	if err := ncap.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
