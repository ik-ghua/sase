//go:build !linux && !darwin

package agentd

import (
	"fmt"
	"net"

	"github.com/ikuai8/sase/internal/dptunnel"
)

// 非 Linux/darwin 平台(Windows wintun 壳 = 后续刀,L2 §4)的占位实现:返回 "unsupported platform" 错误,
// 保证 `go build ./...` 在其余平台也过(cmd/agent 构造壳时返错退出,守护进程不崩)。
//
// 注:Windows wintun 的真实现封装为 dptunnel.PacketIO(接缝复用,L2 §3.2),核心 daemon 零改即可消费——
// 本桩仅占位,真壳为后续刀。Linux 见 shell_linux.go、macOS 见 shell_darwin.go。

var errUnsupportedPlatform = fmt.Errorf("agentd: 当前平台暂无流量接管壳(Windows 为后续刀;Linux/macOS 已实现)")

type unsupportedNetCapture struct{}

// NewPlatformShells 在非 Linux/darwin 平台返回 unsupported 桩(同名便于 cmd 跨平台装配;真平台壳为后续刀)。
func NewPlatformShells(_ string, _ int) (NetCapture, PostureProbe, SystemIntegration) {
	return unsupportedNetCapture{}, unsupportedPostureProbe{}, unsupportedSystemIntegration{}
}

func (unsupportedNetCapture) OpenAdapter() (dptunnel.PacketIO, IfInfo, error) {
	return nil, IfInfo{}, errUnsupportedPlatform
}
func (unsupportedNetCapture) ConfigureRoutes([]*net.IPNet) error { return errUnsupportedPlatform }
func (unsupportedNetCapture) ConfigureDNS(DNSRules) error        { return errUnsupportedPlatform }
func (unsupportedNetCapture) Close() error                       { return nil }

type unsupportedPostureProbe struct{}

func (unsupportedPostureProbe) Collect() (PostureFacts, error) {
	return PostureFacts{}, errUnsupportedPlatform
}

type unsupportedSystemIntegration struct{}

func (unsupportedSystemIntegration) Notify(string, string) error { return nil }
func (unsupportedSystemIntegration) Autostart(bool) error        { return nil }

// OpenBrowser 在非 Linux/darwin 平台(Windows wintun 壳为后续刀,L2 §4)返错:daemon 降级打印 url
// 让用户手动打开(headless 友好)。Windows 真集成(rundll32 url.dll,FileProtocolHandler)= 后续刀。
func (unsupportedSystemIntegration) OpenBrowser(url string) error {
	return fmt.Errorf("agentd: 当前平台暂无 OpenBrowser 壳,请手动打开: %s", url)
}
