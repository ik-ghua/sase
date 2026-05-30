//go:build !linux

package agentd

import (
	"fmt"
	"net"

	"github.com/ikuai8/sase/internal/dptunnel"
)

// 非 Linux 平台(Windows/macOS 壳 = 后续刀,L2 §4)的占位实现:返回 "unsupported platform" 错误,
// 保证 `go build ./...` 在 Mac 上也过(cmd/agent 构造壳时返错退出,守护进程不崩)。
//
// 注:Windows wintun / macOS utun via root daemon 的真实现各封装为 dptunnel.PacketIO(接缝复用,L2 §3.2),
// 核心 daemon 零改即可消费——本桩仅占位,真壳为后续刀。

var errUnsupportedPlatform = fmt.Errorf("agentd: 当前平台暂无流量接管壳(Windows/macOS 为后续刀,仅 Linux 已实现)")

type unsupportedNetCapture struct{}

// NewLinuxShells 在非 Linux 平台返回 unsupported 桩(同名便于 cmd 跨平台装配;真平台壳为后续刀)。
func NewLinuxShells(_ string, _ int) (NetCapture, PostureProbe, SystemIntegration) {
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
