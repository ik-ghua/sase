//go:build darwin

package agentd

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/ikuai8/sase/internal/dptunnel"
)

// macOS 壳实现三窄接口(L2 §3.1/§3.2/§3.8),逐方法对齐 Linux 壳(shell_linux.go):
//   - 流量接管复用 dptunnel.OpenTUN(macOS utun via root daemon,L2 §3.2「MVP 选 root daemon + utun」)。
//   - 路由经 `route -n add`(BSD route 工具,macOS 无 `ip`)把内部 CIDR 指向 utunN;Close 清理防断网。
//   - DNS 接管最小(本刀仅 log,split-DNS 代理 = 后续刀,同 Linux 第一刀)。
//   - 姿态采集 `sw_vers -productVersion` 取 os_version,os="macos";磁盘加密/防火墙等无简易特权-无关 API → 留空
//     (fail-closed,对齐 Linux Collect 的诚实留空)。
//
// 诚实边界:本壳为「特权守护进程直开 utun」形态(需 root,同 Linux CAP_NET_ADMIN / SD-WAN CPE)。
// SystemIntegration 仅 log(launchd plist / 托盘 / IPC 真集成 = 后续刀)。

// darwinNetCapture 是 macOS 流量接管壳:OpenAdapter→dptunnel.OpenTUN(utun);ConfigureRoutes→route add。
type darwinNetCapture struct {
	tunName string // 期望 utun 名(空=内核分配 utunN)
	mtu     int    // 期望内层 MTU(0=不显式设)

	mu     sync.Mutex
	ifname string       // 实际设备名(OpenAdapter 后确定)
	routes []*net.IPNet // 已加的路由(Close 时清理,防崩溃/退出留下断网,L2 §3.5)
}

// NewDarwinNetCapture 构造 macOS 接管壳。tunName 空=内核分配;mtu<=0=不显式设。
func NewDarwinNetCapture(tunName string, mtu int) NetCapture {
	return &darwinNetCapture{tunName: tunName, mtu: mtu}
}

func (d *darwinNetCapture) OpenAdapter() (dptunnel.PacketIO, IfInfo, error) {
	pio, name, err := dptunnel.OpenTUN(d.tunName) // 复用 macOS utun(AF_SYSTEM + utun_control,见 dptunnel/tun_darwin.go)
	if err != nil {
		return nil, IfInfo{}, err
	}
	d.mu.Lock()
	d.ifname = name
	d.mu.Unlock()
	// macOS utun 创建即 up(无需显式 link up,不同于 Linux);仅 MTU 可选设。
	if d.mtu > 0 {
		if err := runIfconfig(name, "mtu", fmt.Sprintf("%d", d.mtu)); err != nil {
			log.Printf("[agentd/darwin] 设 MTU 失败(需 root): %v", err)
		}
	}
	return pio, IfInfo{Name: name, MTU: d.mtu}, nil
}

// ConfigureRoutes 把接管 CIDR 路由指向 utun 设备(split-tunnel 白名单,L2 §3.3)。
// macOS BSD `route` 工具:v4 用 `route -n add -net <cidr> -interface <utunN>`、v6 加 `-inet6`。
// 幂等:先 `route -n delete` 清旧(忽略不存在错)再 add。记录已加路由供 Close 清理。
func (d *darwinNetCapture) ConfigureRoutes(cidrs []*net.IPNet) error {
	d.mu.Lock()
	name := d.ifname
	d.mu.Unlock()
	if name == "" {
		return fmt.Errorf("agentd/darwin: 尚未打开 utun,无法配路由")
	}
	added := make([]*net.IPNet, 0, len(cidrs))
	var firstErr error
	for _, c := range cidrs {
		if c == nil {
			continue
		}
		// 幂等:先删后加(已存在路由 add 会报 "File exists";忽略 delete 失败)。
		_ = runRoute(routeArgs("delete", c, name)...)
		if err := runRoute(routeArgs("add", c, name)...); err != nil {
			log.Printf("[agentd/darwin] 加路由 %s -interface %s 失败: %v", c.String(), name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		added = append(added, c)
	}
	d.mu.Lock()
	d.routes = added
	d.mu.Unlock()
	return firstErr
}

// ConfigureDNS 本刀最小:仅 log 内部域名后缀(split-DNS 代理/overlay 映射 = 后续刀,L2 §3.3,对齐 Linux 壳)。
func (d *darwinNetCapture) ConfigureDNS(rules DNSRules) error {
	if len(rules.InternalSuffixes) > 0 {
		log.Printf("[agentd/darwin] split-DNS(本刀仅记录,代理待后续刀):内部域名后缀 %v", rules.InternalSuffixes)
	}
	return nil
}

// Close 清理已加路由(防崩溃/退出留下断网,L2 §3.5);utun fd 由核心 pump 的 PacketIO.Close 关。
func (d *darwinNetCapture) Close() error {
	d.mu.Lock()
	name, routes := d.ifname, d.routes
	d.routes = nil
	d.mu.Unlock()
	for _, c := range routes {
		if err := runRoute(routeArgs("delete", c, name)...); err != nil {
			log.Printf("[agentd/darwin] 清理路由 %s 失败: %v", c.String(), err)
		}
	}
	return nil
}

// routeArgs 构造 macOS `route` 子命令参数:op ∈ {add,delete};v6 用 `-inet6`。
func routeArgs(op string, c *net.IPNet, ifname string) []string {
	args := []string{"-n", op}
	if c.IP.To4() == nil { // v6
		args = append(args, "-inet6")
	}
	return append(args, "-net", c.String(), "-interface", ifname)
}

func runRoute(args ...string) error {
	cmd := exec.Command("route", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runIfconfig(args ...string) error {
	cmd := exec.Command("ifconfig", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// darwinPostureProbe 采集 macOS 可得的姿态字段(L2 §3.8 各 OS 采集映射表 macOS 列)。
// 拿不到的字段留零值(Unknown),策略侧 fail-closed(对齐 Linux Collect 诚实留空)。
type darwinPostureProbe struct{}

// NewDarwinPostureProbe 构造 macOS 姿态采集器。
func NewDarwinPostureProbe() PostureProbe { return &darwinPostureProbe{} }

func (darwinPostureProbe) Collect() (PostureFacts, error) {
	f := PostureFacts{
		OS:               "macos",
		JailbrokenRooted: TriNo, // 桌面 macOS 默认非越狱(近似;无可靠 root 概念)
	}
	// os_version:`sw_vers -productVersion`(如 14.4.1)。失败留空(诚实)。
	if v := swVersProductVersion(); v != "" {
		f.OSVersion = v
		f.PatchLevel = "macos " + v // 补丁基线以产品版本号近似(无独立包级补丁 API)
	}
	// 其余项(disk_encryption=FileVault / av_edr / firewall / screen_lock)无简易特权-无关 API → 留 Unknown(诚实)。
	// FileVault(fdesetup status)、应用层防火墙(socketfilterfw)多需 root/admin 且输出脆弱 → 本刀不臆造,后续刀深化。
	f.DiskEncryption = FactUnknown
	f.AVEDR = FactUnknown
	f.Firewall = FactUnknown
	f.ScreenLock = FactUnknown
	// device_cert_valid:权威由 PoP mTLS 背书(L2 §3.8 最强项,非 Agent 自报),本端不臆断 → Unknown。
	f.DeviceCertValid = TriUnknown
	// agent_version 由核心 PostureScheduler 盖(单一来源),此处不填。
	return f, nil
}

// swVersProductVersion 调 `sw_vers -productVersion` 取 macOS 产品版本;失败/空 → 返回 ""(诚实留空)。
func swVersProductVersion() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// darwinSystemIntegration 本刀最小:Notify/Autostart 仅 log(launchd plist / 托盘 / IPC 真实现 = 后续刀)。
type darwinSystemIntegration struct{}

// NewDarwinSystemIntegration 构造 macOS 系统集成桩。
func NewDarwinSystemIntegration() SystemIntegration { return &darwinSystemIntegration{} }

func (darwinSystemIntegration) Notify(title, body string) error {
	log.Printf("[agentd/darwin] 通知:%s — %s", title, body)
	return nil
}

func (darwinSystemIntegration) Autostart(enable bool) error {
	log.Printf("[agentd/darwin] 自启登记(本刀仅记录,launchd plist 安装待后续刀):enable=%v", enable)
	return nil
}

// OpenBrowser 用 `open` 拉起系统默认浏览器(IdP 入网,Slice80)。失败 → 返错(daemon 降级打印 url)。
func (darwinSystemIntegration) OpenBrowser(url string) error {
	if err := exec.Command("open", url).Start(); err != nil {
		return fmt.Errorf("agentd/darwin: open 失败,请手动打开 %s: %w", url, err)
	}
	return nil
}

// NewPlatformShells 是 cmd/agent 装配 macOS 三窄壳的便捷构造(平台壳工厂)。
func NewPlatformShells(tunName string, mtu int) (NetCapture, PostureProbe, SystemIntegration) {
	return NewDarwinNetCapture(tunName, mtu), NewDarwinPostureProbe(), NewDarwinSystemIntegration()
}
