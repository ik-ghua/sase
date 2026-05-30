//go:build linux

package agentd

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/ikuai8/sase/internal/dptunnel"
)

// Linux 壳实现三窄接口(L2 §3.1/§3.2/§3.8)。流量接管复用 dptunnel.OpenTUN(Slice75 已证真 TUN 可跑);
// 路由经 `ip route`(exec)把内部 CIDR 指向 tun 设备;DNS 接管最小(本刀仅 log,深化为后续刀);
// 姿态采集读 /etc/os-release、uname 等 Linux 可得字段(拿不到留空,fail-closed)。
//
// 诚实边界:本壳为「特权守护进程直开 TUN」形态(需 CAP_NET_ADMIN / root,同 SD-WAN CPE)。
// ConfigureDNS 仅 log(split-DNS 代理 = 后续刀);SystemIntegration 仅 log(托盘/IPC/自启真实现 = 后续刀)。

// linuxNetCapture 是 Linux 流量接管壳:OpenAdapter→dptunnel.OpenTUN;ConfigureRoutes→ip route。
type linuxNetCapture struct {
	tunName string // 期望 TUN 名(空=内核分配)
	mtu     int    // 期望内层 MTU(0=不显式设)

	mu     sync.Mutex
	ifname string       // 实际设备名(OpenAdapter 后确定)
	routes []*net.IPNet // 已加的路由(Close 时清理,防崩溃留下断网,L2 §3.5)
}

// NewLinuxNetCapture 构造 Linux 接管壳。tunName 空=内核分配;mtu<=0=不显式设。
func NewLinuxNetCapture(tunName string, mtu int) NetCapture {
	return &linuxNetCapture{tunName: tunName, mtu: mtu}
}

func (l *linuxNetCapture) OpenAdapter() (dptunnel.PacketIO, IfInfo, error) {
	pio, name, err := dptunnel.OpenTUN(l.tunName) // 复用既有 Linux TUN(/dev/net/tun + TUNSETIFF)
	if err != nil {
		return nil, IfInfo{}, err
	}
	l.mu.Lock()
	l.ifname = name
	l.mu.Unlock()
	// 拉起设备(必需:新建 TUN 默认 DOWN,不 up 则无法路由)。失败不致命(返回设备给核心 pump),仅告警。
	if err := runIP("link", "set", "dev", name, "up"); err != nil {
		log.Printf("[agentd/linux] ip link up %s 失败(需 CAP_NET_ADMIN): %v", name, err)
	}
	if l.mtu > 0 {
		if err := runIP("link", "set", "dev", name, "mtu", fmt.Sprintf("%d", l.mtu)); err != nil {
			log.Printf("[agentd/linux] 设 MTU 失败: %v", err)
		}
	}
	return pio, IfInfo{Name: name, MTU: l.mtu}, nil
}

// ConfigureRoutes 把接管 CIDR 路由指向 tun 设备(split-tunnel 白名单,L2 §3.3)。
// 幂等:先尝试 replace(已存在则覆盖)。记录已加路由供 Close 清理。
func (l *linuxNetCapture) ConfigureRoutes(cidrs []*net.IPNet) error {
	l.mu.Lock()
	name := l.ifname
	l.mu.Unlock()
	if name == "" {
		return fmt.Errorf("agentd/linux: 尚未打开 TUN,无法配路由")
	}
	added := make([]*net.IPNet, 0, len(cidrs))
	var firstErr error
	for _, c := range cidrs {
		if c == nil {
			continue
		}
		if err := runIP("route", "replace", c.String(), "dev", name); err != nil {
			log.Printf("[agentd/linux] 加路由 %s dev %s 失败: %v", c.String(), name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		added = append(added, c)
	}
	l.mu.Lock()
	l.routes = added
	l.mu.Unlock()
	return firstErr
}

// ConfigureDNS 本刀最小:仅 log 内部域名后缀(split-DNS 代理/overlay 映射 = 后续刀,L2 §3.3)。
func (l *linuxNetCapture) ConfigureDNS(rules DNSRules) error {
	if len(rules.InternalSuffixes) > 0 {
		log.Printf("[agentd/linux] split-DNS(本刀仅记录,代理待后续刀):内部域名后缀 %v", rules.InternalSuffixes)
	}
	return nil
}

// Close 清理已加路由(防崩溃/退出留下断网,L2 §3.5);TUN fd 由核心 pump 的 PacketIO.Close 关。
func (l *linuxNetCapture) Close() error {
	l.mu.Lock()
	name, routes := l.ifname, l.routes
	l.routes = nil
	l.mu.Unlock()
	for _, c := range routes {
		if err := runIP("route", "del", c.String(), "dev", name); err != nil {
			log.Printf("[agentd/linux] 清理路由 %s 失败: %v", c.String(), err)
		}
	}
	return nil
}

func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// linuxPostureProbe 采集 Linux 可得的姿态字段(L2 §3.8 各 OS 采集映射表 Linux 列)。
// 拿不到的字段留零值(Unknown),策略侧 fail-closed。诚实:Linux 多数项弱(无统一 API),自报为主。
type linuxPostureProbe struct{}

// NewLinuxPostureProbe 构造 Linux 姿态采集器。
func NewLinuxPostureProbe() PostureProbe { return &linuxPostureProbe{} }

func (linuxPostureProbe) Collect() (PostureFacts, error) {
	f := PostureFacts{
		OS:               runtime.GOOS, // "linux"
		JailbrokenRooted: TriNo,        // 桌面 Linux 默认非 root 设备(近似;无可靠越狱概念)
	}
	// os_version:读 /etc/os-release 的 VERSION_ID,退回内核版本(/proc/sys/kernel/osrelease)。
	if v := osReleaseField("VERSION_ID"); v != "" {
		f.OSVersion = v
	} else if kv := readTrim("/proc/sys/kernel/osrelease"); kv != "" {
		f.OSVersion = kv
	}
	// patch_level:用内核版本作基线标识(包级补丁基线无统一 API,L2 §3.8 标弱)。
	if kv := readTrim("/proc/sys/kernel/osrelease"); kv != "" {
		f.PatchLevel = "kernel " + kv
	}
	// 其余项(disk_encryption/av_edr/firewall/screen_lock)Linux 无统一可靠 API → 留 Unknown(诚实)。
	// disk_encryption 可探 /proc/crypt 等但因 DE/发行版差异大,本刀不臆造,标后续刀深化。
	f.DiskEncryption = FactUnknown
	f.AVEDR = FactUnknown
	f.Firewall = detectLinuxFirewall()
	f.ScreenLock = FactUnknown
	// device_cert_valid:权威由 PoP mTLS 背书(L2 §3.8 最强项,非 Agent 自报),本端不臆断 → Unknown。
	f.DeviceCertValid = TriUnknown
	// agent_version 由核心 PostureScheduler 盖(单一来源),此处不填。
	return f, nil
}

// detectLinuxFirewall 轻量探测 nft/iptables 是否存在(present;无统一启用状态 API → 不轻言 healthy)。
func detectLinuxFirewall() FactState {
	for _, bin := range []string{"nft", "iptables", "ufw"} {
		if _, err := exec.LookPath(bin); err == nil {
			return FactPresent
		}
	}
	return FactUnknown
}

func osReleaseField(key string) string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key+"=") {
			v := strings.TrimPrefix(line, key+"=")
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// linuxSystemIntegration 本刀最小:Notify/Autostart 仅 log(托盘/IPC/launchd 等真实现 = 后续刀)。
type linuxSystemIntegration struct{}

// NewLinuxSystemIntegration 构造 Linux 系统集成桩。
func NewLinuxSystemIntegration() SystemIntegration { return &linuxSystemIntegration{} }

func (linuxSystemIntegration) Notify(title, body string) error {
	log.Printf("[agentd/linux] 通知:%s — %s", title, body)
	return nil
}

func (linuxSystemIntegration) Autostart(enable bool) error {
	log.Printf("[agentd/linux] 自启登记(本刀仅记录,systemd unit 安装待后续刀):enable=%v", enable)
	return nil
}

// OpenBrowser 用 xdg-open 拉起系统默认浏览器(IdP 入网,Slice80)。无 GUI/无 xdg-open → 返错(daemon 降级打印 url)。
func (linuxSystemIntegration) OpenBrowser(url string) error {
	if _, err := exec.LookPath("xdg-open"); err != nil {
		return fmt.Errorf("agentd/linux: 无 xdg-open(无 GUI?),请手动打开: %s", url)
	}
	if err := exec.Command("xdg-open", url).Start(); err != nil {
		return fmt.Errorf("agentd/linux: xdg-open 失败: %w", err)
	}
	return nil
}

// NewPlatformShells 是 cmd/agent 装配 Linux 三窄壳的便捷构造(平台壳工厂,跨平台同名;macOS 见
// shell_darwin.go、非 Linux/darwin 见 shell_other.go)。
func NewPlatformShells(tunName string, mtu int) (NetCapture, PostureProbe, SystemIntegration) {
	return NewLinuxNetCapture(tunName, mtu), NewLinuxPostureProbe(), NewLinuxSystemIntegration()
}
