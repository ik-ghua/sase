// Package agentd 是真 OS 级 ZTNA 端点 Agent 的**守护进程共享核心**(L2 `docs/sase-l2-ztna-agent.md`
// 子块1「共享核心组装」)。命名为 agentd(非 agent)以与既有 `internal/agent`(会话/实时通道客户端、
// 一次性 Access)区分——本包**复用** `internal/agent`、`internal/cred`、`internal/enroll`、
// `internal/tunhandshake`、`internal/dptunnel` 等既有件,组装成长驻多平台守护进程,而非重造。
//
// 平台无关核心(daemon 状态机 + flowmgr 分流 + popselect 选址 + posture 调度 + 凭证刷新)与
// 碰 OS 的薄壳(NetCapture/PostureProbe/SystemIntegration 三窄接口)分离(L2 §3.1):核心跨平台一致,
// 壳逐 OS 实现(Linux 见 shell_linux.go;Windows/macOS = 后续刀)。
//
// 诚实边界(本刀有意不做,见 L2 §六/附录):
//   - PoP 侧 ZTNA-over-packet 终结 + PEP 在包路径求值 = PoP L2 后续刀(本刀 Agent 侧只把 L3 包送到 PoP)。
//   - Windows/macOS 壳 = 后续刀(本刀只定接口 + Linux 实现 + 非 Linux 桩)。
//   - IPC/托盘 UI/updater/打包签名 = 后续刀(daemon 先 headless 可跑)。
//   - IdP 用户认证入网(LZ11)= 后续刀;本刀入网复用激活码 ZTP(enroll.FetchCert)。
package agentd

import (
	"net"

	"github.com/ikuai8/sase/internal/dptunnel"
)

// NetCapture 是流量接管的平台壳接口(L2 §3.1):壳提供真 TUN/虚拟网卡 + 路由/DNS 接管,
// 核心经 PacketIO 接缝消费(零改复用 dptunnel.Endpoint 双 pump)。
//
//   - OpenAdapter 返回的 PacketIO **直接是 dptunnel.PacketIO**(ReadPacket/WritePacket/Close),
//     核心 tunnel 模块零改即可消费(接缝复用,L2 §3.2)。
//   - ConfigureRoutes 把内部应用 CIDR 路由指向 TUN(split-tunnel 白名单,只接管受保护资源,L2 §3.3)。
//   - ConfigureDNS 接管租户内部域名后缀的解析(split-DNS;本刀最小,可只 log/桩,L2 §3.3)。
//   - Close 须恢复原 DNS/路由(防崩溃留下断网,L2 §3.5 风险)。
type NetCapture interface {
	OpenAdapter() (dptunnel.PacketIO, IfInfo, error)
	ConfigureRoutes(cidrs []*net.IPNet) error
	ConfigureDNS(rules DNSRules) error
	Close() error
}

// IfInfo 是壳创建的虚拟网卡信息(核心据此配 IP/MTU、日志可观测)。
type IfInfo struct {
	Name string // 设备名(如 tun0 / utunN / wintun 适配器名)
	MTU  int    // 内层 MTU(壳按外层 PMTU - 封装开销扣减;0=壳未设,核心不强求,L2 §3.2 LZ5 待实测)
}

// DNSRules 是 split-DNS 接管策略(L2 §3.3):核心只给「内部域名后缀 + overlay 映射」,壳逐 OS 实现接管。
// 本刀最小:仅携内部域名后缀列表;overlay 映射/上游 PoP DNS 转发为后续刀。
type DNSRules struct {
	InternalSuffixes []string // 租户内部域名后缀(命中→走隧道解析;公网旁路),入网/实时通道下发
}

// PostureProbe 是设备姿态采集的平台壳接口(L2 §3.1/§3.8):壳调系统 API 取值填 PostureFacts,
// 核心只调度与上报。返回 err 表示采集整体失败(核心降级:上报「未知」字段,fail-closed,绝不崩)。
type PostureProbe interface {
	Collect() (PostureFacts, error)
}

// SystemIntegration 是安装/权限/通知的平台壳接口(L2 §3.1)。本刀**最小**:Notify(状态通知)+
// Autostart(开机自启登记)桩 + OpenBrowser(IdP 入网时拉起系统默认浏览器,Slice80);Elevate/安装/托盘 IPC = 后续刀。
type SystemIntegration interface {
	Notify(title, body string) error // 向用户通知(托盘气泡等;本刀壳可 log)
	Autostart(enable bool) error     // 登记/取消开机自启(本刀壳可 log/桩)
	// OpenBrowser 拉起系统默认浏览器到 url(IdP 用户认证入网,Slice80;linux=xdg-open、darwin=open、
	// windows/其它=后续刀桩/log)。返回 err 不致命:daemon 可降级为打印 url 让用户手动打开。
	OpenBrowser(url string) error
}
