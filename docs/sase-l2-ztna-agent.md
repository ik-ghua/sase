# 真 OS 级 ZTNA Agent L2 组件软件架构

> **状态:** L2 组件设计 / 待评审
> **版本:** v0.1
> **日期:** 2026-05-30
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **层级与上承:** L2 组件设计,对象为 **ZTNA 端点 Agent**(装用户设备的我方跨平台软件)。本文是客户端 Agent / Connector L2(`sase-l2-client-agent-connector.md`)中 **「端点 Agent」一形态的内部实现深挖**——上位 L2 已定形态边界(三形态)、共享核心+薄壳骨架、姿态 schema(LI5/LP4)、入网/选路/加密栈/持续验证的**口径**;本文不重定那些,而是把它们落到**真 OS 级可编码的内部模块、各 OS 系统 API、流量接管/分流/守护/打包/姿态采集的具体选型**,并收口上位 L2 留下的 Agent 侧悬留点(LA2 移动端范围、LA3 姿态字节编码+采集 API、LA8 远程升级)。
>
> 上承 L1 `sase-architecture-design.md` v0.6 的 **3.8(轨道一 ZTNA:Agent 跨平台共享核心+薄壳、设备姿态、持续验证、应用按需授权)**、3.6(split-DNS、内部域名解析)、3.5(设备证书、私钥本地生成)、3.11(`Enroll` 协议、数据通道)、3.13(RTT 选路、不硬编码 IP)、3.2(租户绑定)。
>
> **衔接:** 客户端 Agent/Connector L2(上位,本文深挖其 Agent 形态)、ZTNA 接入硬化 L2(`sase-l2-ztna-access-hardening.md`:SPA 敲门客户端、终端实时控制通道客户端)、身份子 L2(enroll=令牌交换、短 TTL 凭证、静默刷新)、数据面隧道 L2(`sase-l2-data-plane-tunnel.md`:dptunnel UDP 数据报隧道与 `PacketIO`/`OpenTUN` 接缝)、PoP 单机编排 L2(隧道在 PoP 终结、PEP 求值)、策略编译器子 L2(posture 作 subject 选择器)、信任/风险引擎 L2(姿态/风险信号)、国密选型(隧道/敲门加密待 PoC-G)。
>
> **as-built 对齐(现状,不回避):** 现 `cmd/agent` 是**一次性 CLI echo 桩**(`internal/agent.Access`:`GET /access?app=&path=` 跑一次打印即退,无 TUN / 无守护 / 无姿态采集);`internal/agent.Session`(`control.go`)已是**会话状态 + 终端实时控制通道客户端**(连 `control.Hub`、收 revoke/recheck_posture/reauth、本地弃用凭证)的最小骨架;`internal/cred`(算法可插拔 Ed25519↔SM2)、`internal/enroll`(`FetchCert`/`RenewCert`/`CertRotator`/`RunRenewLoop`,设备本地生成 CSR、私钥不离设备、ZTP 租户绑定证书、热轮换)、`internal/dptunnel`(`PacketIO` 抽象 + Linux `OpenTUN` + `Endpoint` 双 pump + UDP 数据报会话)均已编码且被 `cmd/cpe` 用于 SD-WAN。**真 OS 级 Agent = 把这些既有件(cred / enroll / dptunnel / control)组装成长驻多平台守护进程,补 TUN 接管 / split-tunnel / split-DNS / 姿态采集 / 选址 / 打包 / 托盘**——大量是组装与端侧新件,非从零造密码学/隧道。本文 §3 在每个设计点标注「复用既有 / 新件」。
>
> **范围:** 流量接管(各 OS TUN/虚拟网卡 + netstack vs 内核 TUN)、共享核心+薄壳的内部模块切分、split-tunnel/split-DNS、Agent→PoP 数据面承载、守护进程+IPC+托盘、凭证静默刷新+撤销下推、PoP 选址+节点发现、姿态采集(姿态字段集单一来源+各 OS API+反作弊)、打包/签名/自动更新、enroll/ZTP 首次入网;分期建议(MVP 先做哪两平台、必做 vs 后置)、与既有契约对齐与新增 api/proto。
>
> **不含(明确边界):** 加密算法选定(国密 PoC-G,算法敏捷不阻塞本文);PEP 求值(PoP L2,**数据面权威不变**);凭证签发(控制面 `identity`);各 OS 壳的**逐行实现**(实施期);Agentless(上位 L2 3.5);Connector(上位 L2 3.4);SPA/实时通道**机制本体**(接入硬化 L2,本文只定 Agent 侧客户端如何接);移动端**逐平台实现**(本文给范围结论);字节级 schema(api/proto,本文给逻辑结构与需新增的 proto);**写代码/搭骨架(须另行授权)**。
>
> **设计先行:** 含架构与机制说明,**不写代码**。每个关键决策配 ① 依据 ② 备选及落选原因 ③ 可行方案;能量化就量化;无数据标「待确认 / 待实测 / 待国密」,**绝不编造**。

---

## 目录

- 一、背景
- 二、目标(可衡量)
- 三、设计
  - 3.1 Agent 内部模块全景(共享核心 + 薄壳的落地切分)
  - 3.2 流量接管:各 OS TUN/虚拟网卡 + netstack vs 内核 TUN ★
  - 3.3 split-tunnel / split-DNS(按目的分流) ★
  - 3.4 Agent→PoP 数据面承载(承接 W1 HTTP 隧道演进 → 任意 TCP)★
  - 3.5 守护进程 + IPC + 托盘 UI + 用户登录态
  - 3.6 会话凭证静默刷新 + 撤销实时下推(复用 enroll/CertRotator + control.Hub)
  - 3.7 PoP 选址:RTT 探测 + 节点动态发现(不硬编码 IP)
  - 3.8 设备姿态采集:姿态字段集单一来源 + 各 OS API + 进 claim 同源 + 反作弊 ★
  - 3.9 打包 / 代码签名 / 自动更新
  - 3.10 enroll / ZTP 首次入网(复用现 enroll)
  - 3.11 契约与衔接(收口上位 L2 悬留点 + 新增 api/proto)
- 四、分期建议(MVP 先做哪两平台 + 必做 vs 后置 + XL 拆解)
- 五、风险
- 六、结论与衔接
- 附录:待确认 / 待实测 / 待国密

---

## 一、背景

**ZTNA 是「面向人替代 VPN」**(L1 3.8),其端侧落点是装在用户设备上的 Agent——它要(a)透明接管去往受保护应用的流量、(b)持短 TTL 会话凭证经隧道送到 PoP 由 PEP 裁决、(c)持续采集并上报设备姿态、(d)在多 OS 上长驻运行且静默自更新。

**现状缺口(as-built,见文首对齐):** `cmd/agent` 只是一次性 CLI——发一个 `GET /access` 打印结果就退,没有 TUN、没有守护进程、没有姿态采集,姿态是不可信自报字符串。这对早期切片验证「凭证→PEP→撤销」链路足够,但**离真实可演示的「替代 VPN」差一个真 OS 级 Agent**。按 MVP 路线图(`sase-mvp-roadmap.md`),真 OS 级 Agent 是 **ZTNA MVP 的最大长杆(XL、net-new)**:多平台壳维护、TUN/split-tunnel 在真实终端(VPN 冲突/防火墙/权限/EDR 拦截)坑多,从近乎零到一。

**为何先出设计(项目铁律「设计先行、审核后编码」):** 真 Agent 涉及 OS 内核网络栈接管、跨平台抽象、代码签名/分发、姿态采集的反作弊边界——这些决策一旦编码就难返工(尤其 TUN 库选型、netstack vs 内核 TUN、IPC 形态、姿态字段单一来源)。上位客户端 L2(`sase-l2-client-agent-connector.md`)已定**形态与口径**但**未定真 OS 级内部实现**,故本文为编码定型。

**上位约束(本文不重定,只承接):** 形态边界、共享核心+薄壳骨架、姿态 schema 字段集、enroll/RTT/不硬编码 IP/加密敏捷/持续验证口径——均见 `sase-l2-client-agent-connector.md` §3.1–3.9。SPA 敲门与终端实时通道的**机制本体**见接入硬化 L2;本文只定 Agent 侧客户端如何接它们。

---

## 二、目标(可衡量)

1. **真 OS 级守护进程**:Agent 长驻(开机自启 + 登录态绑定),用户登录后透明接管去往受保护应用的流量,无需用户手动连/断(对比现一次性 CLI)。
2. **流量接管选型定型**:各 OS 的虚拟网卡方案(Windows wintun、macOS utun、Linux tun)与「用户态 netstack vs 内核 TUN」二选一**给出选型 + 依据**,并明确与现 `dptunnel.PacketIO`/`OpenTUN` 接缝的复用边界。
3. **按目的分流**:split-tunnel(应用 CIDR / 路由)+ split-DNS(内部域名劫持转发、公网域名旁路)定型,**默认仅接管受保护资源流量、不全量接管**(降低与本地网络/其它 VPN 冲突)。
4. **数据面承载演进路径清晰**:承接 W1 的 ZTNA 数据面通用化(HTTP GET-only → 任意 HTTP 方法/头/body/多路复用),再到**任意 TCP**,给出 Agent 侧承载形态与里程碑;mTLS(设备级)+ 会话凭证(app 层)双层不破。
5. **凭证静默刷新 + 撤销秒级下推**:近过期无感续期(复用 `enroll.CertRotator`/`RunRenewLoop` 模式 + 身份子 L2 令牌刷新),撤销经终端实时通道(复用 `control.Hub`)秒级到端;**判定/撤销权威仍在 PoP**,端侧仅提速。
6. **PoP 选址去硬编码**:RTT 实测选最近 PoP + 经控制面/域名动态发现节点列表;云 BGP IP 迁自建时 Agent 无需改配。
7. **姿态字段集单一来源**:落实上位 L2 §3.3 的姿态字段集(9 逻辑项→10 proto 字段,计数口径详 §3.8;`os`/`os_version`/`patch_level`/`disk_encryption`/`av_edr`/`firewall`/`screen_lock`/`jailbroken_rooted`/`device_cert_valid`/`agent_version`)为 **api/proto 单一来源**,各 OS 系统 API 采集映射 + 进凭证 posture claim 同源 + 反作弊定位(哪些自报、哪些可由设备证书/系统签名背书)。
8. **打包/签名/静默升级**:各 OS 安装包 + 代码签名 + 灰度静默升级通道,给出选型与分期。
9. **首次入网复用现 enroll**:激活码→本地 CSR→租户绑定证书(`enroll.FetchCert`),私钥本地生成永不离开(L1 3.5)。

**非目标:** 加密算法选定(PoC-G);PEP/数据面实现(PoP);凭证签发(控制面);各 OS 壳逐行实现;Agentless / Connector;SPA/实时通道机制本体(接入硬化 L2);移动端逐平台实现;字节 schema;EDR/DLP 终端本地管控本体(后置安全栈,接入硬化 L2 已划界);写代码。

---

## 三、设计

### 3.1 Agent 内部模块全景(共享核心 + 薄壳的落地切分)

**背景** 上位 L2 §3.2 已定「共享 Go 核心 + 薄平台壳」的**骨架与依据**(核心逻辑跨平台一致、只有碰系统的部分按平台薄封装,把维护成本压到薄壳)。但「哪些模块在核心、壳暴露什么接口、模块间数据流」未落到可编码粒度。本节定之。

**目标** 给出 Agent 内部模块清单、每模块归属(核心/壳/复用既有)、模块间数据流与平台抽象接口。

**设计 —— 模块清单(★=本文新件;复用=既有 internal 包组装)**

| 模块 | 归属 | 职责 | 复用/新件 |
|------|------|------|-----------|
| `enrollment`(入网) | 核心 | 激活码→本地 CSR→租户绑定证书;首次入网 | **复用** `internal/enroll`(`FetchCert`/`CertRotator`) |
| `credstore`(凭证持有) | 核心 | 持短 TTL 会话凭证;静默刷新调度;撤销本地弃用 | **复用** `internal/cred`(验证侧)+ `enroll.RunRenewLoop` 模式 + `agent.Session` |
| `controlchan`(实时通道客户端) | 核心 | 连 `control.Hub`,收 revoke/recheck/reauth/配置/重选路,事件上报姿态 | **复用** `internal/agent.Session.RunControlChannel`(扩指令集,3.6) |
| `popselect`(选址) | 核心 ★ | RTT 探测候选 PoP、选最近、节点发现、动态切换 | **新件**(机制定型,3.7) |
| `tunnel`(数据面隧道客户端) | 核心 | 经隧道把接管流量送 PoP;承接 W1 演进 | **复用+扩** `dptunnel.Endpoint`/`Session` + 数据面承载(3.4) |
| `flowmgr`(分流) | 核心 ★ | split-tunnel 路由判定 + split-DNS 域名劫持/旁路 | **新件**(3.3) |
| `netcapture`(流量接管接缝) | 核心↔壳 ★ | 平台无关接缝(`PacketIO` 兼容);壳提供真 TUN/虚拟网卡 | **复用接缝** `dptunnel.PacketIO`;壳侧 TUN 新件(3.2) |
| `posture`(姿态采集) | 核心(字段)↔壳(系统 API) ★ | 核心定 姿态字段集 schema 与上报调度;壳调系统 API 取值 | **新件**(字段集复用上位 §3.3;采集 API 各 OS 新件,3.8) |
| `daemon`(守护进程) | 核心 ★ | 长驻、状态机、IPC server、健康看护 | **新件**(3.5) |
| `ipc`(壳↔守护通信) | 核心↔壳 ★ | 守护与托盘/UI/CLI 的本机 IPC | **新件**(3.5) |
| `updater`(自动更新) | 核心↔壳 ★ | 版本检查、下载、验签、交壳安装 | **新件**(3.9) |
| `tray/ui`(托盘 UI) | 壳 ★ | 状态展示、登录入口、连/断、日志 | **新件**(各 OS,3.5) |
| `platform`(平台壳抽象) | 壳 ★ | 网卡接管/权限/自启/姿态 API/安装 的平台实现 | **新件**(接口最小化,3.1/3.2/3.8) |

- **核心↔壳接口最小化(上位 §3.2 风险 RA1 缓解):** 壳只实现一组窄接口,候选:
  - `NetCapture`:`OpenAdapter() (PacketIO, ifInfo, error)` / `ConfigureRoutes(splitTunnelRules)` / `ConfigureDNS(splitDNSRules)` / `Close()`——**返回的 `PacketIO` 直接是 `dptunnel.PacketIO`**(`ReadPacket`/`WritePacket`/`Close`),核心 `tunnel` 模块零改即可消费(接缝复用,3.2)。
  - `PostureProbe`:`Collect() (PostureFacts, error)`——壳调系统 API 填 姿态字段集,核心只调度与上报(3.8)。
  - `SystemIntegration`:`InstallAutostart()` / `Elevate()` / `TrayNotify()` 等安装/权限/通知(3.5/3.9)。
- **数据流(一次受保护访问):** 用户进程发包 → 壳虚拟网卡(`netcapture`)→ 核心 `flowmgr` 判定命中 split-tunnel 规则 → 进 `tunnel`(`dptunnel.Endpoint`)→ Seal → 经选定 PoP(`popselect`)的隧道 → PoP 解封 → PEP 用凭证(`credstore`)裁决 → 应用。旁路流量(未命中规则)由 `flowmgr` 直接放行本地协议栈。
- **依据:** 既有 `internal/{cred,enroll,dptunnel,agent,control}` 已覆盖凭证/入网/隧道/实时通道的核心机制(文首对齐已列),真 Agent 是「组装 + 补端侧新件(选址/分流/接管壳/姿态采集/守护/打包)」,而非重造——按现有包边界切核心模块,新件集中在「碰 OS 的壳」与「端侧编排(选址/分流/守护/更新)」。
  - 备选:推倒现 `internal/agent`/`dptunnel` 另起 Agent 专用栈。落选:重复造隧道/凭证、与 SD-WAN CPE 行为漂移、违背 L1「地基统一」(SD-WAN CPE 与 ZTNA Agent 共用 dptunnel/enroll 底座)。
  - 备选:壳里塞业务逻辑(选路/分流也按平台写)。落选:逻辑重复 + 行为漂移 + 维护爆炸(上位 §3.2 已否)。

**风险** 壳接口设计不当导致核心被迫感知平台细节 → 接口以「能力」而非「实现」抽象(返回 `PacketIO`/`PostureFacts` 这类平台无关类型);核心↔壳数据流跨 goroutine/进程边界(守护进程,3.5)→ 接口同步语义清晰 + 错误可观测。

**结论** Agent = 复用既有 `cred/enroll/dptunnel/control` 组装的共享核心(入网/凭证/隧道/实时通道)+ 端侧新件(选址/分流/守护/更新)+ 各 OS 薄壳(`NetCapture`/`PostureProbe`/`SystemIntegration` 三窄接口);壳返回平台无关类型,维护成本压在窄壳。

---

### 3.2 流量接管:各 OS TUN/虚拟网卡 + netstack vs 内核 TUN ★

**背景** 真 Agent 必须透明接管去往受保护应用的流量。现 `dptunnel` 已有 Linux 内核 TUN(`OpenTUN` 经 `/dev/net/tun`+TUNSETIFF,`tun_linux.go`)+ 平台无关 `PacketIO` 接缝,被 `cmd/cpe`(SD-WAN)使用;但**无 Windows/macOS TUN**,且需决定「用户态 netstack(gVisor)还是内核 TUN」。

**目标** 定各 OS 虚拟网卡方案与「netstack vs 内核 TUN」选型,明确与现 `PacketIO`/`OpenTUN` 接缝复用。

**设计 —— 各 OS 虚拟网卡**

| OS | 虚拟网卡 | 接缝 | 权限 | 备注 |
|----|---------|------|------|------|
| **Windows** | **wintun**(WireGuard 项目维护的内核态 TUN 驱动,公开开源,LGPL/独立许可) | 壳封装为 `PacketIO`(`ReadPacket`/`WritePacket`) | 安装期装驱动(需管理员/驱动签名);运行期 SYSTEM 服务 | 经 `wintun.dll` 收发 L3 包;社区成熟、WireGuard 同源 |
| **macOS** | **utun**(系统内建,`SYS_CONTROL`/`PF_SYSTEM` socket + `UTUN_CONTROL_NAME`) | 壳封装为 `PacketIO` | 需 Network Extension 权限(见下)或 root daemon | 无第三方驱动;系统原生 |
| **Linux** | **tun**(现 `OpenTUN`,`/dev/net/tun`+TUNSETIFF) | **已是 `PacketIO`,直接复用** | CAP_NET_ADMIN | as-built,SD-WAN CPE 在用 |

- **macOS 接管路径二选一(给选型):**
  - **(选)root 守护进程 + utun**(直接开 utun,配路由)——**MVP 选此**。依据:无需 App Store / Network Extension entitlement 审批链路,与 Windows SYSTEM 服务 + Linux daemon 形态一致(都是特权守护进程直开 TUN),复用 `PacketIO` 最直接;企业自管设备分发(非 App Store)是 SASE 主场景。
  - (备选)**Network Extension(`NEPacketTunnelProvider`)**——落选(MVP):需 Apple 审批的 NE entitlement、provider 跑在受限沙箱(扩展进程,内存/能力受限)、调试链路长;**但它是 macOS「系统 VPN 列表/按需 VPN/锁屏前连接」的官方路径**,后置(若需深度系统集成/上架再做,附录 LZ2)。
- **netstack(gVisor `tcpip`)vs 内核 TUN —— 核心选型:**
  - **选:内核 TUN(各 OS 原生虚拟网卡)+ L3 包隧道**(与现 `dptunnel` 一致)。
    - 依据:① **复用既有 `dptunnel` 数据面**(`PacketIO`/`Endpoint`/`Session`/UDP 数据报 + FEC),不另造用户态 TCP/IP 栈;② 承载**任意 IP 协议**(TCP/UDP/ICMP),天然支持「未来任意 TCP/任意应用」(目标 4);③ 内核栈性能与正确性久经验证(MTU/分片/校验和/拥塞由 OS 处理)。
    - 量化锚:现 `dptunnel` 在 PoC VM 无加速单核 seal ChaCha20 4.9 Gbps/核(`docs/sase-l2-data-plane-tunnel.md`),内核 TUN 路径不引入额外用户态协议栈开销。
  - 备选:**用户态 netstack(gVisor)**——在用户态实现 TCP/IP,把接管流量转成上层 socket(类「tun2socks」)。落选:① 自带一套用户态 TCP/IP 栈,维护面大、与既有 `dptunnel` L3 隧道范式割裂(变成 L4 代理);② 性能与正确性需自证(MTU/重组/拥塞);③ 优势(不需内核驱动/权限)对「企业自管 + 特权守护进程」场景价值有限。**保留为窄场景候选**:无管理员权限的 BYOD(此时本应走 Agentless,上位 §3.5),或 wintun 驱动签名受阻的降级路径(附录 LZ7)。
- **与现接缝复用边界(明确):** `dptunnel.PacketIO` 接口(`ReadPacket`/`WritePacket`/`Close`)是**平台无关接缝**;Windows/macOS 壳各实现一个 `PacketIO`(内部分别 wintun.dll / utun socket),与现 Linux `tunIO` 平级;核心 `tunnel` 模块、`Endpoint` 双 pump **零改**即可消费三平台。现 `tun_other.go`(非 Linux 占位)由真实现替换。
- **MTU 与封装开销:** 隧道内层 MTU 须扣封装开销——现 `dptunnel` 注释:帧头 8B + body 前缀 10B + AEAD tag 16B ≈ 34B(`endpoint.go`),Agent 配虚拟网卡 MTU 时按外层 PMTU - 34B - UDP/IP 头扣减(具体值待实测,附录 LZ5)。

**风险** wintun 驱动签名/分发(Windows 要求驱动签名)→ 走 EV 代码签名 + 驱动签名流程(3.9);macOS root daemon 与未来 NE 路径分叉 → 接口抽象在 `PacketIO`,底层切换不动核心;与本地其它 VPN/防火墙/EDR 冲突(真实终端坑)→ split-tunnel 默认最小接管(3.3)+ 兼容矩阵实测(附录 LZ4)。

**结论** 流量接管用各 OS 原生内核 TUN/虚拟网卡(Win wintun / macOS utun via root daemon / Linux tun 复用 `OpenTUN`),统一为 `dptunnel.PacketIO` 接缝、核心零改消费;**选内核 TUN + L3 包隧道**(复用既有 dptunnel、承载任意 IP、性能正确性已验)而非用户态 netstack(后者保留为无权限/驱动受阻的降级窄场景)。

---

### 3.3 split-tunnel / split-DNS(按目的分流)★

**背景** L1 3.6 split-DNS、上位 L2 §3.6 split-tunnel/split-DNS 已定口径(入网拉取租户内部域名 + 应用→连接器映射 + split-tunnel 规则;接管内部域名→overlay→隧道→PoP→连接器→应用;公网正常解析或经 SWG)。但**分流判定的数据结构、DNS 劫持的具体策略、默认接管范围**未定。本节定之。

**目标** 定 split-tunnel 路由判定与 split-DNS 劫持/旁路策略,明确默认接管范围。

**设计**
- **默认最小接管(关键原则):** Agent **默认只接管去往受保护资源的流量**(split-tunnel 白名单模式),其余(公网、本地 LAN、其它 VPN)旁路本地协议栈。
  - 依据:全量接管(default route 抢占)易与本地网络/打印机/其它 VPN/视频会议冲突,且把无关流量绕经 PoP 增延迟与带宽成本;ZTNA 按应用授权,本就只需接管受保护资源(L1 3.8)。
  - 备选:全量接管(full tunnel)。落选:冲突多、延迟与带宽浪费;**保留为可选模式**(高合规租户要求「全流量经 PoP 审计/SWG」时按租户配置开启,附录 LZ3)。
- **split-tunnel 规则(入网/实时通道下发,3.10/3.6):** 规则集 = 应用 CIDR 列表 + 内部域名列表 + (可选)应用标识;`flowmgr` 对每个出向包/DNS 查询判定:
  - **目的 IP ∈ 接管 CIDR** → 进隧道(经虚拟网卡路由,壳 `ConfigureRoutes` 把这些 CIDR 路由指向 TUN)。
  - 否则 → 旁路。
  - 判定结构复用 `dptunnel` 已有的 **LPM(最长前缀匹配)radix trie**(`internal/dptunnel/lpm.go`,O(地址位宽);PoP 侧站点选路已用)——Agent 侧 split-tunnel 判定同构,可复用该数据结构(避免另造)。
- **split-DNS 劫持(域名维度,先于 IP):** 很多内部应用只有内部域名(无固定公网 IP),故须在 DNS 层先劫持:
  - Agent 在壳侧把系统 DNS 指向**本机 DNS 代理**(`flowmgr` 内,壳 `ConfigureDNS`);
  - 查询命中**租户内部域名后缀**(入网下发)→ Agent **返回 overlay IP**(隧道内可路由的虚拟地址)或转发到 PoP 侧 DNS 解析,后续该 overlay IP 落入接管 CIDR → 进隧道;
  - 公网域名 → 透传系统原解析(或经 SWG,L1 3.6)。
  - **依据:** 内部应用域名优先(L1 3.6 屏蔽内网拓扑——Agent/PoP 不暴露内网真实 IP,用 overlay IP);split-DNS 精确匹配内部域名后缀避免误劫持公网。
  - 备选:不做 DNS 劫持、纯 IP split-tunnel。落选:内部应用无固定公网 IP 时无法分流;且暴露内网 IP(违 L1 3.6)。
- **平台 DNS 接管差异(壳处理):** Windows(NRPT 名称解析策略表 / 接口 DNS)、macOS(`/etc/resolver` 或 Network Extension DNS proxy / SystemConfiguration)、Linux(systemd-resolved / resolv.conf)——壳 `ConfigureDNS` 各自实现,核心只给「内部域名后缀 + overlay 映射策略」。
- **冲突/回退:** 系统已有 DNS 策略冲突(企业既有内网 DNS)→ 按后缀精确匹配只接管租户内部域名后缀,不夺全局 DNS;Agent 退出/崩溃 → 壳须**恢复原 DNS/路由**(守护进程看护 + 卸载钩子,3.5)。

**风险** DNS 劫持误伤公网/本地解析 → 后缀精确匹配 + 仅租户内部域名;split-tunnel 规则与本地路由冲突 → 默认最小接管 + 明确优先级;Agent 崩溃留下劫持的 DNS/路由(断网)→ 守护进程 watchdog + 退出恢复 + 系统级 cleanup(3.5,附录 LZ4)。

**结论** 默认最小接管(白名单 split-tunnel,全量为可选);split-tunnel 用 CIDR LPM(复用 `dptunnel/lpm.go`)判定、命中进隧道;split-DNS 在 DNS 层先劫持租户内部域名后缀→overlay IP(屏蔽内网拓扑)、公网旁路;各 OS DNS/路由接管在壳、核心只给策略;崩溃/退出须恢复原配置。

---

### 3.4 Agent→PoP 数据面承载(承接 W1 HTTP 隧道演进 → 任意 TCP)★

**背景** 现 ZTNA 数据面是 `GET /access?app=&path=` 的 HTTP handler(`pop/ingress.go`,无 body/方法/流式),Agent 是一次性 CLI 调它(`internal/agent.Access`)。MVP 路线图 W1 把 ZTNA 数据面通用化(GET-only → 任意 HTTP 方法+头+body + 多路复用),目标终态是承载**任意 TCP**(真 Web 业务、任意应用)。真 Agent 的数据面承载须与此演进对齐。

**目标** 定 Agent 侧数据面承载形态与里程碑,mTLS(设备级)+ 会话凭证(app 层)双层不破。

**设计 —— 三段演进(里程碑)**

| 阶段 | 承载形态 | Agent 侧 | 上承 |
|------|---------|---------|------|
| **现状(as-built)** | `GET /access?app=&path=` over mTLS | `agent.Access` 一次性 CLI | — |
| **里程碑 A(承接 W1)** | 任意 HTTP 方法/头/body + 连接多路复用 over mTLS | Agent 把 TUN 截获的 **HTTP(S) 流**转成上层请求送 PoP(应用级反代承载) | W1(ZTNA 数据面通用化) |
| **里程碑 B(目标终态)** | **任意 TCP**(L3/L4 包经隧道,PoP 侧建到应用的 TCP) | Agent 经 **TUN + `dptunnel` L3 隧道**把任意 TCP/UDP 包送 PoP,PoP 解封后到应用 | 本文 3.2 内核 TUN 选型 |

- **选型:Agent 数据面随里程碑收敛到「TUN + dptunnel L3 包隧道」(里程碑 B 为终态)**:
  - 依据:① 内核 TUN(3.2)接管的是 **L3 包**,最自然的承载就是 L3 包隧道(`dptunnel`),不必在 Agent 内拆出 HTTP 语义;② 承载任意 TCP/UDP(非仅 HTTP),覆盖 SSH/RDP/数据库/私有协议等非 Web 应用(L1 3.8「全应用」);③ **复用 SD-WAN 已跑通的 `dptunnel` 数据面**(`Endpoint`/`Session`/握手 `tunhandshake`),地基统一。
  - **里程碑 A 仍有价值(过渡 + Agentless 对称):** W1 的 HTTP 通用化让 ZTNA 能跑真实 Web 业务、是真 Agent 的「对端前提」(PoP 侧能承载真实 HTTP),也是 Agentless(浏览器→PoP 反代)的承载;Agent 在 A 阶段可先以「应用级 HTTP 承载」演示,B 阶段切到 L3 包隧道覆盖任意 TCP。
  - 备选:Agent 永久走应用级 HTTP 代理(SOCKS/HTTP proxy 模式,不接管 L3)。落选:非 HTTP 应用需逐协议适配、不通用;但**保留为降级**(无 TUN 权限时的 proxy 模式,附录 LZ7)。
- **双层认证不破(贯穿):** 隧道传输层 **mTLS(设备级,role:device 证书,W9 租户绑定)**——Agent 用 `enroll` 签发的设备证书(`CertRotator`)建隧道(`tunhandshake.Dial` 已从证书取 tenant/identity);**会话凭证(app 层身份)** 经隧道送 PoP 由 PEP 求值(`cred`)。两层分工同现状,不因承载演进改变。
- **握手复用:** SD-WAN 已用 `internal/tunhandshake`(互认证 TLS1.3 + RFC5705 密钥导出派生 `dptunnel.Session`,非国密档;国密 TLCP 待 PoC-G);Agent→PoP 隧道复用同握手层(身份权威落在证书+密钥,srcAddr 仅解复用)。
- **国密敏捷:** 隧道 AEAD(ChaCha20-Poly1305 ↔ SM4-GCM)与握手(TLS1.3 ↔ TLCP)算法敏捷,待 PoC-G(上位 §3.7;不阻塞本文 Agent 结构)。

**风险** 里程碑 A→B 切换期两套承载并存 → 以隧道能力协商(PoP 通告支持的承载),Agent 择优、向后兼容;任意 TCP 经 L3 隧道的 PoP 侧出站(PoP 替用户建到应用的 TCP)涉及 PoP NAT/连接跟踪 → 属 PoP L2(本文只定 Agent 侧送 L3 包);UDP 应用(DNS/QUIC/RTP)经隧道 → `dptunnel` UDP 数据报天然承载,但需 PoP 侧支持(PoP L2)。

**结论** Agent 数据面随里程碑收敛到「内核 TUN + `dptunnel` L3 包隧道」(终态承载任意 TCP/UDP),里程碑 A 承接 W1 的 HTTP 通用化作过渡 + Agentless 对称;复用 SD-WAN 已跑通的 `dptunnel`+`tunhandshake`;mTLS(设备级)+ 会话凭证(app 层)双层认证不破;加密敏捷待 PoC-G。

---

### 3.5 守护进程 + IPC + 托盘 UI + 用户登录态

**背景** 现 Agent 是跑一次即退的 CLI;真 Agent 须长驻(开机自启)、与用户登录态绑定、有状态展示与本机控制入口。各 OS 的服务模型/IPC/托盘差异大。

**目标** 定守护进程形态、守护↔壳 IPC、托盘 UI 与用户登录态绑定。

**设计 —— 特权守护进程 + 非特权托盘(双进程模型)**
- **守护进程(特权,长驻):** Windows = SYSTEM 服务;macOS = root `launchd` daemon;Linux = systemd service(root / CAP_NET_ADMIN)。
  - 承载:`netcapture`(开 TUN 需特权)、`tunnel`、`flowmgr`、`credstore`、`controlchan`、`posture` 调度、`popselect`、`updater` 下载+验签;开机自启。
  - 依据:开 TUN/配路由/配 DNS 需特权;长驻独立于用户登录(开机即起、用户切换不断);与 SD-WAN CPE 守护进程形态一致。
- **托盘/UI(非特权,用户态):** 状态展示(已连/未连/PoP/上次姿态)、登录入口(触发 enroll/OIDC,跳浏览器)、连/断、日志查看;每个登录用户一个托盘进程。
  - 备选:守护进程直接画 UI。落选:特权进程画 UI 攻击面大(GUI 库漏洞→提权)、且服务进程难访问用户桌面会话(Windows session 0 隔离)。
- **守护↔托盘 IPC(本机):** 候选 **本机 socket + 长度前缀帧 / gRPC over UDS**(Windows 用 named pipe / localhost loopback)。
  - **鉴权(关键,防本机其它用户/进程冒充控制守护进程):** UDS 文件权限 + peer 凭证校验(`SO_PEERCRED` Linux / `LOCAL_PEERCRED` macOS / named pipe 客户端 token Windows);只接受**当前登录用户**的托盘连接;敏感操作(改配置/重入网)经守护进程鉴权。
  - 依据:守护进程特权,IPC 是提权面;须校验对端身份。
  - 备选:无鉴权 localhost TCP。落选:本机任意进程可冒充控制(提权/绕过)。
- **用户登录态绑定:** Agent 的「用户身份」来自 enroll/OIDC 登录(身份子 L2),非 OS 登录用户;但托盘随 OS 用户会话起停,守护进程维护「当前是否有已认证用户会话 + 其凭证」。用户注销/切换 → 守护进程按策略保留或清除会话凭证(待确认,LZ6:是否锁屏即降权)。
- **存活看护(watchdog):** 守护进程崩溃 → OS 服务管理器(launchd/systemd/SCM)自动重启;**重启时须恢复 split-DNS/路由**(防崩溃留下断网,3.3 风险);托盘崩溃不影响数据面(数据面在守护进程)。

**风险** session 0 隔离(Windows 服务不能直接弹 UI)→ 双进程(服务 + 用户态托盘 via IPC);IPC 提权面 → peer 凭证校验 + UDS 权限;崩溃留下劫持配置断网 → watchdog + 退出/重启恢复 + 系统级 cleanup;用户切换/注销凭证去留 → 策略待确认(LZ6)。

**结论** 双进程模型:特权守护进程(各 OS 服务,长驻、承载数据面/凭证/接管)+ 非特权用户态托盘(状态/登录/控制);守护↔托盘 IPC 经本机 socket/UDS/named pipe **带 peer 凭证鉴权**;用户登录态由 enroll/OIDC 决定、托盘随 OS 会话起停;watchdog + 退出恢复防断网。

---

### 3.6 会话凭证静默刷新 + 撤销实时下推(复用 enroll/CertRotator + control.Hub)

**背景** 上位 L2 §3.8 定持续验证口径(短 TTL 凭证、静默刷新、姿态/风险上报触发重评,撤销在控制面/PoP)。as-built 已有:`enroll.CertRotator`/`RunRenewLoop`(设备**证书**热轮换)、`agent.Session.RunControlChannel`(实时通道收 revoke/recheck_posture/reauth)、`control.Hub`(控制面侧下推)。本节定 Agent 侧两类刷新(设备证书 + 会话凭证)与撤销下推的落地。

**目标** 定 Agent 侧设备证书续期、会话凭证刷新、撤销秒级下推的机制与既有件复用。

**设计 —— 两条独立的「续期/刷新」链(勿混淆)**
1. **设备证书续期(transport 层,已 as-built):** `enroll.RunRenewLoop` 在剩余有效期 < lead 时经 mTLS(出示当前证书)POST `/renew` 换延期证书,`CertRotator` 原子热替换(在用连接不受影响,下次重连用新证书)。**Agent 直接复用**;续期被拒(设备被 admin 撤销)→ 隧道下次重握手失败 → Agent 触发重入网/告警。
2. **会话凭证刷新(app 层,新件调度):** 短 TTL 会话凭证(`cred`,分钟级)近过期 → Agent 走**轻量刷新**(重令牌交换,带更新的姿态/risk;身份子 L2)。`credstore` 调度:
   - 近过期(剩余 < refresh-lead)→ 后台静默刷新,不打断会话;
   - 刷新带**当前姿态摘要**(3.8),使新凭证反映最新姿态/risk(动态访问控制,`cred.Claims` 已含 `Posture`/`RiskScore`/`RiskLevel`,签发侧 `identity.WithRiskSource` 填);
   - 刷新失败(网络断)→ 凭证 TTL 到期自然失效(兜底,不可达时 fail-safe)。
   - **机制参照 `enroll.RunRenewLoop`**(同「剩余有效期阈值触发 + 失败重试不退出 + 原子替换」范式),但目标是会话凭证而非证书,且经身份子 L2 令牌交换端点(非 `/renew`)。
- **撤销秒级下推(端提速,已 as-built 骨架):** `agent.Session.RunControlChannel` 连 `control.Hub`,收 `revoke`(jti 命中→本地弃用凭证)/`recheck_posture`(立即重采上报)/`reauth`(重走 enroll)。**Agent 直接复用并扩指令集**(对齐接入硬化 L2 §3.3 的推送类型):
  - 现支持:`revoke` / `recheck_posture` / `reauth`(`control.go` 已实现);
  - **本文建议扩**:`config_update`(split-tunnel/内部域名/PoP 列表变更,推而非轮询,3.3/3.7)、`reselect_pop`(PoP 变更→重连,3.7)——需扩 `ControlCommand` proto(3.11)。
- **权威不变(贯穿):** 实时通道是 **best-effort 提速**(通道断/丢消息不影响安全),**判定与撤销权威仍在 PoP**(吊销表 + 短 TTL,接入硬化 L2 §3.4 三层分工);Agent 本地弃用凭证只是「更快不再用」,PoP 仍强制。
- **依据:** 复用既有 `CertRotator`/`RunRenewLoop`/`Session`/`Hub`,Agent 侧增量是「会话凭证刷新调度 + 扩指令集」;两条链分开(transport 证书 vs app 凭证)避免混淆。

**风险** 刷新风暴(海量 Agent 同时刷新)→ 刷新抖动 jitter(身份子 L2)+ 阈值随机化;两条链混淆 → 文档与代码明确区分(证书续期 vs 凭证刷新);撤销下推依赖在线 → 不在线则短 TTL 兜底(权威在 PoP);扩指令需 proto 兼容 → `ControlCommand` 加字段向后兼容(proto3 可选字段)。

**结论** 两条独立链:设备证书续期(复用 `enroll.RunRenewLoop`/`CertRotator` 热轮换)+ 会话凭证刷新(新件调度,参照 RunRenewLoop 范式、经身份子 L2 令牌交换、带最新姿态/risk);撤销/重认证/重采姿态/配置/重选路经终端实时通道(复用 `agent.Session`+`control.Hub`,扩 `config_update`/`reselect_pop` 指令);**权威永在 PoP,通道仅提速,短 TTL 兜底**。

---

### 3.7 PoP 选址:RTT 探测 + 节点动态发现(不硬编码 IP)★

**背景** L1 3.13 RTT 选路 + 不硬编码 IP(经域名/控制面取节点,使云 BGP IP 迁自建时客户端无需改)。上位 L2 §3.6 已定口径。但现 Agent 是 `POP_URL` 环境变量硬编码单 PoP(`cmd/agent`)。本节定选址机制。

**目标** 定 Agent 的 PoP 节点发现 + RTT 选最近 + 动态切换。

**设计**
- **节点发现(不硬编码 IP):** Agent 入网时(enroll 响应,上位 §3.6 的 `pop_list`)与运行期(实时通道 `config_update`,3.6)拿到**候选 PoP 节点列表**(域名/逻辑名,非硬编码 IP);列表由控制面据租户可用 PoP 给出。
  - 备选:DNS-based(单域名 + GeoDNS 解析就近)。落选(作唯一手段):GeoDNS 粒度粗、不反映实时 RTT/负载、迁移仍依赖 DNS 改;**保留为辅助**(域名解析得候选 IP)。
  - 选:**控制面下发候选列表 + 客户端 RTT 实测选优**(主),DNS 辅助。依据:控制面知租户可用 PoP + 实时容量(对接平台 PoP 容量看板,平台控制台 L2),客户端再用 RTT 细选,兼顾「就近」与「可用/负载」。
- **RTT 探测选最近(L1 3.13):** `popselect` 对候选 PoP 实测 RTT(候选探测方式:轻量 UDP/握手 RTT,或 SPA 敲门往返;**不硬编码 ICMP**——部分网络禁 ICMP),选 RTT 最低且健康者;并**上报 RTT 供选址数据**(L1 3.14 遥测)。
- **动态切换 + 抑抖动:** 活动 PoP RTT 持续劣化/不可达 → 切次优;**滞后/加权切换**避免 flapping(参照 SD-WAN `linkmon` 的 dwell/EWMA 思路——`internal/linkmon` 已有 RTT EWMA + 滑窗丢包评分 + 滞后回切,Agent 选址可复用同算法或同思路)。
- **与隧道/SPA 联动:** 选定 PoP 后,(若启用 SPA,接入硬化 L2)先 SPA 敲门 → 再建隧道(3.4);切换 PoP = 对新 PoP 重敲门+重握手。
- **依据:** 控制面下发 + RTT 实测 + 不硬编码 IP 三件齐(L1 3.13);切换抑抖动复用 SD-WAN 已验的 `linkmon` 思路(地基统一)。

**风险** 候选列表过期(PoP 下线)→ 实时通道 `config_update` 推新列表 + 客户端健康探测剔除;RTT 探测被网络策略阻断(禁 ICMP/UDP)→ 用握手/SPA 往返测 RTT,不依赖单一协议;切换抖动 → 滞后/EWMA(复用 linkmon);首次无列表(入网前)→ 入网域名(管理面)是唯一硬依赖,入网后即用列表。

**结论** PoP 选址 = 控制面下发候选列表(不硬编码 IP,入网 + 实时通道更新)+ 客户端 RTT 实测选最近(轻量握手/UDP RTT,不依赖 ICMP)+ 滞后切换抑抖动(复用 `linkmon` 思路);DNS 辅助;切换联动 SPA 重敲门 + 隧道重握手。

---

### 3.8 设备姿态采集:姿态字段集单一来源 + 各 OS API + 进 claim 同源 + 反作弊 ★

**背景** 上位 L2 §3.3 已定**姿态 schema 姿态字段集**(作采集/凭证/策略单一来源,收口身份 LI5 / 编译器 LP4)与口径(Agent 只报事实不判定、字段可空 fail-closed、posture vs risk 分离)。但**字节编码、各 OS 系统 API 采集映射、进 claim 的同源机制、反作弊定位**(上位 LA3)未落。本节落之。as-built:现姿态是不可信自报字符串(`agent.Session.posture`,如 "compliant"),`cred.Claims.Posture` 是单字符串——**本节把它结构化为 姿态字段集**。

**目标** 定 姿态字段集的 api/proto 单一来源、各 OS 采集 API、进 posture claim 同源、反作弊边界。

**设计 —— 姿态字段集单一来源(api/proto)**

字段集**沿用上位 L2 §3.3(不重定)**:`os`/`os_version`/`patch_level`/`disk_encryption`/`av_edr`(enum none/present/healthy)/`firewall`/`screen_lock`/`jailbroken_rooted`/`device_cert_valid`/`agent_version`。

> **字段计数口径(钉死,消除三方歧义)**:上述为同一姿态事实集,三处文档此前按不同粒度计数,以本节为准——上位 L2 §3.3 按**逻辑项**计 **9 项**(`os`/`os_version` 合记一项「OS 版本」);L1 3.8 按更粗分组计 **8 项**(「OS 版本/补丁」再合一);本文 proto schema 把 `os`(平台名)与 `os_version`(版本号)**拆为两个独立字段**,故 `PostureFacts` 共 **10 个 proto 字段**。**最终单一来源 = api/proto `PostureFacts`(10 字段);契约测试断言数、策略选择器字段集均以 proto 字段数为准**。编码定义 proto 时一次性回写统一 L1 3.8 / 上位 L2 §3.3 / 路线图的计数表述(列为 LZ1 协同项)。下文凡「姿态字段集」均指此 10 字段 proto schema。

- **单一来源落点(收口 LA3):** 在 **api/proto 定义 `PostureFacts` message**(新增,3.11),作为:① Agent 壳 `PostureProbe.Collect()` 的返回类型;② 上报到控制面/PoP 的线格式;③ 控制面签发凭证时填入 posture claim 的来源;④ 策略编译器 device-posture 选择器引用的字段集。**契约测试覆盖四处一致**(对接身份 3.3 / 编译器 RP7,上位 RA2)。
- **进 posture claim 同源(关键演进):** 现 `cred.Claims.Posture` 是单字符串(stand-in)。建议演进为**结构化姿态摘要**——两选项:
  - **(选)claim 携姿态摘要哈希 + 关键布尔位**:凭证 claim 含 `posture` 摘要(如越狱/磁盘加密/证书有效等关键布尔的紧凑编码 + 完整 `PostureFacts` 的哈希),PEP 按位求值(`risk_gte` 已是同模式,`cred.Claims` 已含 `RiskLevel`);完整事实留控制面/遥测,凭证不必塞全量(凭证小、签名快)。依据:凭证是高频验证对象,塞全量 姿态字段集+版本字符串使凭证臃肿;PEP 只需关键位 + 风险等级(risk 已派生)。
  - (备选)claim 携全量 `PostureFacts`。落选:凭证臃肿、每刷新重塞;PEP 数据面无解释器(策略编译器 L2),复杂姿态判定本就该在控制面派生为 risk/关键位。
  - **兼容现状:** 现 `Posture string` 可作过渡;结构化演进时保持 `cred.Claims` 契约可加字段(本文标为待确认 LZ1:claim 姿态编码最终形态,需与身份子 L2 + 编译器 + PEP 协同)。
- **各 OS 采集 API 映射(壳 `PostureProbe.Collect` 实现,逐 OS):**

| 字段 | Windows | macOS | Linux |
|------|---------|-------|-------|
| `os`/`os_version` | `RtlGetVersion`/WMI | `sysctl`/`ProcessInfo` | `uname`/`/etc/os-release` |
| `patch_level` | WMI `Win32_QuickFixEngineering` / Update API | `softwareupdate`/SystemVersion | 包管理器/内核版本 |
| `disk_encryption` | BitLocker WMI(`Win32_EncryptableVolume`) | FileVault(`fdesetup status`/CoreStorage) | LUKS(`/proc`/`dmsetup`/cryptsetup) |
| `av_edr` | Security Center(`WSC` API)枚举 AV/EDR | 检测已知 EDR 进程/系统扩展 | 检测已知 agent 进程(弱,Linux 无统一 API) |
| `firewall` | `WSC`/防火墙策略 API | `socketfilterfw`/PF | `ufw`/`iptables`/`nft` 状态 |
| `screen_lock` | 屏保/锁屏策略(注册表/策略) | `defaults` 锁屏设置 | DE 相关(弱) |
| `jailbroken_rooted` | (桌面 N/A,移动端相关) | SIP 状态(`csrutil`)作近似 | (受限) |
| `device_cert_valid` | **Agent 自查** `CertRotator` 当前证书有效期/链 | 同 | 同 |
| `agent_version` | 编译期注入 | 同 | 同 |

  - 字段可空(某 OS 无该项)→ 上报「未知」,策略按「未知=不满足」(fail-closed,上位 §3.3)。
- **反作弊定位(核心诚实边界):** 端被攻陷则自报姿态不可信(上位 RA3),故须分清**哪些可背书、哪些仅自报**:
  - **可由系统/平台背书(较可信):**
    - `device_cert_valid` —— **由 PoP 侧 mTLS 证书验证背书**(不是 Agent 自报,而是 PoP 看到的设备证书有效性,W9 租户绑定);这是最强的一项。
    - 平台**硬件认证/远程证明**(可选增强,后置):Windows TPM-based Device Health Attestation、macOS DeviceCheck/Secure Enclave、Android SafetyNet/Play Integrity——由硬件/OS 签名背书的姿态断言,端无法伪造。**列为后置增强**(附录 LZ8),MVP 不依赖。
  - **仅 Agent 自报(端被控即可伪造):** 其余 7 项(磁盘加密/杀软/防火墙/锁屏/补丁/越狱 root/OS 版本)——**Agent 防篡改可抬高伪造门槛但非密码学保证**(代码签名 + 进程完整性自检 + 服务防卸载,3.5/3.9)。
  - **安全模型(明确,不夸大):** 姿态**非唯一门禁**——配合 ① 设备证书(transport,不可伪造身份)② 短 TTL ③ risk 派生 ④ PoP 权威判定(端不可信)⑤ 越狱 root 项本身拦高风险设备。**self-reported 姿态是「合规辅助 + 风险输入」,不是「不可绕过的安全边界」**(同上位 §3.3 风险闭环)。
  - 备选:把全部姿态当强门禁。落选:端被控即绕过,造成安全错觉;故明确分级。
- **采集时效:** 周期采集(默认间隔待确认 LZ9)+ **事件驱动**(锁屏/解锁/网络变化/EDR 状态变 → 立即重采上报,经实时通道 `recheck_posture` 触发,3.6);凭证携签发时点摘要,TTL 内变化经刷新更新或触发撤销(上位 §3.8)。

**风险** 自报姿态被伪造 → 明确分级(背书 vs 自报)+ 非唯一门禁 + PoP 权威(本节安全模型);字段平台差异 → 可空 + fail-closed;claim 姿态编码与现单字符串契约演进 → 待确认 LZ1 + 契约测试 + 向后兼容;远程证明引入硬件依赖 → 后置增强不阻塞 MVP(LZ8)。

**结论** 姿态字段集定义在 api/proto `PostureFacts`(单一来源,收口 LA3),Agent 壳逐 OS 调系统 API 采集、核心调度上报;进 posture claim 用「关键布尔位 + 摘要哈希」(凭证不塞全量,PEP 按位+risk 求值,claim 最终编码待 LZ1);**反作弊分级——`device_cert_valid` 由 PoP mTLS 背书(最强)、硬件远程证明后置增强、其余 7 项仅自报(防篡改抬门槛非密码学保证);姿态非唯一门禁、PoP 权威、端不可信**(不夸大);周期 + 事件驱动采集。

---

### 3.9 打包 / 代码签名 / 自动更新

**背景** 真 Agent 要在用户设备安装/升级,涉及各 OS 安装包、代码签名(否则被系统/杀软拦)、静默升级(海量设备不可能手动)。上位 LA8 标了「远程升级类 CPE LS8,机制待实施期」。本节给选型与分期。

**目标** 定各 OS 安装包、代码签名、静默升级通道与回滚。

**设计**
- **安装包(各 OS):** Windows = MSI/MSIX(含 wintun 驱动);macOS = `.pkg`(含 root daemon + launchd plist + 托盘 app);Linux = deb/rpm + systemd unit(企业内分发优先,非应用商店)。
- **代码签名(否则被拦):**
  - Windows:**EV 代码签名证书**(驱动须单独签名/WHQL,wintun 驱动签名);未签名驱动 Win10+ 不加载。
  - macOS:Apple Developer ID 签名 + **公证(notarization)**;否则 Gatekeeper 拦。
  - Linux:仓库签名(deb/rpm GPG)。
  - 依据:无签名在现代 OS 上装不上/被杀软拦;EV/公证是硬要求。**这是外部依赖(证书申请周期),需尽早启动**(对接 MVP 路线图「外部依赖立即启动」)。
- **静默自动更新(updater 模块,3.1):**
  - 守护进程 `updater` 周期向**更新服务**查版本(或实时通道 `config_update` 推「有新版」)→ 下载 → **验签(发布签名,独立于 transport mTLS)** → 交壳安装(壳调系统安装机制,可能需短暂重启服务)。
  - **灰度/分批/回滚(对接运维/部署 L2 §3.3 发布编排):** 更新服务按版本/租户/比例灰度放量;失败/崩溃率超阈值停止放量并回滚;Agent 侧保留上一版本可回滚。**类 CPE LS8**(上位 LA8),复用运维 L2 发布编排思路。
  - 验签独立:更新包验签用**发布签名公钥**(内嵌 Agent,不依赖 transport 证书),防被攻陷的传输信道投毒。
  - 备选:用户手动升级。落选:海量设备不可行、版本碎片化、安全补丁滞后。
- **版本兼容:** Agent↔控制面/PoP 协议版本字段 + 向后兼容(L1 3.11);新旧 Agent 共存期协议协商。

**风险** 代码签名证书申请周期长(外部依赖)→ 尽早启动(MVP 前置);驱动签名(Windows)受阻 → netstack 降级路径(3.2,附录 LZ7);静默更新投毒 → 发布签名独立验签 + 灰度 + 回滚;更新致服务重启断网 → 平滑切换(新进程接管 TUN 再退旧)或短暂重连(待实测 LZ10)。

**结论** 各 OS 安装包(MSI/pkg/deb-rpm,企业分发优先)+ 强制代码签名(Win EV+驱动签名 / macOS Developer ID+公证 / Linux 仓库签名,**证书外部依赖须尽早启动**)+ 静默自动更新(updater 周期/推送查版本→下载→**独立发布签名验签**→灰度放量+失败回滚,类 CPE LS8 复用运维 L2 发布编排);协议版本化向后兼容。

---

### 3.10 enroll / ZTP 首次入网(复用现 enroll)

**背景** Agent 首次入网须拿到租户绑定证书 + 会话凭证。as-built `internal/enroll` 已实现 Connector/CPE 的 ZTP(激活码→本地 CSR→租户绑定证书),`FetchCert` 客户端本地生成密钥+CSR、私钥不离设备。Agent 入网可复用,但 Agent 是「面向人」——入网含 IdP 用户认证(上位 §3.6:IdP 认证 → 设备 CSR → `Enroll{idp_token, device_info, csr}`)。

**目标** 定 Agent 首次入网流程与现 enroll 复用边界。

**设计 —— Agent 入网(用户 + 设备双重)**
- **流程(上位 §3.6 落地):** 用户在托盘点登录 → ① **IdP 用户认证**(OIDC,身份子 L2;现 `internal/oidc` + `/idp/login` 已 as-built 真 OIDC + 企微/钉钉/飞书 adapter)→ ② 设备**本地生成密钥对 + CSR**(`devpki.GenerateCSR`,私钥不离设备,L1 3.5)→ ③ `Enroll{idp_token/或激活码, device_info(姿态摘要), csr}` 提交控制面 → ④ 控制面(令牌交换,身份子 L2)签发**租户绑定设备证书 + 短 TTL 会话凭证** + 返回配置(`pop_list`/内部域名/split-tunnel 规则/policy_version)。
- **复用现 enroll 边界:**
  - **设备证书签发**复用 `enroll`/`devpki.SignCSR`(把 tenant 编进证书 Organization、W9 租户绑定)+ `CertRotator` 热轮换 + `RunRenewLoop` 续期(3.6)——直接复用。
  - **Agent 的入网触发**与 Connector/CPE 不同:Connector/CPE 用纯激活码(`enroll.KindConnector/KindCPE`),Agent 用 **IdP 用户认证 + 设备绑定**;需 enroll 支持 Agent kind(或控制面身份子 L2 的 Agent 入网端点),把 IdP 认证的用户身份与设备证书关联。**建议** enroll 增 `KindAgent` 或经身份子 L2 的 Agent 入网路径(待确认 LZ11:Agent 入网走 enroll 扩展还是身份子 L2 端点)。
- **私钥本地生成永不离开(L1 3.5):** 复用 `devpki.GenerateCSR`,私钥本地;只注册公钥/CSR(同 Connector/CPE)。

**风险** 不同平台 IdP 浏览器跳转差异 → 壳调系统默认浏览器 + 回调(loopback/自定义 scheme,身份子 L2 OIDC callback);Agent 入网路径与现 enroll(激活码-only)契约扩展 → 待确认 LZ11 + 向后兼容;入网时设备身份与用户身份绑定(谁的设备)→ 设备证书 CN/Org 编入,姿态报 `device_cert_valid` 由 PoP 背书(3.8)。

**结论** Agent 入网 = IdP 用户认证(复用现 `internal/oidc`)+ 设备本地 CSR(复用 `devpki.GenerateCSR`,私钥不离设备)→ 控制面签发租户绑定证书(复用 `enroll`/`SignCSR`/`CertRotator`/`RunRenewLoop`)+ 短 TTL 会话凭证 + 配置;Agent 入网触发路径(enroll 扩 `KindAgent` vs 身份子 L2 端点)待确认 LZ11。

---

### 3.11 契约与衔接(收口上位 L2 悬留点 + 新增 api/proto)

**背景** 真 Agent 涉及多个与控制面/PoP/各子 L2 的契约,且本文落实了上位 L2 留的 Agent 侧悬留点(LA2/LA3/LA8)。需汇总并明确新增的 api/proto。

**目标** 明确契约面、收口上位悬留点、列出需新增/扩展的 api/proto。

**设计 —— 契约面**
- **与控制面 `identity`:** Agent 入网(IdP+CSR→证书+凭证,3.10)、会话凭证刷新(3.6);凭证 posture claim 取本文 3.8 编码(待 LZ1)。
- **与终端实时通道 `control`:** 复用 `AgentControl` gRPC 双向流;**建议扩 `ControlCommand` 指令** `config_update`/`reselect_pop`(3.6,需扩 proto)。
- **与数据面 `dptunnel`+`tunhandshake`:** Agent→PoP L3 包隧道复用(3.4);`PacketIO` 接缝复用(3.2)。
- **与 PoP 单机编排 L2:** 隧道在 PoP 终结、PEP 求值(客户端只持凭证、报姿态);Agent 送 L3 包、PoP 解封后到应用(任意 TCP 的 PoP 侧出站属 PoP L2)。
- **与策略编译器子 L2:** posture(3.8 `PostureFacts`)作 subject device-posture 选择器输入(同源,收口 LP4 posture 部分)。
- **与信任/风险引擎 L2:** 姿态/风险信号经实时通道事件上报(`control` posture 上报 → 风险派生)。
- **与计费子 L2:** Agent enroll = 活跃席位计数信号;refresh 不新增席位(去重 user_id+月,上位 §3.9)。
- **与接入硬化 L2:** Agent 侧 SPA 敲门客户端(连隧道前敲门,3.4/3.7)、终端实时通道客户端(3.6)。
- **与国密选型:** 隧道/敲门加密算法待 PoC-G(算法敏捷)。
- **与前端控制台 L2:** Agent 分发/状态、激活码、应用→连接器映射在控制台维护。

**新增/扩展 api/proto(本文识别):**

| proto | 动作 | 用途 | 节 |
|-------|------|------|----|
| `PostureFacts` message(新增,放 `api/proto/sase/posture/v1` 或复用现有) | **新增** | 姿态字段集姿态单一来源(采集/上报/凭证填充/策略选择器引用) | 3.8 |
| `control.v1.ControlCommand` | **扩字段** `config_update`/`reselect_pop`(kind + payload) | 实时通道推配置/重选路 | 3.6 |
| `control.v1.AgentEvent` | **扩** 姿态上报由单字符串 → 结构化 `PostureFacts`(向后兼容) | 事件驱动结构化姿态上报 | 3.8 |
| `cred.Claims.Posture` | **演进** 单字符串 → 关键布尔位+摘要哈希(契约可加字段,待 LZ1) | 凭证携结构化姿态摘要 | 3.8 |
| enroll `KindAgent`(或身份子 L2 Agent 入网端点) | **新增/协调**(待 LZ11) | Agent 入网(IdP+设备绑定) | 3.10 |

**收口上位 L2 悬留点:**
- **LA2(移动端范围):** 本文 §4 给结论——**MVP 桌面优先(Win+macOS),移动端后置**(依据见 §4)。
- **LA3(姿态字节编码 + 各 OS 采集 API):** 本文 3.8 落实(api/proto `PostureFacts` + 各 OS API 映射表)。
- **LA8(远程升级):** 本文 3.9 落实(updater + 类 CPE LS8 复用运维 L2 发布编排)。

**风险** 契约 schema 漂移(尤其 posture)→ api/proto 单一来源 + 契约测试(上位 RA2);proto 扩展兼容 → proto3 加字段向后兼容;Agent 入网路径协调 → 待 LZ11 与身份子 L2 对齐。

**结论** 契约面覆盖 identity/control/dptunnel/PoP/编译器/风险/计费/接入硬化/国密/前端;新增 `PostureFacts` proto(姿态单一来源)、扩 `ControlCommand`/`AgentEvent`(配置推送/结构化姿态)、演进 `cred.Claims.Posture`(待 LZ1)、协调 Agent 入网路径(待 LZ11);收口上位 LA2(桌面优先,§4)/LA3(3.8)/LA8(3.9)。

---

## 四、分期建议(MVP 先做哪两平台 + 必做 vs 后置 + XL 拆解)

**背景** 真 OS 级 Agent 是 XL net-new(MVP 最大长杆,路线图)。须给 MVP 平台选择与设计点优先级,使「最快可演示」与「不返工」兼顾。

**目标** 定 MVP 平台、必做 vs 后置、XL 工作量拆解。

**设计 —— MVP 平台:Windows + macOS(收口 LA2)**
- **选 Windows + macOS,Linux 桌面与移动端后置:**
  - 依据:① 中国大陆 50–5000 人中大型企业(目标客群,CLAUDE.md)办公终端以 Windows 为主、macOS 次之,Linux 桌面占比低;② 移动端(iOS/Android)有后台/VPN API 限制(iOS NEPacketTunnelProvider 沙箱、Android VpnService + 厂商后台杀进程),坑独立且大,**单列后置**(上位 §3.2 风险 + LA2);③ Linux 内核 TUN 已 as-built(`OpenTUN`),Linux daemon 形态成本最低,**可作早期内部联调平台**(开发自用),正式桌面发布后置。
  - 备选:先做 Linux(复用现 `OpenTUN`)。落选(作 MVP 面向客户):客户终端极少 Linux 桌面;但 Linux 作**开发/联调平台**先行(零成本复用)。
  - 移动端:**后置**(iOS/Android VPN API 限制,独立 XL,LA2 收口为后置)。
- **设计点 MVP 必做 vs 后置:**

| 设计点 | MVP 必做 | 后置 | 理由 |
|--------|---------|------|------|
| 内核 TUN 接管(Win wintun / macOS utun) | ✅ | — | 替代 VPN 的核心 |
| 守护进程 + 托盘 + IPC | ✅ | — | 长驻是「真 Agent」前提 |
| split-tunnel(CIDR) | ✅ | split-DNS 深化 | 先按 CIDR 接管可演示;DNS 劫持随内部域名场景 |
| split-DNS | ✅(基础) | 复杂多 DNS 策略 | 内部应用无固定 IP 时必需 |
| 凭证静默刷新 + 撤销下推 | ✅(复用现件) | — | 持续验证核心(且大量复用) |
| RTT 选址 + 节点发现 | ✅(基础) | 复杂负载/亲和 | 去硬编码 IP 必需 |
| 姿态采集 姿态字段集 | ✅(自报 + device_cert 背书) | 硬件远程证明 | 基础合规;TPM/Secure Enclave 后置增强 |
| 数据面 L3 包隧道(里程碑 B) | ✅(复用 dptunnel) | — | 承载任意 TCP |
| 代码签名 + 安装包 | ✅(外部依赖前置) | — | 否则装不上 |
| 自动更新 | ✅(基础)| 灰度/回滚深化 | 海量设备必需,深化随规模 |
| Network Extension(macOS) | — | ✅ | root daemon 先行,NE 深度集成后置 |
| netstack 降级路径 | — | ✅ | 驱动受阻/无权限再做 |
| 移动端 | — | ✅(独立 XL) | API 限制,后置 |

- **XL 工作量拆解(可独立推进的子块,粗粒度):**
  1. **共享核心组装**(M):把 `cred/enroll/dptunnel/control/agent.Session` 组装成守护进程骨架(状态机 + IPC server);largely 复用既有件。
  2. **平台壳 — 流量接管**(L×2):Windows wintun `PacketIO` + macOS utun `PacketIO`(各封装为接缝);坑在驱动/权限/路由/DNS 接管(真实终端冲突)。
  3. **flowmgr 分流**(M):split-tunnel(复用 lpm)+ split-DNS 代理。
  4. **posture 采集**(M×2 平台):各 OS 系统 API 映射 + `PostureFacts` proto + 契约测试。
  5. **守护进程 + 托盘 + IPC**(M×2 平台):服务模型 + 托盘 UI + IPC 鉴权。
  6. **选址 popselect**(S–M):RTT 探测 + 节点发现 + 切换(复用 linkmon 思路)。
  7. **凭证刷新调度**(S):会话凭证刷新(参照 RunRenewLoop)+ 扩实时通道指令。largely 复用。
  8. **打包/签名/更新**(M + 外部依赖):安装包 + 代码签名(证书申请前置)+ updater。
  9. **数据面承载演进**(与 W1 对齐):里程碑 A(HTTP 通用化,W1)→ B(L3 包隧道接 Agent)。

**风险** XL 一次性吞不下 → 按子块独立推进(核心组装 + Linux 联调先行,Win/macOS 壳并行,签名外部依赖前置);真实终端坑(VPN/防火墙/EDR 冲突)→ 兼容矩阵 + 早测(附录 LZ4);移动端范围蔓延 → 明确后置(LA2 收口)。

**结论** MVP 平台 **Windows + macOS**(Linux 作开发联调先行、正式桌面与移动端后置,收口 LA2);MVP 必做内核 TUN/守护+托盘/split-tunnel+基础 split-DNS/凭证刷新+撤销下推(复用现件)/RTT 选址/姿态字段集姿态(自报+device_cert 背书)/L3 包隧道/代码签名+安装包+基础自动更新;后置 macOS NE/netstack 降级/硬件远程证明/灰度回滚深化/移动端;XL 拆 9 子块,核心组装与签名外部依赖前置。

---

## 五、风险

### RZ1:真 OS 级 Agent 是 XL net-new(最大长杆)
缓解:大量复用既有 `cred/enroll/dptunnel/control/agent`(文首对齐,§3.1 复用列);XL 拆 9 子块独立推进(§4);Linux 联调先行(零成本);MVP 限 Win+macOS、移动端后置。

### RZ2:多平台壳维护成本(尤 TUN/姿态/DNS API)
缓解:共享核心 + 三窄壳接口(`NetCapture`/`PostureProbe`/`SystemIntegration`,§3.1),壳返回平台无关类型;`PacketIO` 接缝复用(§3.2);兼容矩阵实测(附录 LZ4)。

### RZ3:与真实终端环境冲突(其它 VPN / 防火墙 / EDR / 路由 / DNS)
缓解:**默认最小接管**(白名单 split-tunnel,§3.3)、不全量抢 default route;崩溃/退出恢复原 DNS/路由(§3.5 watchdog + cleanup);兼容矩阵早测。

### RZ4:自报姿态被攻陷端伪造(安全错觉)
缓解:**明确分级**(§3.8)——`device_cert_valid` 由 PoP mTLS 背书(最强)、硬件远程证明后置增强、其余 7 项仅自报;姿态非唯一门禁 + 短 TTL + risk + **PoP 权威判定**(端不可信);越狱 root 项拦高风险设备;不夸大 self-report 为安全边界。

### RZ5:代码签名/驱动签名外部依赖(申请周期 + 受阻)
缓解:证书申请**尽早启动**(MVP 前置外部依赖,§3.9);Windows 驱动受阻 → netstack 降级路径(§3.2 后置);macOS root daemon 先行(避 NE 审批链)。

### RZ6:数据面承载演进期两套形态共存(W1 HTTP → L3 包隧道)
缓解:隧道能力协商 + 向后兼容(§3.4);里程碑 A(HTTP 通用化,W1)作过渡 + Agentless 对称,B(L3 包隧道)为终态。

### RZ7:加密栈 / SPA 敲门待国密阻塞
缓解:仅加密算法待 PoC-G(算法敏捷、与数据面/CPE 同源,上位 §3.7);Agent 结构/接管/分流/守护/选址/姿态/打包均不阻塞,可先编码(非国密档 TLS1.3/ChaCha20/Ed25519 验集成,同既有切片)。

### RZ8:posture/凭证/协议契约漂移
缓解:`PostureFacts` api/proto 单一来源 + 契约测试(§3.8/§3.11);claim 姿态编码待 LZ1 与身份/编译器/PEP 协同;proto3 加字段向后兼容。

### RZ9:守护进程 IPC 提权面
缓解:双进程模型(特权守护 + 非特权托盘),IPC 经 UDS/named pipe + **peer 凭证鉴权**、只接受当前登录用户(§3.5)。

### RZ10:移动端范围蔓延 / API 限制
缓解:MVP 明确后置(§4,收口 LA2);移动端 VPN API 限制(iOS NE 沙箱 / Android VpnService + 厂商杀进程)作独立 XL,待确认(附录 LZ12)。

---

## 六、结论与衔接

**结论:** 真 OS 级 ZTNA Agent = **复用既有 `cred/enroll/dptunnel/control/agent`(凭证/入网/隧道/实时通道)组装的共享 Go 核心 + 三窄平台壳**(`NetCapture`/`PostureProbe`/`SystemIntegration`)+ 端侧新件(选址/分流/守护/更新);流量接管选**各 OS 原生内核 TUN/虚拟网卡**(Win wintun / macOS utun via root daemon / Linux 复用 `OpenTUN`)统一为 `dptunnel.PacketIO` 接缝(选内核 TUN + L3 包隧道,非用户态 netstack);**默认最小接管**(白名单 split-tunnel,CIDR 复用 lpm)+ split-DNS 劫持租户内部域名→overlay(屏蔽内网拓扑);数据面随里程碑收敛到「TUN + dptunnel L3 包隧道」承载任意 TCP(里程碑 A 承接 W1 HTTP 通用化作过渡),mTLS(设备级)+ 会话凭证(app 层)双层不破;**双进程守护**(特权守护 + 非特权托盘,IPC peer 鉴权);凭证静默刷新(设备证书复用 `RunRenewLoop`/`CertRotator`、会话凭证新调度)+ 撤销秒级下推(复用 `control.Hub`/`agent.Session`,扩配置/重选路指令),**权威永在 PoP、通道仅提速、短 TTL 兜底**;PoP 选址 = 控制面下发候选 + RTT 实测选最近 + 不硬编码 IP(复用 linkmon 切换思路);**姿态字段集(10 proto 字段)定义在 api/proto `PostureFacts` 单一来源**(收口 LI5/LP4/LA3),各 OS 系统 API 采集、进 claim 用关键位+摘要、**反作弊分级**(device_cert 由 PoP 背书最强、硬件证明后置、其余自报、姿态非唯一门禁、PoP 权威);打包/强制代码签名(外部依赖前置)/静默自动更新(类 CPE LS8);入网复用现 enroll/devpki + IdP 认证(私钥本地生成)。**MVP 平台 Windows + macOS**(Linux 联调先行、移动端后置,收口 LA2);XL 拆 9 子块。加密算法敏捷待 PoC-G,不阻塞其余设计。

**衔接:**
- **客户端 Agent/Connector L2(上位):** 本文深挖其「端点 Agent」形态内部;收口 Agent 侧悬留点 **LA2(桌面优先)/LA3(姿态编码+采集 API)/LA8(远程升级)**;形态边界/姿态字段集/口径仍以上位为准。
- **接入硬化 L2:** Agent 侧 SPA 敲门客户端(连隧道前敲门,§3.4/§3.7)、终端实时通道客户端(§3.6,扩指令);机制本体仍以接入硬化 L2 为准。
- **身份子 L2:** 入网/令牌交换/凭证刷新;posture claim 编码协同(待 LZ1)；Agent 入网路径协调(待 LZ11)。
- **数据面隧道 L2:** Agent→PoP L3 包隧道复用 `dptunnel`+`tunhandshake`;`PacketIO`/`OpenTUN` 接缝。
- **PoP 单机编排 L2:** 隧道终结、PEP 求值、任意 TCP 的 PoP 侧出站。
- **策略编译器子 L2:** `PostureFacts` 作 subject 选择器输入(收口 LP4 posture)。
- **信任/风险引擎 L2:** 姿态/风险事件上报。
- **计费子 L2:** enroll=活跃席位信号。
- **运维/部署 L2:** Agent 自动更新复用发布编排(灰度/回滚,§3.9)。
- **国密选型(待 PoC-G):** 隧道/敲门加密算法敏捷。
- **前端控制台 L2:** Agent 分发/状态/激活码/应用映射管理。

搭脚手架 / 写代码须**另行授权**(设计先行)。

---

## 附录:待确认 / 待实测 / 待国密

| # | 项 | 性质 | 去向 |
|---|----|------|------|
| LZ1 | posture claim 最终编码(关键布尔位 + 摘要哈希 vs 全量)与现 `cred.Claims.Posture` 单字符串契约演进 | 契约 | 与身份子 L2 + 编译器 + PEP 协同;§3.8 |
| LZ2 | macOS 接管 root daemon(MVP)→ Network Extension(深度系统集成/上架)迁移时机 | 选型/范围 | 后置,§3.2 |
| LZ3 | 全量接管(full tunnel)模式按租户开启的策略/契约 | 机制 | 与策略/前端协调,§3.3 |
| LZ4 | 各 OS 与本地 VPN/防火墙/EDR/路由/DNS 兼容矩阵 | 待实测 | 实施期兼容测试,§3.2/3.3/3.5 |
| LZ5 | 隧道内层 MTU 扣减实测值(外层 PMTU - 封装开销 - UDP/IP 头) | 待实测 | 实施期,§3.2 |
| LZ6 | 用户注销/切换/锁屏时会话凭证去留与降权策略 | 机制 | §3.5,与身份子 L2 |
| LZ7 | 无 TUN 权限 / wintun 驱动签名受阻的降级(netstack / proxy 模式)触发条件 | 降级 | 后置,§3.2/3.4 |
| LZ8 | 硬件远程证明(TPM DHA / macOS DeviceCheck / Android Integrity)作姿态背书的引入 | 增强 | 后置增强,§3.8 |
| LZ9 | 姿态周期采集默认间隔 + 事件触发集合 | 参数 | 待实测/调优,§3.8 |
| LZ10 | 自动更新致服务重启时的隧道平滑切换(新进程接管 TUN 再退旧 vs 短暂重连) | 待实测 | 实施期,§3.9 |
| LZ11 | Agent 入网路径:enroll 扩 `KindAgent` vs 身份子 L2 独立 Agent 入网端点 | 契约 | 与身份子 L2 协调,§3.10 |
| LZ12 | 移动端(iOS NE 沙箱 / Android VpnService + 厂商后台杀进程)范围与限制 | 范围 | 后置独立 XL,§4/LA2 |
| LZ13 | Agent 隧道/SPA 敲门加密算法(TLCP/SM4 ↔ TLS1.3/ChaCha20) | 待国密 | PoC-G(算法敏捷,不阻塞结构) |

> 说明:本 L2 是客户端 Agent/Connector L2 中「端点 Agent」形态的真 OS 级内部深挖,收口其 Agent 侧悬留点(LA2/LA3/LA8);大量复用既有 `cred/enroll/dptunnel/control/agent` 组装,新件集中在碰 OS 的窄壳与端侧编排(选址/分流/守护/更新);加密算法敏捷待 PoC-G,**判定与撤销权威在 PoP、端不可信、姿态非唯一门禁**(不夸大 self-report)。MVP Windows+macOS,移动端后置。
