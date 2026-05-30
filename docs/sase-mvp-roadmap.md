# SASE MVP 开发路线图(v0.1 草案)

> 状态:草案,待花刚确认方向后定稿。产出依据:2026-05-30 全子系统成熟度盘点(7 agent 交叉核验 + 直接读码确认关键断言)。

## 一、背景

Slice 0–73 端到端纵向切片已让两轨道(ZTNA/SD-WAN)+ 三安全能力(SWG/FWaaS/CASB-DLP)+ 控制面 + 平台控制台**全部跑通**。但近 14 刀(Slice 60–73)集中在加固/脱敏/可观测/前端只读页,**无新增实质能力**——花刚 2026-05-30 点名「这几轮一直在加固优化,没有实质性进展」。需重定开发计划。

## 二、目标(花刚 2026-05-30 定向)

1. **国密后置**:首批目标客户为普通企业(非等保三级/金融/政企),可用标准密码学(ChaCha20/TLS1.3,已做实);不在被双重阻塞的国密上耗时,国密作并行准备轨。
2. **近期(1–2 月)= 可演示/可签单的端到端 MVP**:优先广度打通,让真实客户真能装、真能用;尽快有东西能给客户看/试用。停止只做加固。
3. **两条轨道并行**(复用统一地基)。

## 三、现状盘点(成熟度全景,代码实证)

各子系统整体定性:**控制面 / 平台控制台 / 多租户隔离 = 接近生产级**;**ZTNA 接入 / SD-WAN 数据面 / 三安全能力 = functional-but-standin**;**生产就绪(部署/计费/PKI) = design-only(近乎 0 代码)**。

| 层 | 已是生产级真实能力 | 关键 stand-in / 0 代码(代码实证) |
|---|---|---|
| **控制面** | 策略编译 fail-closed、xDS 下发、RLS 跨租户 0 泄漏、IdP/OIDC 真验签登录、撤销秒级链路、会话凭证 crypto-agility | 风险引擎内存 map(不跨副本)、遥测未落 ClickHouse、secret 用 DevProvider(KEK 内存,**重启即丢→已加密数据不可恢复**) |
| **平台控制台** | 平台运维 5 页 + 租户/PoP/RBAC/审计 CRUD、跨租户只读路径、CSRF/Bearer | 管理员登录靠 bootstrap env 短令牌手粘 Bearer(`authz.go` 只读 Bearer **不读 cookie**)、无对客租户自助控制台、计费 0 代码 |
| **ZTNA 接入** | 会话凭证/PEP 裁决/撤销/ZTP 入网/出站反向隧道/全链路 mTLS | **数据面 = `GET /access?app=&path=` 的 HTTP handler**(`ingress.go`,无 body/方法/流式);**Agent = 一次性 CLI**(`cmd/agent` 跑一次打印即退,无 TUN/守护/姿态采集);**姿态是不可信自报字符串** |
| **SD-WAN** | dptunnel 真数据报栈(AEAD/重放窗/FEC/LPM 路由,-race 实证跨租户隔离)、非国密档握手(TLS1.3+RFC5705 派生密钥)真端到端通 | 默认数据路径仍走 revtunnel(L7 HTTP stand-in),dptunnel 是 opt-in;国密档/双密钥/rekey/NAT 阻塞外部审查 |
| **三安全能力** | 规则引擎(default-deny/优先级/预编译)、FWaaS L3/L4 在真隧道生效 | **SWG/DLP 只扫 URL path**(无真 HTTP 代理/TLS 解密/body 检测);全仓无 `ext_authz/ext_proc/ebpf/netns` 非注释实现 |
| **生产就绪** | metrics RED、CI 门禁(本地) | **0 部署制品**(无 Dockerfile/K8s/Helm/systemd/Terraform/CI);dev 自签 CA + 无 HSM/KMS;**计费 0 代码**(quota 字段只存不查) |

## 四、缺口与阻塞分析

### 4.1 被外部输入阻塞(自己解不开)
- **国密 CPU(带 SM4 加速)** → 国密 PKI、国密档隧道数据面、C-G1 硬件选型。
- **外部密码学审查** → 自研握手 schedule、NAT receiver-index、tx/rx 双密钥+rekey、铜锁-Envoy。
- **HSM/云 KMS 选型采购** → 生产 secret Provider(接口已抽好,实现为零)。
- **厂商凭证 + 备案回调域名** → 企微/钉钉/飞书真沙箱。
- **真实部署环境(多 PoP/压测床)** → 部署、PoP 隔离实测、容灾、xDS 规模化。

### 4.2 现在就能做的高价值未阻塞项(推进重点,`blockedBy: none`)
- ZTNA 数据面通用化(GET-only → 任意 HTTP/TCP 流转发 + 多路复用)。
- 真实管理员登录(OIDC session cookie → authz 桥接 + MFA)。
- 控制面 HA 外置 Redis(OIDC state/token cache/风险热态)。
- SD-WAN 默认路径切到 dptunnel 真包隧道 + 真 TUN 验证 + 控制面下发隧道参数。
- 计费计量 + quota 执行(工程不阻塞,启动看商业决策)。
- 部署制品(Docker/compose/systemd)让全栈可一键跑起来演示。
- CA/KEK 双人控制 + 跨租户支持模式(带理由+审计)。

## 五、路线图(对齐"MVP / 两轨并行 / 国密后置")

**关键洞察(协调"两轨并行"与"最快可演示")**:SD-WAN 离可演示更近(CPE 是软件守护进程、真隧道已通,只需切默认路径 + 真 TUN 验证,M–L 未阻塞);ZTNA 离可演示更远(真 OS 级 Agent 是 XL 长杆,且 net-new 需先出 L2 设计)。故"两轨并行"= 两轨同时推进,但 demo-ready 时间不同。

### 阶段 1(立即,未阻塞,2–4 周):让全栈可演示
并行三股 + 一个设计 + 外部启动:
- **ZTNA 数据面通用化**:revtunnel/ingress 从 GET-only → 承载任意 HTTP 方法+头+body + 连接多路复用(去 connector.mu 串行)。解锁:ZTNA 能跑真实 Web 业务(真 Agent 的对端前提)。
- **SD-WAN 真包隧道主路径化**:默认路径切 dptunnel + 真 TUN 两站点经 PoP 互通验证 + 控制面 SiteConfig 下发隧道参数。解锁:最快的可演示 SD-WAN MVP。
- **真实管理员登录**:OIDC session cookie → authz 桥接 + MFA。解锁:平台控制台可交付真实运维 + 过等保特权认证。
- **部署制品(demo 底座)**:docker-compose 一键起 postgres + 控制面 + PoP + 种子数据。解锁:能现场演示。
- **【设计先行】真 OS 级 ZTNA Agent L2 设计**:TUN 库选型/split-tunnel/split-DNS/打包/自动更新/姿态采集 schema——XL net-new,先出设计评审再编码。
- **【花刚启动外部流程】**:① 采购带 SM4 加速国密 CPU;② 送审 `sase-tunnel-handshake-crypto-review.md`;③ 选 KMS/HSM 方案;④ 备案域名做厂商 IdP 沙箱。

### 阶段 2(4–8 周):ZTNA 真客户端 + SD-WAN 工程化
- 真 OS 级 Agent(Win/macOS)落地(按阶段 1 的设计):TUN 接管 + 长驻守护 + 静默刷新 + RTT 选 PoP + 节点发现。
- 真设备姿态采集(9 字段 schema + OS 系统 API + 凭证 claim 同源)。
- CPE 工程化(本站 LAN 流量引入隧道 + 对端路由 + NAT)+ SD-WAN NAT 穿透。
- 控制面 HA 外置 Redis。

### 阶段 3(并行/随后):商业化 + 安全能力做深
- 计费计量 + quota 执行 + 对客租户自助控制台。
- 真 Envoy 集成(ext_authz 接 PEP + ext_proc 接 SWG/DLP body 检测)+ 选择性 TLS 解密(待 HSM)。
- PoP 内核级多租户隔离(netns/unreachable-default,PoC-1 进产品)。
- 国密档端到端(待国密 CPU + 密码学审查就位)。

## 六、风险
- **真 OS Agent(XL)是 ZTNA MVP 长杆**:多平台壳维护、TUN/split-tunnel 在真实终端(VPN 冲突/防火墙/权限)坑多,从近乎零到一——故先出设计、先做 Win/macOS 两端。
- **阶段 1 的 MVP 切片比 Slice 60–73 加固刀更相互依赖**(共用 cmd/pop-agent、pop ingress 等),并行 disjoint 难度更高——需按文件归属谨慎切分,部分刀可能要串行。
- **不写部署制品就无法真演示**:阶段 1 必含 demo 底座,否则"可演示"落空。
- **外部阻塞若不立即启动采购/送审**,阶段 2/3 会串行干等(国密 CPU 到货 + 密码学审查周期都以周/月计)。

## 七、结论与下一步

**先走"阶段 1"(让全栈可演示),两轨并行推进未阻塞项,真 Agent 先出设计,外部依赖立即启动。** 最重的 Envoy/eBPF/TLS 解密(阶段 3)留到有可用产品 + 外部条件就位再攻坚。

**建议首批 Slice 74(并行 3 刀,均未阻塞)**:① ZTNA 数据面通用化;② 真实管理员登录;③ demo 部署底座(docker-compose 一键起栈)。SD-WAN 真包隧道主路径化排 Slice 75(与 ① 共用 cmd/pop-agent,避免并行冲突)。同步起草真 Agent L2 设计文档。
