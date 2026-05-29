# PoP 单机编排 L2 组件软件架构

> **状态:** L2 组件设计 / 待评审
> **版本:** v0.1
> **日期:** 2026-05-25
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **层级与上承:** L2 组件设计,对象为**单个 PoP 节点的内部编排**(数据面边缘)。上承 L1 `sase-architecture-design.md` v0.6 的 **3.1(PoP=WireGuard+Envoy+eBPF+PEP+本地遥测+fail-static 缓存、PoP 为 xDS client、无状态)**、3.7(数据面三件套顺序、共享 Envoy 方案B、硬件)、3.2(每租户独立 namespace/路由域 + 加密绑定标签)、3.13(IaC、N+1、灰度/drain)、3.5(PoP 不持 CA 主私钥、短期密钥、解密 CA per-tenant 子 CA+HSM)、3.12(PoP 失陷爆炸半径)。
>
> **消费控制面 L2 契约:** xDS server 子 L2(6 类资源、按租户订阅、fail-static、撤销独立流)、策略编译器子 L2(PEP 求值 L7PolicyBundle、写 eBPF L34RuleSet、热路径无解释器)、身份子 L2(PEP 离线验会话凭证 + TrustBundle 公钥)、计费子 L2(PoP 计量签名上报)。
>
> **隔离落地以 PoC-1 实测为据(关键):** `poc/poc1-isolation/RESULT.md`(2026-05-25,Phase1 路由层 + Phase2 真实 Envoy)已实测确立两条硬要求,本文 3.3 直接采纳。
>
> **加密栈待 PoC-G:** 数据面隧道/铜锁-Envoy 算法随国密选型(`sase-gm-crypto-selection.md`),**算法敏捷、待 PoC-G**(仅加密算法这块,不阻塞其余编排设计)。
>
> **范围:** PoP 组件构成与编排、三件套接线、租户隔离落地、PoP-agent(xDS 消费与配置落地)、PEP、fail-static 与撤销、本地遥测计量、加密栈、无状态/发布/HA、PoP 内安全与爆炸半径。
>
> **不含(明确边界):** 加密算法选定(PoC-G);PEP 求值算法/eBPF map 字节布局/L7 bundle 编码(策略编译器子 L2 契约 + 字节 schema 待 api/proto);硬件选型数值(M1 实测);控制面内部(控制面 L2);写代码/搭骨架(须另行授权)。
>
> **设计先行:** 含架构与机制说明,**不写代码**。每个决策配依据 / 备选及落选 / 可行方案;未定项标「待确认 / 待国密 / 待实测」。

---

## 目录

- 一、背景
- 二、目标
- 三、设计
  - 3.1 PoP 组件构成与编排模型
  - 3.2 数据面三件套接线
  - 3.3 租户隔离落地(采纳 PoC-1 实测结论)★
  - 3.4 PoP-agent:xDS 消费与配置落地
  - 3.5 PEP:策略求值与凭证验证
  - 3.6 fail-static 与撤销落地
  - 3.7 本地遥测与计量
  - 3.8 加密栈(待国密 PoC-G)
  - 3.9 无状态、发布与高可用
  - 3.10 PoP 内安全与爆炸半径
- 四、风险
- 五、结论与衔接
- 附录:待确认 / 待国密 / 待实测

---

## 一、背景

L1 定 PoP 为无状态数据面边缘:三件套(XDP/eBPF + WireGuard + Envoy)+ PEP + PoP-agent(xDS client)+ 本地遥测,配置由控制面经 xDS 下发、本地缓存支持 fail-static。其内部如何编排(谁驱动谁、配置怎么落地、租户隔离怎么建、fail-static/撤销怎么落、计量怎么采)此前未定义。

**且 L1 3.7 方案B 的隔离"兜底"曾标"待 PoC 证明"——现已由 PoC-1 实测解决**(`RESULT.md`):得出两条硬要求(per-tenant 表带 `unreachable default`;共享 Envoy 持 CAP_NET_ADMIN),本文据此落地。加密算法仍待 PoC-G(算法敏捷,不阻塞编排)。

---

## 二、目标(可衡量)

1. **组件构成与编排**:定 PoP 内组件与"谁编排"(PoP-agent 为本机编排器 + 唯一 xDS client)。
2. **三件套接线**:XDP→WG 解密入域→eBPF/Envoy 顺序(L1 3.7)的本机落地。
3. **租户隔离落地(PoC-1)**:每租户 namespace/路由域 + per-tenant 表(**`unreachable default`**)+ SO_MARK + TPROXY;共享 Envoy(**CAP_NET_ADMIN**);隔离测试门禁。
4. **配置落地**:PoP-agent 把 xDS 6 类资源原子落地为本机动作;按租户动态订阅;fail-static 本地缓存。
5. **PEP**:加载 L7PolicyBundle、**离线验**会话凭证(TrustBundle 公钥)、热路径无解释器。
6. **fail-static 与撤销**:控制面不可达用缓存继续;撤销独立流即时应用;短 TTL 兜底。
7. **计量**:per-tenant 字节 + 会话事件、**签名上报**(计费子 L2 契约)。
8. **无状态/发布/HA + 爆炸半径**:无持久业务数据;分批升级 + drain;不持 CA 主私钥、短期密钥。

**非目标:** 加密算法选定(PoC-G);PEP/编译器内部算法、字节 schema、硬件数值;控制面;写代码。

---

## 三、设计

### 3.1 PoP 组件构成与编排模型

**背景** PoP 内多组件(WG、Envoy、eBPF/XDP、PEP、遥测、计量),需明确谁驱动、怎么保持配置一致。

**目标** 定组件清单与编排中心。

**设计 —— 组件 + PoP-agent 为本机编排器**

| 组件 | 职责 |
|------|------|
| **PoP-agent**(Go) | **唯一 xDS client + 本机编排器**:订阅控制面资源(3.4),驱动以下所有组件落地;持本地配置缓存(fail-static) |
| WireGuard 终结 | 隧道解密、内层包入该租户路由域(3.2);加密栈待国密(3.8) |
| eBPF/XDP | 驱动层早丢 + L3/L4 规则(L34RuleSet) |
| 共享 Envoy | L7(SWG/ZTNA Web/CASB),per-tenant 配置;**持 CAP_NET_ADMIN**(3.3) |
| PEP | L7 策略求值 + 凭证验证(本文 3.5),Envoy `ext_authz`/`ext_proc` 调用 |
| 本地遥测/计量 | 指标/流日志/计量采集与上报(本文 3.7) |

**决策:PoP-agent 为单一本机编排器(集中)。** 依据:① 配置一致性——所有资源经一个 agent 原子落地,避免各组件各自订阅 xDS 导致的版本错位;② fail-static 缓存集中一处;③ 单一 xDS 连接(对接 xDS 子 L2 per-PoP 订阅)。
- 备选:各组件各自做 xDS client。落选:多连接、跨组件版本不一致、原子切换难(xDS 子 L2 的 per-PoP 原子版本无法保证)。

**部署形态(待细化):** 数据面组件需贴内核(XDP/eBPF)、需 CAP_NET_ADMIN/CAP_BPF/NET_RAW,且要管理 per-tenant netns。**PoC-1 已证特权容器内可建 netns + 跑共享 Envoy + SO_MARK(CAP_NET_ADMIN)**;但 **XDP/eBPF map 在容器内的完整性、与裸机进程(systemd)的性能/隔离权衡待 PoC/实测**(附录)。本文定编排逻辑,容器化程度留实测。

**风险** PoP-agent 单点 → agent 崩溃不应断流(数据面转发由内核/Envoy 持续,agent 只管配置);agent 重启从缓存恢复(3.6)。

**结论** PoP-agent 为唯一 xDS client + 本机编排器(集中,保配置一致与原子);组件清单如上;部署形态(容器 vs 裸机进程)待实测,PoC-1 已证特权容器路径可行。

---

### 3.2 数据面三件套接线

**背景** L1 3.7 定包生命周期顺序;本节给本机落地。

**目标** 明确包从 NIC 到出口的处理链与每租户入域点。

**设计(沿用 L1 3.7,本机落地)**
1. **NIC 收加密 UDP** → **XDP(驱动层,解密前)**:DDoS/垃圾包早丢、按源限速、WG 流量 RSS 多核分流。
2. **WireGuard 终结 + 解密**:内层包**进该租户独立路由域/namespace**(3.3);租户身份由 WG 公钥**加密绑定**确立(L1 3.2,不依赖可篡改报文头)。
3. **内层分流**:L3/L4 → eBPF map 查表(L34RuleSet);L7 → 经 TPROXY 重定向到共享 Envoy(3.3)。
4. **出口**(按租户路由域独立):→ 互联网 或 经 App Connector 反向隧道到内网。

依据:加密包先 XDP 早丢省解密 CPU;解密后才见内层、才谈 L3/L4 与 L7;**隔离在"解密入域"时由内核建立**(3.3)。

**风险** XDP 对网卡/驱动有要求 → 硬件选型纳入(M1);多核分流不均 → RSS + 队列调优(实测)。

**接入面 SPA 隐身(横切,见 `sase-l2-ztna-access-hardening.md`)** XDP 早丢栈同时承载 **SPA 单包授权**:PoP 接入端口**默认 XDP 丢包**,Agent/CPE 先 SPA 敲门 → PoP-agent **用户态验签**(eBPF 做不了非对称)通过后写 **XDP 短 TTL 白名单** 才对该源开放;缩小接入面、抗扫描/DDoS(L1 3.12)。详见该横切 L2(SPA over XDP 列 PoC 候选)。

**结论** XDP 早丢 → WG 解密入租户域 → eBPF(L3/L4)/ Envoy(L7,经 TPROXY)→ 按域出口;隔离在解密入域时建立(3.3);**接入端口经 SPA + XDP 白名单隐身**(横切 L2)。

---

### 3.3 租户隔离落地(采纳 PoC-1 实测结论)★

**背景** 这是"跨租户 0 泄漏"(L1 2.2)在 PoP 的落点,也是 L1 3.7 方案B 曾标"待 PoC 证明"之处。**PoC-1 已实测(`RESULT.md`)**,本节落地其结论。

**目标** 定每租户隔离的具体本机构造,确保 SO_MARK+共享 Envoy 的出口被内核强制绑定到正确租户域。

**设计 —— 每租户隔离构造(PoC-1 实测要求)**
- **每租户独立 network namespace / 路由域**(L1 3.2):WG 解密后内层包入该域。
- **per-tenant 路由表 + `ip rule fwmark → 该表`**:出口连接按 SO_MARK 选本租户表。
- **★ per-tenant 表必须带 `unreachable default`(PoC-1 硬要求 1)**:否则表内无匹配会 **fall-through 到 main 表跨租户泄漏**(PoC-1 Phase1/2 均复现:打租户A标记的连接够到 B)。`unreachable default` 使表内无匹配即丢、不 fall-through;实测加之后隔离成立且复用地址消歧不受损。
- **共享 Envoy 出口打 SO_MARK**:Envoy cluster `upstream_bind_config.socket_options` 设 SO_MARK=租户标记(L1 3.7 #3)。
- **★ 共享 Envoy 进程必须持 CAP_NET_ADMIN(PoC-1 硬要求 2)**:否则设 SO_MARK 静默 EPERM → SO_MARK 失效 → **全部出口连接挂掉**(PoC-1 Phase2 复现:默认镜像降权即全 connect_fail)。
- **TPROXY 透明重定向**:解密后需 L7 的流量经 TPROXY/ORIGINAL_DST 导入共享 Envoy,租户标识由来源 WG 接口/标记推导。
- **地址复用**:租户间路由域隔离,overlay 地址可复用(L1 3.6);PoC-1 已验同一 `100.64.0.10` 在两租户被 SO_MARK+per-tenant 表正确消歧。
- **隔离测试门禁**:把"per-tenant 表带 unreachable default"+"Envoy 持 CAP_NET_ADMIN"+跨租户可达性=0 纳入 PoP 自检与 CI(对接 L1 3.20、复用 PoC-1 脚本)。

依据:**全部为 PoC-1 实测结论**,非推测;两条硬要求缺一即泄漏或出口全挂(实测复现)。
- 备选(高隔离租户):方案A 每租户独立 Envoy(L1 3.7 逃生通道)。保留给超大/高隔离租户,不作默认(N 进程不可扩展)。

**风险** PoP-agent 建租户表时漏 `unreachable default` → 落地模板强制带 + 自检门禁拦截(本节);Envoy 未授 CAP_NET_ADMIN → 启动自检(无 CAP_NET_ADMIN 即拒绝服务,避免静默失效);TPROXY/VRF 全保真接线细节 → PoC-1 验了 SO_MARK 出口隔离,TPROXY 下行入流待补验(附录,不影响出口隔离结论)。

**结论** 每租户 namespace/路由域 + per-tenant 表(**强制 `unreachable default`**)+ SO_MARK + TPROXY;共享 Envoy **强制 CAP_NET_ADMIN**;两条硬要求 + 跨租户可达性=0 入门禁。**均有 PoC-1 实测背书。**

---

### 3.4 PoP-agent:xDS 消费与配置落地

**背景** PoP-agent 是本机大脑:把控制面资源变成本机内核/Envoy/PEP 状态。

**目标** 定它消费哪些资源、怎么原子落地、按租户订阅、缓存。

**设计**
- **消费 xDS 6 类资源(xDS 子 L2)→ 本机动作:**

| 资源 | 落地动作 |
|------|---------|
| `TenantRoutingDomain` | 建/拆租户 namespace/路由域 + per-tenant 表(**带 unreachable default**,3.3)+ ip rule |
| `WGPeerSet` | 配 WireGuard peer(公钥)|
| `L34RuleSet` | 写 eBPF map(L3/L4 规则)|
| `L7PolicyBundle` | 交 PEP 加载(3.5)|
| `RevocationTable` | 交 PEP/验证层即时应用(撤销,3.6)|
| `TrustBundle` | 装载会话凭证验证公钥(PEP 离线验,3.5)+ 标准 Envoy 资源 |

> 计数注:6 类 = L1 3.1 原列 4 类自定义资源 + 编译器把"eBPF 规则"细化为 `L34RuleSet`/`L7PolicyBundle`(+1)+ 新增 `TrustBundle`(+1);详见 xDS 子 L2 3.1。`TrustBundle` 已于 **L1 v0.5 回写 3.1**。注:此为含 `TrustBundle`/`L34RuleSet` 的设计资源口径,与 L1 v0.6 的「as-built 6 类」(`L7PolicyBundle`/`RevocationList`/`SWGRuleSet`/`FWRuleSet`/`DLPRuleSet`/`SiteConfig`)成员不同,勿混。

- **按租户动态订阅**:某租户在本 PoP 首次有活跃接入(WG 握手确立身份)→ 订阅其资源;无活跃超时 → 退订(对接 xDS 子 L2 3.4)。
- **原子落地**:按 xDS 的 per-PoP 原子版本切换(xDS 子 L2 3.7)——新版本整体生效或不生效,不留半新半旧;落地失败回 NACK(保留旧版,不停摆)。
- **fail-static 缓存**:PoP-agent 持久化最近 ACK 的快照(本地磁盘);控制面/xDS 不可达时用缓存继续(3.6)。

依据:单 agent 集中落地保证原子与一致(3.1);按租户订阅降量 + 限爆炸半径(L1 3.12)。

**风险** 资源落地与内核状态漂移 → 周期对账(agent 比对期望态 vs 实际 netns/eBPF/Envoy 配置,纠偏);大量租户上线订阅风暴 → 限流(xDS 子 L2)。

**结论** PoP-agent 消费 6 类资源→本机动作、按租户动态订阅、原子落地(失败 NACK 不停摆)、持久化缓存支撑 fail-static。

---

### 3.5 PEP:策略求值与凭证验证

**背景** PEP 是 L7 决策点,在 PoP 侧执行策略编译器与身份子 L2 的契约。

**目标** 定 PEP 的加载、求值、凭证验证,守"热路径无解释器""离线验"契约。

**设计**
- **加载**:PoP-agent 把 `L7PolicyBundle`(策略编译器产物)交 PEP;PEP 按其**预索引有界结构**求值(策略编译器子 L2 3.4/3.5),**热路径只查表 + 有界谓词比较,不解释 AST**(契约,性能门禁对接 L1 3.19/3.20)。
- **凭证验证(离线)**:Envoy `ext_authz` 调 PEP;PEP 用 **`TrustBundle` 里的会话凭证验证公钥离线验签**(身份子 L2 3.2),**不回调控制面**(fail-static,L1 3.1);验 `tenant_id`/`aud` 绑定(防跨租户重用)。
- **撤销即时**:PEP 查最新 `RevocationTable`(3.6)拒绝已撤凭证。
- **求值维度**:用凭证 claims(groups/posture)+ 运行期条件(time/geo/risk)匹配(策略编译器 3.6)。

依据:离线自包含验证是 fail-static 与热路径前提(身份/编译器子 L2 已定);PEP 只消费契约产物,不自造语义。

**风险** PEP 求值超预算 → 性能门禁(求值步数上界,编译器 3.5);凭证公钥轮换未及时 → TrustBundle 经 xDS 更新(3.4)。

**结论** PEP 加载 L7PolicyBundle 按有界结构求值(无解释器)、用 TrustBundle 公钥离线验凭证(验租户/aud)、即时应用撤销;只执行契约,不自造语义。

---

### 3.6 fail-static 与撤销落地

**背景** L1 3.1:控制面不可达 PoP 用缓存继续、不接受新策略;撤销走独立快速失效通道。xDS 子 L2 定了撤销独立高优先流 + 短 TTL 兜底。

**目标** 定 PoP 侧 fail-static 与撤销的本机落地。

**设计**
- **fail-static**:控制面/xDS 不可达时,PoP 用 **PoP-agent 缓存的最近 ACK 快照**继续转发(数据面由内核/Envoy 持续,不依赖 agent 在线);**不接受新策略**(无新配置即维持)。重连后增量补差(xDS 子 L2)。
- **撤销即时应用**:`RevocationTable` 经**独立高优先流**(xDS 子 L2 3.7)到达 → PoP-agent 即时更新 PEP/验证层 → 已撤凭证/证书立即被拒。
- **短 TTL 兜底**:控制面长不可达、吊销表推不到 → 会话凭证**短 TTL 到期自然失效**(身份子 L2,分钟级)——撤销最终保证不依赖网络可达。
- **撤销与 fail-static 不矛盾**:fail-static 保可用(不断流),短 TTL 保安全(撤销终生效)。

依据:三者纵深(缓存保可用 + 独立流可达时快撤 + 短 TTL 不可达时终撤),与 xDS/身份子 L2 一致。

**风险** PoP 长失联用陈旧配置 → 陈旧窗口受短 TTL 限制 + 失联告警(3.7);缓存被篡改 → 缓存完整性校验(签名,对接 L1 3.5)。

**与终端实时通道的关系(横切,见 `sase-l2-ztna-access-hardening.md` 3.4)** 终端实时控制通道是 **Agent↔控制面**(非 PoP)、用于秒级提速端侧响应;**PoP 的权威切流(吊销表 + PEP)不变**——实时通道仅提速,非安全边界,通道断/端不配合时 PoP 吊销表 + 短 TTL 仍强制。

**结论** fail-static 用缓存继续(不接受新策略)、撤销走独立流即时应用、短 TTL 兜底;三者纵深保"可用且可撤销";终端实时通道仅提速、PoP 权威切流不变(横切 L2 3.4)。

---

### 3.7 本地遥测与计量

**背景** PoP 是计量源(计费子 L2)与遥测源(L1 3.14)。

**目标** 定 PoP 侧采集与上报,守计费"签名 + 准确"契约。

**设计**
- **计量(计费子 L2 契约)**:per-tenant 字节计数(按租户路由域,L1 3.2 = 计量边界)、会话事件;**PoP 用其证书签名上报**(计费子 L2 3.5 防篡改);计量**全量不采样**(收入准确)。
- **遥测(L1 3.14)**:指标(隧道数/吞吐/解密延迟/策略评估延迟/丢包,带 tenant+pop 标签)、流日志、安全事件;上报遥测管道(单元③)。可采样(与计量区分)。
- **隔离自检**:周期跑跨租户可达性自检(复用 PoC-1 脚本思路)+ 上报(3.3 门禁的运行期延伸)。

依据:计量边界复用租户路由域;签名上报对接计费子 L2 防篡改;计量不采样、遥测可采样(计费子 L2 已定区分)。

**风险** 高基数指标成本 → 标签基数控制(L1 3.14);计量上报通道与遥测复用 → 计量路径不采样(计费子 L2)。

**结论** PoP 采 per-tenant 计量(签名、不采样)+ 遥测(可采样)上报;周期隔离自检上报;边界复用租户路由域。

---

### 3.8 加密栈(待国密 PoC-G)

**背景** PoP 的 WG 终结与 Envoy TLS 受国密影响(R7);算法随国密选型,待 PoC-G。

**目标** 定加密栈形态,算法敏捷、待 PoC-G,不阻塞其余编排。

**设计**
- **数据面隧道终结**:国密档租户 TLCP(铜锁)、非国密租户 WireGuard——与客户端/CPE **同一套加密栈与 crypto provider 抽象**(国密选型 3.2/3.7);**算法待 PoC-G**。
- **Envoy TLS**:SWG 解密走国密版 TLS(铜锁-Envoy,国密选型 3.4),解密 CA 为 **per-tenant 子 CA + HSM/受保护密钥区**(L1 3.5);**铜锁-Envoy 稳定性待 PoC-G(M-G3)**。
- **控制信令面**:PoP↔控制面 xDS、PoP↔connector 控制通道走**国密 mTLS**(国密选型 3.8 内部面)。
- **会话凭证验证**:PEP 离线验凭证用的 `TrustBundle` 公钥,其**签名算法亦随 PoC-G**(身份子 L2 LI3:会话凭证签名是 crypto provider 新增签发用途,gm-crypto 现仅覆盖隧道/PKI/TLS,PoC-G 须一并验)。
- **CAP_NET_ADMIN**:共享 Envoy 持(3.3,SO_MARK 必需);与国密无关,但同属 Envoy 启动前置。

依据:加密栈与端侧同源(不自成一套);算法敏捷使 PoC-G 结论一处切换;仅算法待定,编排不阻塞。

**风险** SM4 在 PoP CPU 无加速时吞吐不足(国密选型 RG1)→ 硬件选型纳入 SM4 加速(M1+C-G1);铜锁-Envoy 不稳 → 前置终结代理回退(国密选型 3.4)。

**结论** 加密栈与端侧同源、算法敏捷待 PoC-G(隧道/铜锁-Envoy/控制面国密 mTLS);解密 CA per-tenant 子 CA+HSM;Envoy CAP_NET_ADMIN 前置;仅算法待定。

---

### 3.9 无状态、发布与高可用

**背景** L1 3.1 无状态、3.13 N+1/灰度/drain。

**目标** 定 PoP 无持久业务数据、升级与 HA。

**设计**
- **无状态**:PoP 不持持久业务数据;配置由 xDS 派生 + 本地缓存(fail-static,非权威源);任一 PoP 经认证可服务任一租户(L1 3.1)。
- **发布**:PoP 二进制分批升级 + **优雅 drain**(在途连接靠客户端重连,L1 3.13);配置经 xDS 灰度(per-PoP 版本 + NACK 回退,3.4)。
- **HA**:PoP 内多节点 N+1 + 健康检查(L1 3.13);PoP 整体故障 → 客户端重测 RTT 切次优 PoP(无状态使其可行)。
- **重启恢复**:PoP-agent 重启从本地缓存快照恢复(3.6),不需控制面在线即可继续服务已有租户。

依据:无状态 + 缓存使升级/重启/故障切换不依赖控制面在线;沿用 L1 3.13。

**风险** 升级影响在途连接 → drain + 客户端重连;缓存与控制面版本差 → 重连对账(3.4)。

**结论** PoP 无持久业务数据、配置 xDS 派生+缓存;分批升级+drain、N+1+健康检查、客户端切换;重启从缓存恢复。

---

### 3.10 PoP 内安全与爆炸半径

**背景** L1 3.12:PoP 是高价值目标,失陷爆炸半径须受限。

**目标** 定 PoP 内安全措施,落实 L1 3.12/3.5。

**设计**
- **不持平台根密钥**:PoP **不持 Root/中间 CA 主私钥、无跨租户静态数据**(L1 3.5/3.12)。
- **短期密钥 + TTL**:PoP 持有的密钥/证书短期、限窗口(L1 3.5);失陷影响随 TTL 收敛。
- **解密 CA**:SWG 解密 CA 为 **per-tenant 子 CA + HSM/受保护密钥区**(L1 3.5),不以明文驻留磁盘;失陷只暴露本 PoP 服务的租户。
- **只持活跃租户资源**:按租户订阅(3.4)→ PoP 失陷只暴露其当前服务租户(L1 3.12)。
- **租户输入视为敌意**:数据面解析器加固/fuzzing(L1 3.12/3.20);解密内容视为敌意输入。
- **隔离强制**:3.3 的 per-tenant 表 unreachable default + namespace 是跨租户逃逸的核心控制(PoC-1 背书)。

依据:不持根密钥 + 短期密钥 + 按租户订阅 + 解密 CA 子 CA/HSM,使 PoP 失陷暴露面收敛到"本 PoP 当前服务租户、且随 TTL 失效"(L1 3.12)。

**风险** 解密 CA 在线私钥仍是高价值目标 → HSM/受保护密钥区 + 不可导出(L1 3.5);PoP-agent 被攻陷可错配隔离 → 落地模板强制 unreachable default + 自检门禁(3.3)。

**结论** PoP 不持根密钥、短期密钥限窗口、解密 CA per-tenant 子 CA+HSM、只持活跃租户资源、租户输入视敌意;失陷暴露面受限并随 TTL 收敛(L1 3.12)。

---

## 四、风险

### RP1:隔离落地漏 unreachable default 或 Envoy 缺 CAP_NET_ADMIN
PoC-1 实测:前者跨租户泄漏、后者出口全挂。缓解:落地模板强制带 `unreachable default`;Envoy 启动自检无 CAP_NET_ADMIN 即拒服务(避免静默失效);两者入隔离门禁(3.3)。

### RP2:加密栈待 PoC-G 阻塞 PoP 加密实现
缓解:仅加密算法待 PoC-G(3.8,算法敏捷、与端侧同源);其余编排(隔离/PoP-agent/PEP/fail-static/计量/HA)不阻塞、可先设计。

### RP3:PoP-agent 单点
缓解:数据面转发由内核/Envoy 持续,agent 崩不断流;agent 重启从缓存恢复(3.1/3.6);周期对账纠偏(3.4)。

### RP4:容器化程度未定影响 XDP/eBPF
缓解:PoC-1 已证特权容器跑通 netns+Envoy+SO_MARK;XDP/eBPF map 在容器内完整性 + 裸机进程权衡待 PoC/实测(附录)。

### RP5:PoP 失陷扩大暴露面
缓解:不持根密钥 + 短期密钥 + 按租户订阅 + 解密 CA 子 CA/HSM(3.10,L1 3.12)。

### RP6:fail-static 陈旧配置窗口
缓解:短 TTL 限窗口 + 失联告警(3.6/3.7);缓存完整性校验。

---

## 五、结论与衔接

**结论:** PoP 以 **PoP-agent 为唯一 xDS client + 本机编排器**(集中保配置一致与原子);三件套按 XDP→WG 解密入域→eBPF/Envoy 接线;**租户隔离落地直接采纳 PoC-1 实测两条硬要求——per-tenant 表强制 `unreachable default`、共享 Envoy 强制 CAP_NET_ADMIN**(缺一即泄漏或出口全挂,实测背书),配 namespace/路由域 + SO_MARK + TPROXY,跨租户可达性=0 入门禁;PoP-agent 消费 6 类资源原子落地、按租户订阅、缓存支撑 fail-static;PEP 加载 L7PolicyBundle 无解释器求值 + TrustBundle 公钥离线验凭证;撤销走独立流即时应用 + 短 TTL 兜底;计量签名上报(不采样);无状态 + 分批升级 drain + N+1;PoP 不持根密钥、短期密钥、解密 CA per-tenant 子 CA+HSM,失陷暴露面受限。**加密算法待 PoC-G(算法敏捷,不阻塞编排)。**

**衔接:**
- **PoC-1(`RESULT.md`)**:3.3 隔离落地的直接依据(unreachable default + CAP_NET_ADMIN)。
- **xDS server 子 L2**:6 类资源消费、按租户订阅、原子版本、撤销独立流、fail-static。
- **策略编译器子 L2**:PEP 求值 L7PolicyBundle(无解释器)、写 eBPF L34RuleSet。
- **身份子 L2**:PEP 离线验会话凭证(TrustBundle 公钥)。
- **计费子 L2**:PoP 计量签名上报契约。
- **国密选型(待 PoC-G)**:加密栈算法(隧道/铜锁-Envoy/控制面 mTLS)。
- **SD-WAN CPE 子 L2**:CPE 隧道在 PoP 终结、骨干选路(本文 PoP 侧)。

搭脚手架 / 写代码须**另行授权**(设计先行)。

---

## 附录:待确认 / 待国密 / 待实测

| # | 项 | 性质 | 去向 |
|---|----|------|------|
| LO1 | PoP 部署形态:特权容器 vs 裸机进程(systemd)的性能/隔离权衡;XDP/eBPF map 在容器内完整性 | 形态 | PoC/实测(PoC-1 已证特权容器跑 netns+Envoy+SO_MARK) |
| LO2 | 加密栈算法(隧道 TLCP/WireGuard、铜锁-Envoy、**会话凭证签名**) | 待国密 | PoC-G(凭证签名见身份子 L2 LI3) |
| LO3 | TPROXY 下行透明入流全保真接线(PoC-1 只验了 SO_MARK 出口隔离) | 机制 | PoC-1 续验 / 实测 |
| LO4 | 单 PoP 租户 namespace 数量上限与开销 | 待实测 | M3(L1 附录 B)/ PoC-1 I-4 |
| LO5 | 单 PoP 10Gbps 吞吐(国密后按 SM4) | 待实测 | M1 + 国密选型 M-G1 |
| LO6 | PoP-agent 对账周期与纠偏策略 | 参数 | 实施期 |
| LO7 | fail-static 缓存的持久化与完整性校验细节 | 机制 | 实施期(对接 L1 3.5 签名) |

> 说明:本 L2 的租户隔离落地(3.3)以 **PoC-1 实测**为据(unreachable default + CAP_NET_ADMIN);加密算法待 PoC-G(算法敏捷,不阻塞);TPROXY 下行入流、namespace 规模、吞吐待续验/实测。
