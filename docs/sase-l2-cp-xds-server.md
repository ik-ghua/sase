# 控制面 L2 子文档 · xDS server(配置分发)

> **状态:** L2 组件设计 / 机制深挖 / 待评审
> **版本:** v0.1
> **日期:** 2026-05-24
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **层级与上承:** L2 子文档,深挖**控制面单元②(配置分发,xDS server)**。上承控制面 L2 总览 `sase-l2-control-plane-overview.md` 的 3.1(PolicyBundle 入库 + 通知交接、xDS server 读库下发、对业务逻辑零依赖)、3.4(xDS 快照机制点名)、LC4(变更通知机制待定);及 L1 `sase-architecture-design.md` v0.6 的 **3.1(xDS 传输机制、标准/自定义资源、fail-static、无状态 PoP)**、3.4(单元②职责)、3.11(xDS 契约、go-control-plane)、3.5(吊销表快速失效)、3.7(共享 Envoy per-tenant listener/route/cluster)、3.12(PoP 爆炸半径)、3.14(xDS 推送滞后)。
>
> **上承下游文档:** 消费 数据访问层子 L2 `sase-l2-cp-data-access-rls.md`(读库经 `data` 层)、策略编译器子 L2 `sase-l2-cp-policy-compiler.md`(其产 `L34RuleSet`/`L7PolicyBundle`)。**对端是 PoP 单机编排 L2**(PoP 侧 xDS 客户端如何消费,属 PoP L2,部分待 PoC-1)。
>
> **为什么深挖它:** 它是控制面到全国 PoP 的**唯一下发通道**,也是控制面↔PoP 的**契约接口**;撤销实时性、配置一致性、fail-static 都落在这里。
>
> **范围:** 资源模型与 type URL、传输语义(ADS/增量/ACK-NACK/版本)、快照构建与一致性、per-PoP 资源作用域、变更通知(解 LC4)、无状态水平扩展、fail-static 与撤销独立流、安全(mTLS + 作用域授权)、可观测、go-control-plane 选型。
>
> **不含(明确边界):** **PoP 侧 xDS 客户端如何消费/落地资源**(eBPF 写入、Envoy 加载、PEP 加载——PoP L2);资源的**字节级 schema**(随 PoP L2 与 `api/proto` 契约细化);各资源**内容如何编译/生成**(策略编译器子 L2 等已定)。**本文定"分发机制 + 资源契约的传输语义",不定 PoP 如何执行资源。**
>
> **设计先行:** 含机制与契约语义说明,**不写 xDS server 代码、不搭脚手架**。每个决策配依据 / 备选及落选 / 可行方案;未定项标「待确认 / 待实测 / 待 PoP L2」。

---

## 目录

- 一、背景
- 二、目标
- 三、设计
  - 3.1 资源模型与 type URL
  - 3.2 传输语义:ADS + 增量 xDS + 版本/ACK-NACK
  - 3.3 快照构建与一致性
  - 3.4 节点标识与 per-PoP 资源作用域
  - 3.5 变更通知机制(解 LC4)
  - 3.6 无状态与水平扩展
  - 3.7 fail-static 与撤销独立流
  - 3.8 版本化、ACK/NACK、回滚
  - 3.9 安全:mTLS + 作用域授权
  - 3.10 可观测性
  - 3.11 go-control-plane 选型
- 四、风险
- 五、结论与衔接
- 附录:待确认 / 待实测 / 待 PoP L2

---

## 一、背景

L1 3.1 把配置分发定为复用 **xDS 传输机制**(gRPC streaming + 版本 + ACK/NACK + 增量),并区分**标准 Envoy 资源**(LDS/RDS/CDS/EDS,Envoy 专有 schema)与**自定义资源**(WG peer、eBPF 规则、吊销表、租户路由域);3.4 把它列为独立单元(长连流式负载,与 CRUD 特征不同,无持久存储);总览定它**读库下发、对业务逻辑零依赖、无状态可水平扩展**,但把变更通知机制(LC4)留待定,快照机制只点名。

本文回答:**控制面如何把"已编译的配置"一致、及时、按需、安全地下发到全国 PoP,且撤销不被大配置推送拖慢,控制面挂了 PoP 仍能服务(fail-static)。** 它同时是控制面与 PoP L2 之间的契约接口。

---

## 二、目标(可衡量)

1. **资源模型**:枚举标准 Envoy 资源与自定义资源类型、各自 type URL 与生产者,全部按 `tenant_id` 命名空间化。
2. **传输语义**:定 ADS(聚合)+ 增量 xDS + 版本/nonce + ACK/NACK 的使用方式。
3. **一致性**:跨资源引用不出现"引用了尚未下发的资源"的瞬态坏配(make-before-break)。
4. **按需作用域**:一个 PoP 只收到**它服务的租户**的资源(降量 + 限爆炸半径,L1 3.12)。
5. **无状态水平扩展**:xDS server 无持久数据,快照由 DB 派生;多实例,PoP 连任一实例结果一致。
6. **撤销实时**:吊销表下发**不被大配置推送队头阻塞**,撤销 < 分钟级(L1 3.8);控制面不可达时短 TTL 凭证兜底(fail-static)。
7. **安全**:PoP 经 mTLS 认证(L1 3.5);只发其有权且订阅的租户资源。
8. **可观测**:推送滞后、ACK/NACK 率、快照版本 lag、流数可观测(L1 3.14);规模化推送压力实测(M4)。

**非目标:** PoP 侧消费实现(PoP L2);资源字节级 schema(契约细化);资源内容的编译/生成(各生产者子 L2);PoP 选址/RTT 选路(L1 3.13,客户端行为)。

---

## 三、设计

### 3.1 资源模型与 type URL

**背景** L1 列了资源种类但未系统化。分发的第一件事是定清"分发什么"。

**目标** 枚举资源类型、生产者、命名空间,作为控制面↔PoP 契约的骨架。

**设计 —— 资源清单(均按 `tenant_id` 命名空间化;字节级 schema 见附录)**

| 类别 | 资源 | 生产者(控制面模块) | 内容 |
|------|------|---------------------|------|
| 标准 Envoy | LDS/RDS/CDS/EDS(per-tenant) | `resource`(应用→cluster、连接器→endpoint)+ `policy`(路由) | 共享 Envoy 的 per-tenant listener/route/cluster(L1 3.7) |
| 自定义 | `L34RuleSet` | `policy.compiler`(编译器子 L2) | L3/L4 eBPF 规则(网络分段) |
| 自定义 | `L7PolicyBundle` | `policy.compiler` | L7 PEP 决策结构 |
| 自定义 | `WGPeerSet` | `identity`/`resource` | 该租户在该 PoP 的 WireGuard peer 公钥集(Agent/连接器) |
| 自定义 | `TenantRoutingDomain` | `tenant` | 租户路由域/namespace 配置(L1 3.2) |
| 自定义 | `RevocationTable` | `identity`/PKI | 吊销的凭证/证书(快速失效,L1 3.5;独立流,3.7) |
| 自定义 | `TrustBundle` | `identity`/PKI | **会话凭证验证公钥**(PoP 离线验凭证用,身份子 L2 3.2)+ 信任材料;签发密钥轮换时更新(L1 3.5) |

> 与 L1 对账:L1 3.1 列 4 类自定义资源(WG peer、eBPF 规则、吊销表、租户路由域);本文 ① 把"eBPF 规则"按编译器子 L2 产出**细化为 `L34RuleSet`(L3/L4)+ `L7PolicyBundle`(L7 PEP)**(+1);② **新增 `TrustBundle`**(会话凭证验证公钥/信任材料,源自身份子 L2 的凭证离线验证需求,L1 未列)(+1)。故自定义资源由 L1 的 4 类增至 **6 类**——属细化 + 新增,非计数不一致;`TrustBundle` 已于 L1 v0.5 补入 3.1 资源清单。**注:本节「6 类」是含 `TrustBundle`/`L34RuleSet`/`WGPeerSet` 的设计资源口径;L1 v0.6 另有「as-built 6 类」指已编码的 `L7PolicyBundle`/`RevocationList`/`SWGRuleSet`/`FWRuleSet`/`DLPRuleSet`/`SiteConfig`(`TrustBundle`/`L34RuleSet`/`WGPeerSet` 仍待后续刀)——两组都恰为 6 但成员不同,对账勿混。**

- **命名空间:** 资源名形如 `tenant/<tenant_id>/<kind>/<name>`;PoP 按租户订阅(3.4)。
- **标准 vs 自定义:** 标准资源走 go-control-plane 的 Envoy schema(供共享 Envoy);自定义资源用自定义 type URL,经同一 xDS 传输承载,供 PoP-agent 消费(L1 3.1/3.11)。
- **生产者解耦:** xDS server **不生产内容**,只从 DB 读各模块写入的资源、组装下发(总览"对业务逻辑零依赖")。

依据:资源清单 = 控制面↔PoP 的契约骨架;命名空间化支撑 per-PoP 按租户作用域(3.4)与多租户隔离(L1 3.2)。

**风险** 资源清单后续增项(如新增安全能力)→ type URL 可扩展、版本化契约(`api/proto`,总览 3.6);标准/自定义混用一条流的排序 → ADS + 依赖序(3.2/3.3)。

**结论** 六类资源(1 标准 per-tenant + 5 自定义),按 `tenant/<id>/...` 命名;xDS server 只读不产;清单即控制面↔PoP 契约骨架。

---

### 3.2 传输语义:ADS + 增量 xDS + 版本/ACK-NACK

**背景** xDS 有多种传输形态(SotW 全量 / Delta 增量;分资源流 / 聚合 ADS)。多租户下资源量大,选型直接影响推送开销与一致性。

**目标** 选定传输形态,兼顾规模化推送开销与跨资源一致性。

**设计 —— 决策**

| 维度 | 决策 | 依据 | 备选及落选 |
|------|------|------|-----------|
| 全量 vs 增量 | **增量(Delta xDS)** | 多租户 + 上千 PoP,每次推全量资源集开销大(L1 M4 风险);Delta 只发变化资源,契合"按需订阅"(3.4)与 L1 3.1 明示的"增量" | **SotW 全量**:实现简单,但规模化每次推整集、带宽/CPU 浪费 → 落选(起步即用 Delta,go-control-plane 支持) |
| 聚合 vs 分流 | **ADS(聚合发现,单流有序)** | 单 mTLS 流承载所有资源类型、保证下发**有序**(避免"路由引用了尚未到的 cluster"的瞬态坏配,3.3) | **每类型独立流**:跨类型到达无序、易瞬态坏配 → 落选(撤销除外,见下) |
| 版本/确认 | **per-资源类型 version + nonce + ACK/NACK** | xDS 原生一致性语义(L1 3.1):PoP ACK 已应用版本、NACK 拒绝坏配并回报 | 无可选(xDS 原生语义,非自选项) |
| 例外 | **`RevocationTable` 走独立高优先流(不聚合)** | 撤销不能被大 bundle 推送队头阻塞(3.7) | 与 ADS 聚合:HoL 阻塞致撤销延迟 → 对零信任不可接受,落选 |

依据:ADS+Delta 是"规模化省量 + 跨资源一致"的组合;撤销因实时性要求**破例**走独立流(3.7),其余聚合。

**风险** Delta 状态机比 SotW 复杂(资源增删跟踪)→ 用 go-control-plane 的 delta 实现(3.11),不自研;ADS 单流故障影响该 PoP 全部资源 → 流断 PoP 重连重订阅(3.6),fail-static 期间用缓存(3.7)。

**结论** ADS + 增量 xDS + per-type 版本/ACK-NACK;`RevocationTable` 破例走独立高优先流;复用 go-control-plane delta,不自研状态机。

---

### 3.3 快照构建与一致性

**背景** xDS server 无持久存储,每次按 DB 状态构 per-PoP 快照。构建顺序错会下发瞬态坏配。

**目标** 定快照如何从 DB 派生、如何保证跨资源引用一致。

**设计**
- **快照来源(按租户读、内存聚合):** xDS server 对该 PoP 的**每个订阅租户分别**经数据层子 L2 的**只读事务入口 `InTxRO`(单租户上下文,只读角色 `app_ro`)** 读其各类资源(3.1),**在内存里按 PoP 聚合**成 per-node 快照(go-control-plane snapshot)。依据:数据层的 RLS 上下文是**单租户/事务级**(数据层子 L2,`InTx` 每事务一个 `tenant_id`),故"一个 PoP 读多租户"=**按租户多次单租户读 + 内存聚合**,而非一次跨租户读——这与"按租户增量重建"(下文风险)天然一致。
  > 衔接:`app_ro`(只读、无 BYPASSRLS、受 RLS 约束)与 `InTxRO` 为**数据层子 L2 本次新增**(原仅 `app_rw`);见该文 3.2/3.5 与门禁 G2。
- **一致性:** 每租户的读在其单租户 `InTxRO` 内一致(不读半更新);跨租户聚合的瞬时不一致由原子版本切换(下文)+ 跨 PoP 最终一致(3.6)消化。
- **资源依赖序(make-before-break):** 同一快照内,被引用资源先于引用者:`TenantRoutingDomain`/`WGPeerSet`(连通性基础)→ 标准 CDS/EDS(cluster/endpoint)→ LDS/RDS(listener/route)→ `L34RuleSet`/`L7PolicyBundle`(策略)。go-control-plane 按 Envoy 规则处理标准资源序;自定义资源序由 xDS server 在快照内保证。
- **原子版本:** 每次重建产新快照版本号,PoP 整体切换到新版(对接编译器子 L2 的 PolicyBundle 原子激活)。
- **一致性边界:** 跨 PoP 不要求同时一致(各 PoP 独立 ack);撤销实时性不依赖此(走独立流 3.7)。

依据:一致性读 + 依赖序 + 原子版本,消除"引用未到资源"的瞬态坏配;跨 PoP 最终一致可接受(L1 3.1 无状态 PoP)。

**风险** DB 读与下发间状态又变 → 下次通知触发再重建(3.5),版本单调收敛;大租户快照构建耗时 → 按租户增量重建(只重建变化租户的资源,配合 Delta 3.2)。

**结论** 快照由 DB 一致性读派生;同快照内按依赖序(连通性→cluster→listener→策略)make-before-break;原子版本切换;跨 PoP 最终一致。

---

### 3.4 节点标识与 per-PoP 资源作用域

**背景** PoP 是无状态的、任一 PoP 可服务任一租户(L1 3.1 RTT 选路)。但不应给每个 PoP 推全部租户资源——既浪费又扩大爆炸半径(L1 3.12)。

**目标** 定 PoP 只收到"它当前服务的租户"资源的机制。

**设计**
- **节点标识:** PoP-agent 以 node id(PoP 标识)+ mTLS 身份(PoP 证书,L1 3.5)接入 xDS server。
- **按租户动态订阅:** PoP 上**某租户首次有活跃接入**(WG 握手确立租户身份,L1 3.2)时,PoP-agent 经增量 xDS **订阅该租户资源名**(`tenant/<id>/*`);租户在该 PoP 无活跃接入并超时后**退订**。xDS server 只下发被订阅且有权的资源。
- **依据:** ① 降量——单 PoP 只持活跃租户资源(L1 3.2 "每 PoP 仅为有活跃用户的租户创建");② 限爆炸半径——PoP 被攻陷只暴露其当前服务租户(L1 3.12);③ 契合 Delta 的资源级订阅(3.2)。
- **冷启动延迟(设计点):** 租户首个用户接入触发"订阅→拉取→生效",引入首连额外延迟。缓解:对高频租户按 tenant→PoP 亲和**预热订阅**;延迟量级**待实测**(附录),不臆造。

- 备选:给每 PoP 推全部租户资源。落选:资源量随租户数线性膨胀、爆炸半径=全租户,违背 L1 3.2/3.12。
- 备选:控制面维护 tenant→PoP 静态分配。落选:与 RTT 动态选路(L1 3.13)、无状态 PoP 冲突,且租户分布动态。

**风险** 订阅风暴(大量租户同时上线)→ 订阅限流 + 批量;退订时机过激致频繁订阅/退订抖动 → 退订加保持窗口(hysteresis)。

**结论** PoP 按 node+mTLS 接入,**按租户活跃动态订阅/退订**;只发订阅且有权资源;降量 + 限爆炸半径;冷启动延迟靠亲和预热,量级待实测。

---

### 3.5 变更通知机制(解 LC4)

**背景** 总览 LC4 留了"DB 变更如何触发 xDS server 重建下发"未定:LISTEN/NOTIFY vs 内部 gRPC vs 轮询。

**目标** 选定通知机制,使配置变更低延迟传播,且不与 api-server 强耦合。

**设计 —— 决策:Postgres `LISTEN/NOTIFY`(低延迟信号)+ 周期对账(兜底)。**
- api-server 模块写入资源/PolicyBundle 后,在同事务发 `NOTIFY <channel>`(带租户/资源标识);xDS server `LISTEN` 收到后,**读该租户变化资源、重建其快照、按订阅下发**。
- **NOTIFY 不持久**(订阅者断连期间的通知丢失)→ xDS server **(重)连 DB 后做一次全量对账读**,且**周期对账**(低频)作兜底,保证不依赖"每条 NOTIFY 都收到"。
- **依据:** ① DB 是单元间交接真相源(总览 3.1),NOTIFY 让 xDS server 仍**只依赖 DB**、不与 api-server 直接耦合(保持解耦);② NOTIFY 低延迟(亚秒)优于轮询;③ 周期对账 + 重连全量读消除 NOTIFY 不可靠的隐患。
- 备选:**内部 gRPC**(api-server 直接通知 xDS server)。落选:api-server 与 xDS server 直接耦合,违背总览"经持久化交接物解耦";xDS server 要感知 api-server 拓扑。
- 备选:**纯轮询**。落选:延迟与 DB 负载难两全(低延迟需高频轮询)。

**风险** NOTIFY payload 大小限制 → 只传标识,内容回读 DB;对账读放大 DB 负载 → 对账低频 + 按租户增量;通道风暴 → 合并去抖(对接编译器子 L2 3.8 防抖)。

**结论** LISTEN/NOTIFY 低延迟信号 + 重连全量对账 + 周期对账兜底;xDS server 仍只依赖 DB,与 api-server 解耦;解 LC4。

---

### 3.6 无状态与水平扩展

**背景** L1 3.4/总览定 xDS server 无持久存储、可水平扩展。但它持有大量长连流(连接态)。

**目标** 明确"无持久数据"下的多实例扩展与流分布。

**设计**
- **无持久数据:** 快照在内存、由 DB 派生(3.3);实例重启 → 重新 LISTEN + 全量对账重建(3.5),无需持久化快照。
- **多实例 + LB:** 多个 xDS server 实例,PoP 经 LB/域名连任一实例;因快照由同一 DB 派生,**连哪个实例结果一致**。
- **流分布:** PoP 长连分散到各实例;某实例故障 → 其上 PoP 重连到其他实例并重订阅(3.4),fail-static 期间用缓存(3.7)。
- **扩展维度:** 瓶颈是长连数 × 快照构建/推送 CPU;按 PoP 数与资源变更率横向加实例。规模化推送压力**待实测(M4)**。

依据:无持久 + DB 派生使任一实例可服务任一 PoP,水平扩展无状态协调;与 CRUD 单元(api-server)分离正因其连接/推送负载特征不同(L1 3.4)。

**风险** 全部实例同时重启致 DB 对账风暴 → 滚动重启 + 对账限流;长连内存随 PoP 数增长 → 监控 + 按需扩容(L1 3.14)。

**结论** 内存快照 DB 派生、无持久;多实例 + LB,PoP 连任一实例一致;故障重连重订阅;推送压力 M4 待实测。

---

### 3.7 fail-static 与撤销独立流

**背景** L1 3.1 定 fail-static(控制面不可达,PoP 用缓存继续、不收新策略),但**撤销不能等控制面恢复**——走独立快速失效通道(短 TTL + 吊销表)。这三者的协同是安全关键。

**目标** 定 fail-static 下 xDS server 侧行为,及撤销如何不被拖慢、不可达时如何兜底。

**设计 —— 三者协同**
1. **fail-static(PoP 侧主导,xDS server 配合):** 控制面/xDS server 不可达时,PoP 用**最后一次 ACK 的快照**继续转发,不接受新配置。xDS server 侧:PoP 重连后按当前快照版本**重新同步**(增量补差)。
2. **撤销独立高优先流(xDS server 主导):** `RevocationTable` 走**独立 xDS 流**(3.2 例外),不与大配置 ADS 流复用 → 撤销事件触发后**立即**重建吊销表快照并推送,不被大 PolicyBundle 推送队头阻塞。依据:撤销 < 分钟级(L1 3.8),HoL 阻塞不可接受。
3. **短 TTL 兜底(控制面不可达时):** 若控制面不可达、吊销表推不到 PoP,则**短 TTL 凭证到期自动失效**(L1 3.5)——撤销的最终保证不依赖网络可达。即:吊销表是"可达时的快速撤销",短 TTL 是"不可达时的兜底撤销"。

依据:三者构成撤销的纵深——独立流保证可达时快(不被阻塞)、短 TTL 保证不可达时也终会失效;fail-static 保证可用性(控制面挂不断流)与撤销安全(短 TTL)不矛盾。

**风险** 独立撤销流自身故障 → 短 TTL 兜底(故设 TTL 为分钟级,L1 3.1);PoP 长期失联用陈旧配置 → 陈旧窗口受短 TTL 限制(L1 3.1),并告警失联 PoP(3.10)。

**结论** fail-static 用缓存保可用 + PoP 重连补差;撤销走独立高优先流避队头阻塞(可达时快);短 TTL 兜底(不可达时终失效);三者纵深保证"可用且可撤销"。

---

### 3.8 版本化、ACK/NACK、回滚

**背景** xDS 原生版本/确认语义需明确用法,尤其 NACK(PoP 拒绝坏配)与回滚。

**目标** 定版本、ACK/NACK 处理、回滚动作。

**设计**
- **版本:** per-资源类型 version(+ nonce);快照重建产新版,PoP ACK 已应用版本。
- **ACK:** PoP 应用成功回 ACK(携版本)→ xDS server 记录该 PoP 已达版本(可观测,3.10)。
- **NACK(关键):** PoP 校验失败拒绝坏配、回 NACK + 错误 → xDS server **保留 PoP 当前运行的旧版(不强推坏配)**、记录并**告警**(3.10)。坏配不会使 PoP 失效(它继续用旧版)。
- **回滚:** 上层(编译器子 L2)激活上一 PolicyBundle 版本 → 触发通知(3.5)→ xDS server 重建为"旧内容的新快照版"下发。即回滚在内容层(激活旧 bundle),传输层照常版本前进。
- **幂等:** 内容未变(`content_hash` 同——该字段为编译器子 L2 新增、已于 L1 v0.5 回写 3.3)→ 不产新快照、不推送(对接 3.5 去抖)。

依据:NACK 保留旧版是 fail-safe(坏配不致停摆);回滚复用"激活旧内容"而非传输层倒退版本,语义清晰。

**风险** 反复 NACK(PoP 持续拒配)→ 告警 + 阻断该版本继续推、人工介入;版本与内容版本(PolicyBundle version)两套编号混淆 → 文档与契约明确区分"传输版本(xDS)"与"内容版本(PolicyBundle)"。

**结论** per-type 版本 + ACK 记录达成 + NACK 保留旧版并告警(坏配不停摆)+ 回滚=激活旧内容触发新快照 + 幂等跳过无变化。

---

### 3.9 安全:mTLS + 作用域授权

**背景** xDS 流承载全部租户配置,是高价值目标;PoP 被攻陷的爆炸半径须受限(L1 3.12)。

**目标** 定 PoP 接入认证与资源授权,限爆炸半径。

**设计**
- **认证:** PoP 经 **mTLS** 接入 xDS server,用 PoP 证书(PoP CA 签发,L1 3.5);xDS server 验证证书 + 撤销状态。
- **授权(作用域):** xDS server 只对某 PoP 下发**它有权且已订阅**的租户资源(3.4)。即便 PoP 请求未授权租户资源也拒绝。
- **限爆炸半径:** PoP 只持其活跃租户的资源(3.4)→ 单 PoP 失陷只暴露这些租户(L1 3.12);PoP 不持 CA 主私钥(L1 3.5)。
- **传输保护:** gRPC over mTLS,控制面侧证书校验;xDS server 自身用**只读角色 `app_ro`(SELECT-only、无 BYPASSRLS、受 RLS 约束)按租户 `InTxRO` 读**(3.3),不具写权限。`app_ro` 为数据层子 L2 本次新增。

依据:mTLS + 按订阅授权 + 只读最小权限,使 xDS 通道与 PoP 失陷的暴露面都被收敛(L1 3.12)。

**风险** PoP 证书泄露 → 撤销(吊销表)+ 短 TTL(L1 3.5);xDS server 被攻陷可下发恶意配置 → xDS server 属控制面信任域、最高防护(L1 3.12 控制面被攻陷=最高),且它只读 DB、不产内容,恶意构造受限;NACK 可作 PoP 侧对异常配置的最后一道校验(3.8)。

**结论** PoP mTLS 接入(PoP 证书)+ 按订阅作用域授权 + 只读最小权限连 DB;PoP 只持活跃租户资源限爆炸半径(L1 3.12)。

---

### 3.10 可观测性

**背景** L1 3.14 把"xDS 推送滞后"列为控制面指标;M4 把规模化推送列为待实测。

**目标** 定 xDS server 的指标与告警,支撑容量与 SLO。

**设计 —— 指标(带 `pop`、`resource_type` 标签)**
- 推送滞后(变更→PoP ACK 的延迟)、ACK/NACK 率与计数、各 PoP 已达版本与 lag(落后当前快照版本的程度)、活跃流数、快照重建耗时、订阅/退订速率(3.4)、撤销流推送延迟(单列,3.7)。
- **告警:** NACK 突增(坏配,3.8)、PoP 失联(fail-static 进行中,3.7)、推送滞后超阈、版本 lag 持续。
- **对接:** 指标入遥测管道(总览单元③);撤销推送延迟单列 SLO(撤销 < 分钟级,L1 3.8)。
- **规模化:** 上千 PoP × 多租户的推送延迟/内存为 **M4 待实测**(L1 附录 B),不臆造。

依据:推送滞后/版本 lag/NACK 是配置面健康的核心信号;撤销延迟单列因其有独立 SLO。

**风险** 高基数标签(pop×resource_type×tenant)成本 → 控制标签基数(tenant 维度聚合或采样,对接 L1 3.14)。

**结论** 推送滞后/ACK-NACK/版本 lag/流数/撤销延迟可观测,入遥测管道;撤销延迟单列 SLO;规模化压力 M4 待实测;控制标签基数。

---

### 3.11 go-control-plane 选型

**背景** L1 3.11 提"可基于 go-control-plane 自定义资源能力,或等价自研 streaming"。需定。

**目标** 定 xDS server 实现基座。

**设计 —— 决策:基于 `go-control-plane`(snapshot cache + delta + 自定义资源 via type URL)。**
- 依据:① 复用成熟的 xDS server 实现(版本/nonce/ACK/NACK/ADS/Delta 状态机),不重造 L1 3.1 要求的传输语义;② 其 `resource.Resource` 抽象支持**自定义 type URL**,可承载本文 6 类自定义资源(3.1);③ 与 Envoy 标准资源同栈(共享 Envoy 用,L1 3.7)。
- 备选:**自研 streaming 服务**。落选:重造 ACK/NACK/版本/Delta 状态机,成本高且易错(L1 3.1 的传输语义正是不想自造的);仅当 go-control-plane 无法承载自定义资源时才考虑——而它能(type URL)。
- **可行落地:** 标准资源用 go-control-plane 的 Envoy 类型;自定义资源实现 `resource.Resource` 接口 + 自定义 marshal(`api/proto`,总览 3.6);撤销独立流(3.7)用单独的 cache/stream 实例。

**风险** go-control-plane 对自定义资源的 delta 支持细节 → PoC 验证(与 M4 一并);版本升级跟随 → 锁定版本 + 定期升级(对接 L1 3.21 选型维护)。

**结论** 基于 go-control-plane(snapshot cache + delta + 自定义 type URL);自研落选;撤销流用独立 cache 实例;自定义资源 marshal 走 proto 单一来源。

---

## 四、风险

### RX1:规模化推送延迟/内存(L1 M4)
上千 PoP × 多租户的推送压力未实测。缓解:Delta + 按租户订阅降量(3.2/3.4)、水平扩展(3.6)、可观测告警(3.10);**M4 PoC 实测,不臆造**。

### RX2:撤销被大配置推送队头阻塞
缓解:`RevocationTable` 独立高优先流(3.2/3.7);短 TTL 兜底(3.7)。

### RX3:瞬态坏配(引用未到资源)
缓解:ADS + 快照内依赖序 make-before-break + 一致性读(3.2/3.3)。

### RX4:NOTIFY 丢失致配置陈旧
缓解:重连全量对账 + 周期对账兜底(3.5),不依赖单条 NOTIFY。

### RX5:PoP 失陷扩大暴露面
缓解:按订阅作用域授权 + 只持活跃租户资源(3.4/3.9);PoP 不持 CA 主私钥(L1 3.5/3.12)。

### RX6:坏配使 PoP 失效
缓解:NACK 保留旧版不强推(3.8);PoP 侧校验为最后一道(契约,PoP L2)。

### RX7:冷启动订阅延迟影响首连
缓解:tenant→PoP 亲和预热(3.4);延迟量级待实测(附录),必要时调整预热策略。

---

## 五、结论与衔接

**结论:** xDS server 是控制面**无状态**配置分发单元:分发 1 类标准 Envoy(per-tenant)+ 6 类自定义资源(3.1,含 `TrustBundle` 凭证验证公钥),全部按 `tenant/<id>` 命名;传输用 **ADS + 增量 xDS + 版本/ACK-NACK**,`RevocationTable` 破例走**独立高优先流**避队头阻塞;快照由 **DB 一致性读派生**、按依赖序 make-before-break、原子版本切换;PoP **按租户活跃动态订阅**,只收有权资源(降量 + 限爆炸半径);变更通知用 **LISTEN/NOTIFY + 重连/周期对账兜底**(解 LC4),保持与 api-server 解耦;**fail-static(缓存保可用)+ 撤销独立流(可达时快)+ 短 TTL(不可达时终失效)** 三者纵深;NACK 保留旧版不停摆;基于 **go-control-plane**。

**衔接:**
- **PoP 单机编排 L2(部分待 PoC-1):** PoP 侧 xDS 客户端如何消费各资源(写 eBPF、加载 Envoy/PEP)是 PoP 实现,须遵守本文资源契约(3.1)与 fail-static/撤销语义(3.7)。
- **策略编译器子 L2:** 产 `L34RuleSet`/`L7PolicyBundle`,经 DB 由本单元下发(已定)。
- **数据访问层子 L2:** 本单元经**只读角色 `app_ro` + 只读事务入口 `InTxRO` 按租户读**(3.3);`app_ro`/`InTxRO` 为该文本次新增(原仅 `app_rw`),已联合修订。
- **`identity`/`tenant`/`resource` 模块:** 产 `WGPeerSet`/`TenantRoutingDomain`/`RevocationTable`/`TrustBundle`(凭证验证公钥)/标准 Envoy 资源(总览模块分解)。
- **遥测管道(单元③):** 消费本单元指标(3.10)。
- 与国密无关(不依赖 PoC-G);字节级 schema 与 PoP 消费实现待 PoP L2 / 契约。

搭 monorepo / 写 xDS server 代码须另行授权(设计先行)。

---

## 附录:待确认 / 待实测 / 待 PoP L2

| # | 项 | 性质 | 去向 |
|---|----|------|------|
| LX1 | 6 类自定义资源的字节级 schema(type URL、proto 字段) | 契约 | `api/proto` 单一来源 + PoP L2 |
| LX10 | `TrustBundle`(凭证验证公钥/信任材料)的下发形态:独立资源 vs 并入信任 bundle | 契约 | 与身份子 L2 LI7 一并定 |
| LX2 | PoP 侧 xDS 客户端消费实现(eBPF 写入、Envoy/PEP 加载) | 实现 | PoP L2(守本文 3.1/3.7 契约) |
| LX3 | 规模化推送延迟/内存(上千 PoP × 多租户) | 待实测 | M4(L1 附录 B)/ PoC |
| LX4 | 冷启动订阅→生效延迟,及预热策略有效性 | 待实测 | 与 M4 一并 / PoP L2 |
| LX5 | 撤销独立流是"独立 gRPC 流"还是"独立 ADS 类型优先级",及其 SLO 目标值 | 机制细化 | 与 PoP L2 契约一并定 |
| LX6 | go-control-plane 对自定义资源 Delta 的支持细节 | 选型验证 | PoC(与 M4) |
| LX7 | 退订保持窗口(hysteresis)时长 | 参数 | 实测调参 |
| LX8 | 只读角色 `app_ro` + 只读事务入口 `InTxRO`(SELECT-only、无 BYPASSRLS、受 RLS;供 xDS 按租户读) | 衔接(已联合修订) | 数据访问层子 L2(本轮已补 3.2/3.5/G2) |
| LX9 | 撤销推送延迟 SLO 目标值 | 指标目标 | 与 PoP L2 一并定 |

> 说明:本子 L2 解了总览 LC4(变更通知=LISTEN/NOTIFY + 对账兜底),定了控制面↔PoP 的分发机制与资源契约骨架;PoP 侧消费、字节级 schema、规模化实测(M4)留 PoP L2 / 契约 / PoC。不依赖国密 PoC-G。
