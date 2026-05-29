# 客户端 Agent / Connector L2 组件软件架构

> **状态:** L2 组件设计 / 待评审
> **版本:** v0.1
> **日期:** 2026-05-25
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **层级与上承:** L2 组件设计,对象为 **ZTNA 端侧**——端点 Agent(用户设备)、App Connector(客户网络内,出站反向)、Agentless(浏览器 + PoP 侧身份感知反代)。上承 L1 `sase-architecture-design.md` v0.6 的 **3.8(轨道一 ZTNA:Agent/Connector/Agentless、反向连接器协议、访问决策流、设备姿态)**、3.6(split-DNS、连接器屏蔽内网拓扑)、3.5(Agent/Connector 证书、私钥本地生成)、3.11(`Enroll`/`Register` 协议、QUIC 数据通道)、3.13(RTT 选路、不硬编码 IP)、3.2(租户绑定)。落实已定:**ZTNA(P1)先行**、软件优先。
>
> **收口两个跨文档悬留契约:** 本文 3.3 定义**设备姿态 schema**,即身份子 L2 `sase-l2-cp-identity-idp.md` 的 **LI5(posture 取值域)** 与策略编译器子 L2 `sase-l2-cp-policy-compiler.md` 的 **LP4 的 posture 部分** 的定义方,同源于 `api/proto`。注:LP4 三合一(**risk 取值域 / 姿态字段 / geo 来源**)——**本文收口 posture**、**risk 由信任/风险引擎子 L2 收口**、**geo 来源仍悬留**(编译器 LP4 / 遥测子 L2)。
>
> **衔接:** 身份子 L2(enroll=令牌交换、持短 TTL 凭证、静默刷新)、PoP 单机编排 L2(隧道在 PoP 终结、PEP 求值、connector 数据通道)、策略编译器子 L2(posture 作 subject 选择器输入)、计费子 L2(会话=enroll/refresh 信号=活跃席位)、国密选型(加密栈待 PoC-G、TLCP-over-QUIC=M-G4)、前端控制台 L2(连接器/激活码管理)。
>
> **加密栈待 PoC-G:** Agent 隧道、Connector 数据通道(QUIC)加密随国密选型,**算法敏捷、待 PoC-G**(仅加密这块,不阻塞其余设计)。
>
> **范围:** 三类形态与边界、Agent 内部(跨平台共享核心)、姿态采集与 schema、Connector 内部(出站反向/零入站/HA)、Agentless 边界、入网与选路、加密栈、持续验证、契约。
>
> **不含(明确边界):** 加密算法选定(PoC-G);PEP 求值(PoP L2);凭证签发(控制面 `identity`);各平台壳的具体实现(实施期);Agentless 的 PoP 侧 Envoy 反代实现(PoP L2 / SWG);字节级 schema(api/proto);写代码/搭骨架(须另行授权)。
>
> **设计先行:** 含架构与机制说明,**不写代码**。每个决策配依据 / 备选及落选 / 可行方案;未定项标「待确认 / 待国密」。

---

## 目录

- 一、背景
- 二、目标
- 三、设计
  - 3.1 三类客户端形态与边界
  - 3.2 端点 Agent 内部架构(跨平台共享核心 + 薄壳)
  - 3.3 设备姿态采集与 schema(收口 LI5/LP4)★
  - 3.4 App Connector 内部架构(出站反向 / 零入站 / HA)
  - 3.5 Agentless 边界
  - 3.6 入网、RTT 选路与不硬编码 IP
  - 3.7 加密栈与数据通道(待国密 PoC-G)
  - 3.8 持续验证与凭证持有
  - 3.9 契约与衔接
- 四、风险
- 五、结论与衔接
- 附录:待确认 / 待国密

---

## 一、背景

L1 3.8 定 ZTNA 端侧三形态:端点 Agent(RTT 选 PoP、建隧道、报姿态、split-tunnel/DNS)、App Connector(仅出站连 PoP、发布内网应用、应用零入站暴露)、Agentless(浏览器 + 身份感知反代,BYOD/外包);访问按应用授权 + 持续验证;反向连接器协议(mTLS 控制 + QUIC 数据)使应用对公网零入站暴露。

但客户端内部如何组织(Agent 怎么跨平台、姿态采什么、Connector 反向连接怎么建与 HA、加密栈怎么处理国密、与控制面/PoP 的契约)此前未定义,且**身份/策略子 L2 留了 posture schema 的悬留契约(LI5/LP4)**待客户端定。本文给客户端 L2,收口这些。加密算法待 PoC-G(算法敏捷,不阻塞)。

---

## 二、目标(可衡量)

1. **三形态边界**:Agent / Connector / Agentless 各自职责与适用,清晰不重叠。
2. **Agent 跨平台**:共享 Go 核心 + 薄平台壳(L1 3.8 缓解多平台维护)。
3. **姿态 schema(收口 LI5/LP4)**:定采集字段与取值域,与身份凭证 posture claim、策略 subject 选择器**同源**。
4. **Connector 出站反向**:仅出站拨号、mTLS 控制 + QUIC 数据(回退 TCP)、**应用零入站暴露**、屏蔽内网拓扑、HA(每应用多连接器)。
5. **入网/选路**:enroll(=令牌交换,身份子 L2)、RTT 选最近 PoP、**不硬编码 IP**(经域名/控制面取节点,L1 3.13)。
6. **加密栈**:算法敏捷、**待 PoC-G**;私钥本地生成永不离开(L1 3.5)。
7. **持续验证**:持短 TTL 凭证、静默刷新、姿态/风险上报触发重评(撤销在控制面/PoP)。

**非目标:** 加密算法选定(PoC-G);PEP 求值(PoP);凭证签发(控制面);平台壳实现;Agentless 的 PoP 侧 Envoy 实现;字节 schema;写代码。

---

## 三、设计

### 3.1 三类客户端形态与边界

**背景** L1 3.8 三形态职责不同、适用不同,需先厘清边界。

**目标** 定三形态边界与适用,避免混用。

**设计**

| 形态 | 我方交付物 | 适用 | 姿态校验 |
|------|-----------|------|---------|
| **端点 Agent** | 我方跨平台 Go Agent(装用户设备) | 受管设备、需强姿态/split-tunnel/全应用 | 强(采集 3.3) |
| **App Connector** | 我方 Go Connector(装客户网络内) | 发布内网应用、出站反向、应用零入站 | N/A(它是应用侧出口) |
| **Agentless** | 无端侧代码;浏览器 + **PoP 侧身份感知反代**(Envoy) | BYOD/外包、仅 Web 应用、装不了 Agent | **弱**(无端代理,不能强校验姿态) |

依据:Agent 管"人→应用"全形态且能采姿态;Connector 管"应用零入站发布";Agentless 是装不了 Agent 时的浏览器兜底,因姿态弱**仅限低敏 Web 应用**(L1 3.8)。
- 备选:只做 Agentless(全浏览器)。落选:无法强校验姿态、无 split-tunnel、非 Web 应用不支持(L1 3.8)。

**风险** Agentless 姿态弱被误用于高敏应用 → 策略限定 Agentless 仅低敏应用(对接策略 subject 区分访问方式,待确认 LA4);三形态身份口径不一 → 都经统一凭证(身份子 L2,3.8)。

**结论** Agent(强姿态全形态)/ Connector(应用零入站发布)/ Agentless(浏览器低敏兜底,PoP 侧反代);边界与适用清晰,Agentless 限低敏。

---

### 3.2 端点 Agent 内部架构(跨平台共享核心 + 薄壳)

**背景** L1 3.8 缓解"多平台 Agent 维护"→共享 Go 核心 + 薄壳。需给内部模块。

**目标** 定 Agent 内部模块与跨平台结构。

**设计 —— 共享 Go 核心 + 薄平台壳**
- **共享核心(Go,跨平台):** enroll、PoP 选路(RTT)、隧道客户端(加密待国密,3.7)、split-DNS(3.6)、split-tunnel、姿态采集(3.3)、凭证持有与静默刷新(3.8)、上报(RTT/姿态/遥测)。
- **薄平台壳(各 OS):** 仅放平台相关的小块——网络栈接管(TUN/虚拟网卡)、姿态采集的系统 API 调用、安装/自启/权限、UI/托盘。Windows/macOS/Linux(+后续 移动端)各一薄壳,调同一核心。
- **依据:** 核心逻辑(选路/隧道/策略相关/凭证)跨平台一致,只有"碰系统的部分"按平台薄封装——把多平台维护成本压到薄壳(L1 3.8)。
  - 备选:每平台独立实现。落选:逻辑重复、行为漂移、维护爆炸(L1 3.8 已否)。

**风险** 平台壳碰系统差异大(尤其 TUN/姿态 API)→ 壳接口最小化 + 平台兼容矩阵(实施期);移动端限制(后台/VPN API)→ 移动端单列(待确认,本期桌面优先)。

**结论** Agent = 共享 Go 核心(选路/隧道/split-DNS/split-tunnel/姿态/凭证/上报)+ 各 OS 薄壳(网络接管/姿态 API/安装/UI);维护成本压在薄壳。

---

### 3.3 设备姿态采集与 schema(收口 LI5/LP4)★

**背景** L1 3.8 列了姿态项(OS/补丁、磁盘加密、杀软、越狱 root、证书);身份子 L2(LI5)与策略编译器(LP4)都留了"posture 取值域 schema 待客户端定"。本节定义之,三者同源。

**目标** 定姿态采集字段与取值域,作为身份凭证 posture claim、策略 subject device-posture 选择器的**单一来源**。

**设计 —— 姿态 schema(逻辑字段,字节编码待 api/proto)**

| 字段 | 取值 | 说明 |
|------|------|------|
| `os` / `os_version` | 枚举 + 版本号 | 操作系统与版本 |
| `patch_level` | 日期/级别 | 补丁更新程度 |
| `disk_encryption` | bool | 磁盘加密开启 |
| `av_edr` | enum(none/present/healthy) | 杀软/EDR 存在与健康 |
| `firewall` | bool | 主机防火墙开启 |
| `screen_lock` | bool | 屏幕锁/自动锁 |
| `jailbroken_rooted` | bool | 越狱/root(高风险) |
| `device_cert_valid` | bool | 设备证书有效(对接 L1 3.5) |
| `agent_version` | 版本号 | Agent 自身版本(可作合规条件) |

- **同源(收口 LI5/LP4):** 本 schema 定义在 `api/proto`(单一来源);**身份子 L2** 在签发凭证时取**姿态摘要**填入 posture claim(身份 3.3);**策略编译器** 的 subject device-posture 选择器**引用同一字段**(编译器 3.1/3.6);契约测试覆盖三者一致(对接编译器 RP7、身份 3.3)。
- **采集位置:** Agent 共享核心定义字段,平台壳调系统 API 取值(3.2);**Agent 只上报姿态事实,不做策略判定**(判定在 PEP,PoP L2)。
> 字段来源:`os`/`patch_level`/`disk_encryption`/`av_edr`/`jailbroken_rooted`/`device_cert_valid` 对应 L1 3.8 列的 5 类姿态项;`firewall`/`screen_lock`/`agent_version` 为本文**扩展**(合理增项,已于 L1 v0.5 同步姿态项清单,L1 3.8 现 8 项,W7)。

- **posture vs risk:** 本 schema 是**原始姿态事实**;`risk`(风险分)是**遥测/姿态派生**的二级量(L1 3.8/3.14),**其取值域不在本文定义**(属 LA5 / 身份子 L2 LI6 / 遥测管道),Agent 只报原始姿态事实、risk 由平台侧派生。
- **时效:** 姿态随设备变;Agent 周期/事件上报;凭证携签发时点摘要,TTL 内变化经刷新更新或触发撤销(身份 3.6,3.8)。

依据:posture 是 ZTNA"按身份+姿态授权"的核心输入(L1 3.8),三处(采集/凭证/策略)必须同源,否则"凭证报的"与"策略要的"对不齐(身份 RP7 根因);本节作为定义方收口。

**风险** 姿态字段平台差异(某些项某 OS 无)→ 字段可空 + 策略按"未知=不满足"(fail-closed);姿态可被篡改(端被控)→ 姿态非唯一门禁,配合设备证书 + 短 TTL + 行为/风险(L1 3.8),且越狱 root 项本身拦高风险设备。

**结论** 定义姿态 schema(9 字段)作为采集/凭证/策略**单一来源**(收口 LI5/LP4);Agent 只报事实不判定;risk 为派生量单列;字段可空按 fail-closed。

---

### 3.4 App Connector 内部架构(出站反向 / 零入站 / HA)

**背景** L1 3.8 反向连接器是 ZTNA"应用零入站暴露"的关键:连接器向外拨号 PoP,应用只见来自连接器的连接。

**目标** 定 Connector 内部:出站反向连接、控制/数据通道、内网解析、HA。

**设计**
- **出站反向连接(零入站):** Connector 装客户网络内,**仅出站**拨号到 PoP——建持久**控制通道(mTLS)** + **数据隧道(QUIC,回退 TCP/443)**(L1 3.8/3.11)。客户防火墙**无需入站规则**,应用**无需公网 IP**;应用只见来自连接器(内网)的连接。
- **控制通道(mTLS):** 心跳、`PublishApp{app_id, internal_addr}` / `WithdrawApp`(L1 3.11);tenant-bound 证书(L1 3.5,Register 入网,3.6)。
- **数据通道(QUIC):** PoP↔Connector,每用户会话一组多路复用流(L1 3.11);加密待国密(3.7,TLCP-over-QUIC=M-G4)。
- **内网解析(屏蔽拓扑):** Connector 在客户网络内解析应用真实地址(内网 DNS/IP),**对 PoP 屏蔽内网拓扑**(L1 3.6);PoP 只把授权用户流量导入连接器→应用。
- **HA(连接器单点缓解,L1 3.8):** **每应用多连接器** + PoP 侧负载均衡;一个连接器挂,其余继续;连接器无状态(配置由控制面/Register 拉)。

依据:出站反向 = 零入站暴露(同 ZTNA 核心价值);mTLS 控制 + QUIC 数据(弱网友好多路复用,被拦回退 TCP);多连接器解单点(L1 3.8)。
- 备选:应用直接暴露 + PoP 反代。落选:需公网入站/IP,违背"应用零入站暴露"(L1 3.8)。

**风险** 连接器单点 → 每应用多连接器 + LB(本节);QUIC 被运营商/防火墙拦 → 回退 TCP/443(L1 3.8);连接器被攻陷 → 仅该租户应用、tenant-bound 证书可吊销(L1 3.12)。

**结论** Connector 仅出站拨号(零入站)、mTLS 控制 + QUIC 数据(回退 TCP)、内网解析屏蔽拓扑、每应用多连接器 HA;tenant-bound 证书、加密待国密。

---

### 3.5 Agentless 边界

**背景** Agentless 给装不了 Agent 的浏览器场景;客户端是浏览器(无我方代码)。

**目标** 界定 Agentless 的客户端边界与限制。

**设计**
- **客户端 = 浏览器**(无我方端侧代码);我方部分是 **PoP 侧身份感知反代(Envoy)**——用户经浏览器登录(IdP)后,反代按身份授权访问 Web 应用。
- **本文边界:** Agentless 的**反代实现属 PoP L2 / SWG**(身份感知 Envoy 配置),**不在本客户端文档展开**;本文只确立"Agentless 无端侧代码、姿态弱、限低敏 Web 应用"(3.1)。
- **限制:** 无法强校验姿态(无端代理)、无 split-tunnel、仅 Web(HTTP/HTTPS)应用 → **仅低敏应用**(L1 3.8)。

依据:浏览器场景无端侧软件,姿态/网络层能力受限,只能做身份层 + Web 反代,故限低敏(L1 3.8)。

**风险** Agentless 被用于高敏 → 策略限定访问方式(3.1 风险);浏览器兼容 → 标准 OIDC/SAML Web 登录。

**结论** Agentless = 浏览器 + PoP 侧身份感知反代(实现属 PoP L2/SWG);无端代码、姿态弱、仅低敏 Web;本文只定边界。

---

### 3.6 入网、RTT 选路与不硬编码 IP

**背景** L1 3.11 enroll/Register、3.13 RTT 选路/不硬编码 IP、3.6 拉配置。

**目标** 定 Agent/Connector 入网、选路与节点获取。

**设计**
- **Agent 入网(`Enroll`,L1 3.11):** IdP 认证 → 设备生成密钥对 + CSR(私钥不离设备,L1 3.5)→ `Enroll{idp_token, device_info, csr}` → 控制面(令牌交换,身份子 L2)签发**短期设备证书 + 短 TTL 会话凭证** + 返回 `{pop_list, tenant_domains, split_tunnel_rules, policy_version}`。
- **Connector 入网(`Register`,L1 3.11):** 一次性激活码 + CSR → tenant-bound 证书 + `pop_endpoints`(同 CPE 的 Register 模式)。
- **RTT 选路:** Agent/Connector 实测对候选 PoP 的 RTT,选最近(L1 3.13);并上报 RTT 供选址数据(L1 3.14)。
- **不硬编码 IP(L1 3.13):** 客户端**经域名/控制面动态获取 PoP 节点列表**,不硬编码 IP——使云 BGP IP 迁自建时客户端无需改。
- **split-DNS / split-tunnel(L1 3.6):** Agent 入网拉取租户内部域名列表 + 应用→连接器映射 + split-tunnel 规则;接管内部域名解析→overlay IP→隧道→PoP→连接器→应用;公网域名正常解析或经 SWG。

依据:沿用 L1 3.11/3.13/3.6;私钥本地生成(L1 3.5);不硬编码 IP 解云→自建迁移(L1 3.13)。

**风险** 首次入网 IdP 流在不同平台差异 → 共享核心 + 平台壳处理(3.2);RTT 选路抖动 → 滞后/加权(实测);split-DNS 与公网域名冲突 → 按租户配置精确匹配内部域名(L1 3.6)。

**结论** Agent `Enroll`(IdP+CSR→证书+凭证+配置)、Connector `Register`(激活码+CSR);RTT 选最近 PoP;经域名/控制面动态取节点不硬编码 IP;split-DNS/split-tunnel 入网拉取。

---

### 3.7 加密栈与数据通道(待国密 PoC-G)

**背景** Agent 隧道与 Connector 数据通道(QUIC)受国密影响(R7);算法随国密选型,待 PoC-G。

**目标** 定加密栈形态,算法敏捷待 PoC-G,不阻塞其余设计。

**设计**
- **Agent 隧道:** 国密档租户 TLCP(铜锁)、非国密 WireGuard——与 CPE/数据面 **同一套加密栈 + crypto provider 抽象**(国密选型 3.2/3.7);**算法待 PoC-G**。
- **Connector 数据通道(QUIC):** 多路复用 QUIC(L1 3.8/3.11);国密下 **TLCP-over-QUIC 可行性 = 国密选型 M-G4**(不成熟则退 TLCP-over-TCP);算法待 PoC-G。被拦回退 TCP/443(L1 3.8)。
- **私钥本地生成:** Agent/Connector 隧道与证书私钥**本地生成、永不离开设备**(L1 3.5),只注册公钥(enroll/Register)。
- **控制通道:** Connector↔PoP 控制通道 mTLS,国密档走国密 mTLS(国密选型 3.8 内部面)。

依据:客户端加密栈与数据面/CPE 同源(不自成一套),算法敏捷使 PoC-G 一处切换;私钥本地生成守 L1 3.5。

**风险** TLCP-over-QUIC 不成熟 → 退 TCP(M-G4 验);客户端国密性能(移动/低端设备 SM4)→ 待实测(端侧设备多样,趋势参考);QUIC 被拦 → 回退 TCP/443。

**SPA 敲门客户端(横切,见 `sase-l2-ztna-access-hardening.md`)** Agent/CPE **建隧道前先发 SPA 单包敲门**(设备身份+租户+时间戳+nonce,加密签名)到 PoP——PoP 默认丢包、验签通过才开放接入端口;敲门加密算法同端侧栈(待 PoC-G)。详见该横切 L2。

**结论** Agent 隧道与 Connector QUIC 数据通道加密与数据面/CPE 同源、算法敏捷待 PoC-G;TLCP-over-QUIC 待 M-G4(退 TCP 兜底);私钥本地生成;控制通道国密 mTLS;**建隧道前先 SPA 敲门**(横切 L2)。

---

### 3.8 持续验证与凭证持有

**背景** L1 3.8 持续验证:短 TTL 凭证、姿态/风险变化即快速撤销、会话静默刷新。客户端是凭证持有方与姿态上报方。

**目标** 定客户端侧的凭证持有、刷新、姿态上报触发。

**设计**
- **持凭证:** Agent 持控制面签发的**短 TTL 会话凭证**(身份子 L2);凭证用于 PoP 侧 PEP 求值(PoP L2);**Agent 不持签发私钥**(签发在控制面)。
- **静默刷新:** 凭证近过期,Agent 走轻量刷新(重令牌交换,带更新的姿态/risk)——不打断会话(L1 3.8、身份 3.6)。
- **姿态/风险上报触发重评:** Agent 周期 + 事件上报姿态(3.3);姿态恶化/风险升高 → 控制面/PoP 触发**快速撤销**(撤销在控制面产 RevocationTable → PoP PEP 即时拒,身份 3.6 / PoP L2 3.6);Agent 侧表现为下次决策被拒/需重认证。
- **逐连接/可重评:** 访问按应用、可重评(L1 3.8);Agent 拦截→隧道到 PoP→PEP 决策。

依据:客户端是凭证持有 + 姿态上报方,判定与撤销在控制面/PoP(客户端不可信,不做安全决定);短 TTL + 刷新 + 上报触发实现 L1 3.8 持续验证。

**风险** 客户端被控伪造姿态 → 姿态非唯一门禁(3.3 风险)+ 设备证书 + 短 TTL;刷新风暴 → 刷新抖动(身份子 L2);离线设备 → 凭证 TTL 到期自然失效。

**终端实时控制通道(横切,见 `sase-l2-ztna-access-hardening.md` 3.3)** Agent 维持到**控制面**的持久 mTLS 通道,**收服务端推送**(撤销/强制重认证/按需重采姿态/配置/重选路)+ **事件驱动上报**姿态/风险信号——比等凭证过期快(秒级);**但权威仍在 PoP PEP、客户端不可信**,通道仅提速非安全边界。详见该横切 L2。

**结论** Agent 持短 TTL 凭证、静默刷新、周期/事件上报姿态;判定与撤销在控制面/PoP,客户端不做安全决定;按应用可重评;**终端实时通道**收推送提速持续验证(横切 L2,权威仍在 PoP)。

---

### 3.9 契约与衔接

**背景** 客户端与控制面/PoP/各子 L2 的契约需汇总。

**目标** 明确契约面与衔接。

**设计**
- **与控制面 `identity`:** `Enroll`/`Register`(令牌交换)、静默刷新;凭证 posture claim 取本文 3.3 schema。
- **与 PoP 单机编排 L2:** Agent 建隧道到 PoP(加密待国密);Connector 数据通道 QUIC PoP↔Connector;PEP 在 PoP 侧求值(客户端只持凭证、报姿态)。
- **与策略编译器子 L2:** posture(3.3)作 subject device-posture 选择器输入(同源)。
- **与计费子 L2:** Agent **enroll = 会话起点 = 活跃席位计数信号**;**refresh 不新增席位**(按 user_id+月去重、刷新只作核对,计费 3.2)。
- **与国密选型:** 加密栈算法、TLCP-over-QUIC(M-G4)待 PoC-G。
- **与前端控制台 L2:** 连接器激活码生成、Agent 分发/状态、应用→连接器映射在控制台维护。

**风险** 契约 schema 漂移(尤其 posture)→ `api/proto` 单一来源 + 契约测试(3.3);多端版本兼容 → 版本字段 + 向后兼容(L1 3.11)。

**结论** 客户端契约面:identity(enroll/凭证)、PoP(隧道/数据通道)、编译器(posture)、计费(会话)、国密(加密)、前端(管理);posture 同源、协议版本化。

---

## 四、风险

### RA1:多平台 Agent 维护成本
缓解:共享 Go 核心 + 薄平台壳(3.2),维护压在薄壳;平台兼容矩阵。

### RA2:posture schema 与凭证/策略漂移(LI5/LP4 根因)
缓解:本文 3.3 定义为单一来源(api/proto)+ 契约测试(对接身份 3.3 / 编译器 RP7)。

### RA3:客户端被控伪造姿态
缓解:姿态非唯一门禁(3.3)+ 设备证书 + 短 TTL + 风险;越狱/root 项拦高风险设备;判定在 PoP 不在客户端(3.8)。

### RA4:连接器单点
缓解:每应用多连接器 + PoP LB(3.4);连接器无状态可快速重建。

### RA5:加密/QUIC 待国密阻塞客户端加密实现
缓解:仅加密栈待 PoC-G(3.7,算法敏捷、与数据面/CPE 同源);其余(选路/split-DNS/姿态/enroll/Connector 反向/HA)不阻塞、可先设计。

### RA6:QUIC 被拦 / TLCP-over-QUIC 不成熟
缓解:回退 TCP/443(L1 3.8);TLCP-over-QUIC 待 M-G4,不行退 TLCP-over-TCP(国密选型 3.2)。

### RA7:Agentless 姿态弱被误用高敏
缓解:策略限定 Agentless 仅低敏 Web 应用(3.1/3.5)。

---

## 五、结论与衔接

**结论:** ZTNA 端侧三形态——**端点 Agent(共享 Go 核心 + 薄平台壳**:选路/隧道/split-DNS/split-tunnel/姿态/凭证/上报)、**App Connector(仅出站反向拨号、mTLS 控制 + QUIC 数据、应用零入站暴露、屏蔽内网拓扑、每应用多连接器 HA)、Agentless(浏览器 + PoP 侧身份感知反代,限低敏 Web,实现属 PoP L2)**;**设备姿态 schema(9 字段)作为采集/凭证/策略单一来源,收口身份 LI5 与编译器 LP4**;入网经 Enroll/Register(IdP/激活码 + CSR、私钥本地生成),RTT 选最近 PoP、**不硬编码 IP**;**加密栈与数据面/CPE 同源、算法敏捷待 PoC-G**(TLCP-over-QUIC=M-G4,退 TCP 兜底);持短 TTL 凭证 + 静默刷新 + 姿态上报触发重评,**判定与撤销在控制面/PoP,客户端不做安全决定**。

**衔接:**
- **身份子 L2:** enroll=令牌交换、持凭证、静默刷新;**posture schema 收口 LI5**。
- **策略编译器子 L2:** posture 作 subject 选择器输入(同源,**收口 LP4 的 posture 部分**;risk 部分由信任/风险引擎子 L2 收口、geo 仍悬留)。
- **PoP 单机编排 L2:** 隧道/数据通道在 PoP 终结、PEP 求值。
- **计费子 L2:** enroll=活跃席位计数信号;refresh 不新增席位(去重 user_id+月)。
- **国密选型(待 PoC-G):** 加密栈、TLCP-over-QUIC(M-G4)。
- **前端控制台 L2:** 连接器/激活码/应用映射管理。

搭脚手架 / 写代码须**另行授权**(设计先行)。

---

## 附录:待确认 / 待国密

| # | 项 | 性质 | 去向 |
|---|----|------|------|
| LA1 | Agent 隧道 / Connector QUIC 加密算法(TLCP/WireGuard、TLCP-over-QUIC) | 待国密 | PoC-G(M-G1/M-G4) |
| LA2 | 移动端 Agent(后台/VPN API 限制)是否本期纳入 | 范围 | 待确认(桌面优先) |
| LA3 | 姿态 schema 字节编码与各平台采集 API 映射 | 契约/实现 | api/proto + 平台壳实施期 |
| LA4 | Agentless 仅低敏的"访问方式"如何进策略(subject 区分 Agent/Agentless) | 契约 | 与策略编译器子 L2 协调 |
| LA5 | risk 分派生算法与取值域(遥测/姿态派生) | 契约 | 与遥测子 L2 / 身份 risk claim 对齐 |
| LA6 | 客户端国密性能(移动/低端设备 SM4) | 待国密/实测 | PoC-G 趋势 + 端侧实测 |
| LA7 | 连接器与 PoP 的负载均衡/会话亲和细节 | 机制 | 与 PoP L2 一并定 |
| LA8 | Agent 远程升级:灰度/分批放量/回滚 + 版本兼容(薄壳承载,类 CPE LS8) | 机制 | 发布编排见运维/部署 L2 3.3,机制待实施期 |

> 说明:本 L2 收口 posture schema(身份 LI5 / 编译器 LP4);加密算法待 PoC-G(算法敏捷,不阻塞其余:选路/split-DNS/姿态/enroll/Connector 反向/HA 均已设计)。判定与撤销在控制面/PoP,客户端不做安全决定。
