# SD-WAN 数据面隧道握手 L2(密钥协商 + 身份绑定)

> **状态:** L2 组件设计 / 形态 A 已认可(花刚 2026-05-26)/ **非国密档已编码(Slice30)** / **国密档(TLCP)+ 完整协议仍待第三方密码学审查**
> **版本:** v0.2
> **日期:** 2026-05-27
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **v0.2(2026-05-27,Slice30 as-built):** 非国密档(TLS1.3 + RFC5705 exporter)已编码并端到端跑通(`internal/tunhandshake` + 接进 `cmd/pop-agent`/`cmd/cpe`,FWaaS L4 真数据面生效)。实现现状与本刀**有意保留的简化**见 §9;**国密档(TLCP/铜锁 + SM3-KDF 导出,§7.3)、tx/rx 双密钥、receiver-index(NAT)、rekey/epoch 编排仍待第三方密码学审查后编码。**
>
> **层级与上承:** 落地数据面隧道 L2 `sase-l2-data-plane-tunnel.md` §4.2/§7.1 留的「握手(Noise/ZTP)= 待确认、需密码学审查」;上承 L1(现 v0.6)R7 国密、`sase-gm-crypto-selection.md`(现 v0.4,隧道形态已收敛为自研 UDP 数据报、握手 TLCP/TLS1.3 导出密钥)、不自研加密协议 L1 2.3、ZTP 设备入网(`internal/enroll`,记忆 `tunnel-form-decision`)。
>
> **衔接:** `internal/dptunnel`(数据面会话,接受本握手协商出的密钥)、`internal/enroll`(ZTP 设备证书/撤销)、PoP `Router`(身份绑定收口入向解复用)、xDS `SiteConfig`(下发隧道 alg/参数)。
>
> **范围:** SD-WAN 隧道的**握手**——如何在 CPE 与 PoP 间互认证、协商出 `dptunnel.Session` 所需会话密钥、把密钥绑定到 ZTP 身份(tenant/site)。**数据面封装/FEC/重放见隧道 L2,不在此。** ⚠️ **本设计含密码学协议选择,定稿前须经第三方密码学审查;文中"待审查"项尤甚。**
>
> **对隧道 L2 §4.2/§7.1 既有握手方向的修正(已回写隧道 L2 v0.2):** 隧道 L2 §7.1 与记忆 `tunnel-form-decision` 原拟握手"借 **Noise 模式(IK)** 做有限自研"。本文经再评估**改为形态 A:互认证 TLS1.3/TLCP 导出密钥**——理由(§3):Noise 框架无国密原语,国密档走 Noise 必自研"国密 Noise"(正是 L1 2.3 否决 WG 国密化的同因),而 TLCP 是现成国密件;TLS/TLCP 路径把握手的**密钥协商+认证**做成零自研。**已回写隧道 L2 v0.2(§3/§4.2/§7.1/§8/§9)+ 记忆 `tunnel-form-decision`(2026-05-26 花刚认可形态 A 后)。** 自研边界也随之收窄(见 §7.2,与隧道 L2 §7.1 口径对齐)。

---

## 1. 背景

数据面隧道 `dptunnel`(Slice18/19)已实现密文数据报 + FEC + 路由,但 **`Session` 当前接受外部"注入"的会话密钥**——缺一个**互认证 + 密钥协商**的握手。没有握手,隧道无法在 `cmd` 层跑通真密钥,且 PoP `Router` 当前靠 UDP 源地址解复用(隧道 L2 §4.3 已注明 srcAddr 仅解复用、权威应是每会话 AEAD 密钥;§8 留"NAT 下入向解复用须 receiver-index——握手协商")。

**核心张力(决定形态):**
- **不自研加密协议(L1 2.3)**:`gm-crypto` v0.3 正是据此否决「WG 国密化(改 Noise 套件)」。握手是最不该自研的部分——自研密钥协商/认证协议风险最高。
- **国密要求(R7)**:国密租户的密钥协商须用 SM2/SM3(非 Curve25519/SHA)。而 **Noise 协议框架不含国密原语**——"国密 Noise" = 非标自研(正是要避免的)。

本设计目标:用**成熟、可审计**的机制完成握手,把自研收敛到已被认可的数据面 AEAD 封装(隧道 L2,花刚 2026-05-26 认可②)。

---

## 2. 目标 / 非目标

### 2.1 目标
1. **互认证**:CPE 与 PoP 用 **ZTP 设备证书**(SM2/Ed25519,tenant 在 Organization、site 在 CN)互验身份。
2. **密钥协商**:协商出 `dptunnel.Session` 所需会话密钥(每方向独立 tx/rx 密钥),前向安全。
3. **身份绑定**:PoP 从**已认证的对端证书**得 (tenant, site),据此登记 `Router`——**隔离权威从 srcAddr 收到密钥+证书身份**(收口隧道 L2 §4.3 注明的"srcAddr 仅解复用、权威是密钥")。
4. **crypto-agility**:非国密档与国密档同结构,算法由**租户策略**(控制面下发)定、非客户端协商(防降级)。
5. **复用 ZTP**:证书签发/续期/撤销沿用 `internal/enroll`;撤销 → 握手失败 → 隧道在证书有效期内断(有界撤销)。
6. **最小自研**:密钥协商+认证用 off-the-shelf,不自研握手协议。

### 2.2 非目标
- 不设计数据面封装/FEC/重放(隧道 L2)。
- 不实现(本文是设计;编码待评审+密码学审查通过)。
- 不改 ZTNA(L7,保持)。

---

## 3. 形态决策与备选

| 备选 | 机制 | 依据 | 落选 / 顾虑 |
|------|------|------|------------|
| **A 握手=互认证 TLS1.3(非国密)/ TLCP-铜锁(国密),导出隧道密钥(选定)** | 用 ZTP 证书做 mutual TLS/TLCP 握手(短控制连接)→ 经密钥导出(RFC5705 式)派生数据面密钥;数据面仍 UDP 数据报(dptunnel) | **零自研密钥协商/认证**——TLS1.3 有形式化分析、TLCP/铜锁是国密标准实现;国密档天然有 TLCP(无需自研国密 Noise);复用 ZTP 证书 + 既有控制面 mTLS;身份经证书认证 → 收口 Router srcAddr 信任 | 需控制连接(TCP/TLS)与 UDP 数据面并存;依赖 TLCP 导出密钥的可用性(待确认,见 7.3) |
| B Noise IK over UDP(WireGuard 式) | 1-RTT 数据报原生握手 | 数据报原生、无需 TCP;非国密档成熟(WG 同源) | **国密档无标准 Noise → 自研国密 Noise**(违 L1 2.3,正是否决 WG 国密化的同因);双档机制不一(国密自研 vs 非国密 Noise) |
| C 全自研国密 Noise 式 | 自研 SM2/SM3/SM4 的 Noise 式握手 | 数据报原生、国密 | **自研握手协议,密码学风险最高**;与 L1 2.3 直接冲突 |

**结论:选 A。** 关键:A 把**最高危的"握手密钥协商+认证"自研彻底移除**(用 TLS1.3/TLCP);**残留自研收窄为**:① 国密档密钥导出(TLCP 若无标准 exporter → SM3-KDF 派生,§7.3 待审查)② rekey/epoch 编排(§4.6/§7.5 待审查)③ 数据面 AEAD 封装(隧道 L2,已认可)。与隧道 L2 §7.1"有限自研经审查"口径一致——A 只是把自研面从"整个 Noise 握手"缩到上述三项。国密档复用 TLCP、无需自研国密 Noise,是相对 B/C 的决定性优势。

> 代价:A 需一个控制连接做握手。但 CPE 本就有 ZTP/续期等 mTLS 控制连接(`internal/enroll`),握手作为其上一次密钥协商操作,复用既有连接,不新增信任面。

---

## 4. 协议设计(形态 A)

### 4.1 总体流程
```
① CPE 用 ZTP 证书向 PoP 发起 mutual TLS1.3 / TLCP 握手(控制连接,CPE 出站)
② 双方互验证书:PoP 验 CPE 证书(取 tenant=Organization、site=CN);CPE 验 PoP 证书(本 CA 签)
③ 握手完成 → 共享主密钥;双方经密钥导出(见 4.3)派生数据面 tx/rx 密钥 + receiver-index
④ PoP 据已认证的 (tenant, site) + 派生密钥 + CPE 数据面 UDP 端点 注册 Router(身份权威来自证书,非 srcAddr)
⑤ 数据面:CPE/PoP 用派生密钥起 dptunnel.Session,UDP 数据报收发(隧道 L2);数据帧加 receiver-index 外层(见 4.4)
⑥ rekey:周期重握手(回 ①)→ 新密钥 + epoch++;旧 epoch 排空后退休
```

### 4.2 算法档(crypto-agility,租户策略定、非协商)
- **非国密档**:TLS 1.3(ECDHE-P256/X25519 + AEAD)+ 数据面 ChaCha20-Poly1305。
- **国密档**:TLCP(SM2 密钥交换/SM2 证书/SM3/SM4)+ 数据面 SM4-GCM。
- 档由**控制面据租户合规策略经 xDS `SiteConfig` 下发**(`tunnel_alg`),CPE/PoP 按下发档握手——**不在握手里协商算法**(防降级:攻击者无法把国密租户降到非国密)。

### 4.3 密钥导出 → 数据面密钥
握手主密钥**不直接做数据面密钥**;经标准密钥导出派生,绑定用途/档/epoch:
- 优先 **RFC 5705 TLS Exporter**(`tls-exporter`),label 含 `"sase-sdwan-tunnel"` + epoch + alg;TLCP 若无标准 exporter → 据 TLCP 主密钥 + SM3-KDF 按同结构派生(**待审查,见 7.3**)。
- 派生 **两个方向独立密钥**(`k_cpe→pop`、`k_pop→cpe`)+ receiver-index。**本设计主张**把 `dptunnel.Session` 从当前骨架的"单密钥 + 方向字节 nonce"(`sendDir!=recvDir` 防同向 nonce 复用)演进为 **tx/rx 双密钥**——方向独立密钥更干净、免共享密钥的跨向 nonce 管理。这是本文驱动的接口调整,**待编码 + 与隧道 L2 协同**(`internal/dptunnel` 现状为单密钥,待核)。
- 前向安全:每次(re)握手新 ECDHE/SM2 临时密钥 → 新主密钥 → 新数据面密钥;旧密钥不可由长期私钥重算。

### 4.4 receiver-index(收口 NAT 解复用)
握手时 **PoP 给该会话分配一个 4 字节 receiver-index**,CPE 在每个数据面 UDP 数据报**外层**(dptunnel 帧前)带上它。PoP 据 index(非 srcAddr)解复用到会话——**解决 NAT 下源地址漂移**(收口隧道 L2 §8 留的"NAT 下入向解复用须 receiver-index——握手协商")。index 明文但仅作解复用;真伪仍由 AEAD 兜底。这是**握手驱动的 dptunnel 帧外层新增**(待隧道 L2 协同改)。

### 4.5 身份绑定(收口 Router 的 srcAddr 解复用)
PoP 在握手 ② 从**已认证**的 CPE 证书取 (tenant, site),据此 `Router.Register(tenant, site, sess, dataUDPAddr, cidrs)`——**租户/站点身份权威来自证书,不再依赖 srcAddr**。srcAddr/receiver-index 仅解复用。cidrs 仍由 xDS `SiteConfig` 下发(站点子网是配置,非证书内容)。

### 4.6 rekey / epoch
- 触发:时间(如每 N 分钟)或计数器近阈值(dptunnel `ErrRekeyRequired`,B1)。
- 机制:重走握手 ① 得新密钥;nonce 的 epoch 字段(dptunnel nonce `[1:4]` 预留)递增,使新旧密钥的 nonce 空间不交叠;旧 epoch 短暂并存(排空在途包)后退休。

---

## 5. 与底座复用

- **ZTP 证书**(`internal/enroll`,字段约定见隧道 L2 §6.1:租户在 Organization、site_key 在 CN):直接作握手的 mutual TLS/TLCP 证书。无需另造隧道身份。
- **撤销/续期**:撤销设备 → 续期被拒 → 证书过期 → 握手失败 → 隧道断(有界时间,复用 ZTP 撤销模型)。rekey 重握手即天然重验证书有效性。
- **xDS `SiteConfig`**:下发 `tunnel_alg`(档)、站点 cidrs、rekey 周期、FEC 参数。
- **既有控制连接**:握手复用 CPE 既有 ZTP/控制 mTLS 通道形态(出站),不新增暴露面。
- **dptunnel**:数据面会话消费本握手派生的密钥(需把 Session 接口从单密钥演进为 tx/rx 双密钥 + epoch)。

---

## 6. crypto-agility 落点
| 层 | 非国密档 | 国密档 |
|----|---------|--------|
| 握手认证+密钥协商 | TLS 1.3(X25519/P256,SM2 外) | TLCP/铜锁(SM2/SM3) |
| 证书 | Ed25519/ECDSA | SM2 |
| 密钥导出 | RFC5705 exporter | TLCP 主密钥 + SM3-KDF(待审查) |
| 数据面 AEAD | ChaCha20-Poly1305 | SM4-GCM |
档切换不改流程/帧结构,只换底层套件——与 `cred`/`dptunnel` 的 crypto-agility 一致。

---

## 7. 风险

### 7.1 控制连接与数据面耦合
握手在 TCP/TLS 控制连接、数据在 UDP——两条腿。缓解:控制连接复用既有出站 mTLS;握手低频(每会话 + rekey);数据面密钥一旦派生,数据收发不依赖控制连接在线。**残留**:控制连接被阻断则无法(re)握手 → 隧道在当前 epoch 到期后断;监控 + 重连兜底(待)。

### 7.2 残留自研面(直面 L1 2.3,与隧道 L2 §7.1 对齐)
- **零自研**:握手的**密钥协商 + 互认证**(TLS1.3/TLCP,成熟可审计)——这是 A 相对 B/C(国密档须自研 Noise)的核心优势。
- **残留有限自研(须审查)**:① **国密档密钥导出**——TLS1.3 用标准 RFC5705 exporter(零自研);TLCP 若无标准 exporter 则 SM3-KDF 派生(§7.3,新增组合);② **rekey/epoch 编排**(§4.6/§7.5);③ **数据面 AEAD 封装/帧/FEC**(隧道 L2,已认可)。
- 即 A 把自研面从"整个 Noise 握手 + 数据面"缩到"密钥导出绑定 + rekey 编排 + 数据面封装"——与隧道 L2 §7.1"有限自研、只组合标准原语、经审查"同口径,且把高危的握手核心移出自研面。**非"握手零自研"的绝对说法。**

### 7.3 TLCP 密钥导出可用性(待审查,关键未知)
TLS1.3 有 RFC5705 exporter;**TLCP 是否有等价标准 exporter 待确认**。若无,据 TLCP 主密钥用 SM3-KDF 按 exporter 同构派生——这一步是新增组合,**须密码学审查**(确保不削弱 TLCP 安全性、不复用主密钥于多用途)。铜锁库是否暴露主密钥/导出接口 = 待实测。

### 7.4 降级攻击
档由控制面租户策略定、握手不协商算法 → 攻击者无法把国密租户降级到非国密。前提:`SiteConfig` 下发链已是 mTLS(as-built),不可篡改。

### 7.5 rekey 竞态 / epoch 管理
新旧 epoch 并存窗口处理不当 → 丢包或 nonce 复用。缓解:epoch 入 nonce(空间隔离)、旧 epoch 仅收不发并限时排空、严格阈值前 rekey(dptunnel `ErrRekeyRequired` fail-closed)。细节待审查。

### 7.6 receiver-index 明文
index 明文可被观测/伪造,但仅解复用;伪造 index 命中他会话 → 该会话 AEAD 解不开伪造载荷 → 丢弃。不破隔离(权威是密钥)。

---

## 8. 待确认 / 待密码学审查

> **已打包送审(2026-05-27):** 下列待审查项已精确规格化为**密码学审查包** `docs/sase-tunnel-handshake-crypto-review.md`(统一密钥 schedule + 安全目标 + 威胁模型 + 按 P0/P1 排序的审查者问题清单;含关键发现:国密档须强制 **ECDHE-SM2** 套件保前向安全)。该包是面向外部密码学审查者的输入;**P0 四问(尤 TLCP 导出健全性、ECDHE-SM2 FS)获独立审查确认/修正后,方编码国密档 + tx/rx 双密钥 + receiver-index + rekey/epoch。**

**必须经第三方密码学审查后方可编码定稿:**
- TLCP 密钥导出机制(标准 exporter 还是 SM3-KDF 自定义派生)——7.3,**最关键未知**。
- 密钥派生的 label/上下文绑定(用途+档+epoch+身份)的具体构造。
- tx/rx 双密钥 + epoch 的 KDF schedule;前向安全证明边界。
- rekey/epoch 并存窗口的安全性(防 nonce 复用/重放跨 epoch)。
- receiver-index 长度/分配/回收。

**待实测 / 待定:**
- 铜锁库的 TLCP API 是否暴露主密钥/导出(待实测)。
- 握手时延(控制连接 RTT × 往返数;TLS1.3 1-RTT、TLCP 待测)。
- rekey 周期默认值(待权衡前向安全 vs 握手开销)。
- `dptunnel.Session` 从单密钥演进到 tx/rx 双密钥 + epoch 的接口改动(待编码;须核 `internal/dptunnel` 现状)。
- **字段宽度澄清**:receiver-index 长度(拟 4B,外层解复用)与 epoch 宽度(nonce `[1:4]` = 3B)是两个不同字段,勿混。

**文档回写(已完成,记录):**
- ✅ 已回写隧道 L2 `sase-l2-data-plane-tunnel.md` §4.2/§7.1/§8:"握手借 Noise IK" → "TLS1.3/TLCP 导出握手"(本文形态 A 修正,隧道 L2 v0.2)。
- ✅ 已回写记忆 `tunnel-form-decision`:握手机制 Noise → TLS/TLCP 导出。

**依赖项(审查时确认):**
- 降级防护(§7.4)依赖 xDS `SiteConfig` 下发链完整性(as-built mTLS),须确认覆盖 `tunnel_alg` 字段不可篡改。
- 控制连接被阻断的监控 + 重连兜底(§7.1)——待。

---

## 9. 实现现状(Slice30 as-built)

`internal/tunhandshake`(`Server` PoP 侧 / `Dial` CPE 侧 / `deriveKey` RFC5705 exporter),接进 `cmd/pop-agent`(gated `SDWAN_TUNNEL_ADDR`:FWStore+SubscribeFW → `dptunnel.Router`.SetFirewall → UDP 数据面 Serve → 握手 Server,onEstablished 校验证书租户==本 PoP 租户后 `Router.Register`)+ `cmd/cpe`(gated `SDWAN_TUNNEL=1`:握手 → `dptunnel.Session` → `OpenTUN` → `Endpoint`)。**FWaaS L3/L4 在真数据面裁决已生效**(收口 Slice20 留的「执行点接 pop-agent 待 dptunnel Router 进 cmd」)。

**已落地(对齐 §4):** ① 互认证 mutual TLS1.3(ZTP 证书,tenant=Organization/site=CN);② RFC5705 exporter 派生会话密钥(label+epoch+alg 绑入 context);③ 身份绑定——PoP 从已认证证书取 (tenant,site) 登记 Router,**隔离权威落在密钥+证书身份**(srcAddr 仅解复用);④ 防降级——alg 由控制面定、CPE 校验 serverHello.alg==期望(§7.4);⑤ 复用 ZTP 证书/撤销(撤销→证书过期→握手失败→隧道断,有界)。e2e(`-race` 净):真握手密钥端到端可达 + FWaaS deny + 跨租户隔离 + 防降级拒 + 非 ZTP 证书拒。

**本刀有意保留的简化(均 L2 标注的待审查/后续项,非缺陷):**
- **仅非国密档**(TLS1.3 + RFC5705)。**国密档(TLCP/铜锁 + SM3-KDF 导出,§7.3)待铜锁 exporter 实测 + 密码学审查。**
- **单共享密钥 + 方向字节**(复用现 `dptunnel.Session`,已 nonce-safe);**tx/rx 双密钥(§4.3)待审查**。
- **入向解复用沿用 srcAddr**(非 NAT/dev 可行);**NAT 下 receiver-index(§4.4)待审查**——`cmd` 注释已标 NAT 局限。
- **握手一次产长期会话密钥**;**周期 rekey / epoch 编排(§4.6)待审查**——`Server.epoch` 恒 0,派生与 serverHello 通告**同源**(防将来非零 epoch 两端不一致致静默丢包)。
- **alg 在 cmd 取 env 默认(dev)**;生产应取自控制面 xDS 下发的租户档(否则防降级只防到本地配置层)。

## 10. 结论

SD-WAN 隧道握手采用**形态 A:互认证 TLS1.3(非国密)/ TLCP-铜锁(国密),用 ZTP 设备证书,经密钥导出派生数据面 tx/rx 密钥 + receiver-index**。**关键价值:握手的密钥协商与互认证零自研**(复用 TLS1.3/TLCP 成熟件,国密档天然有 TLCP、不必自研国密 Noise);残留有限自研(国密档密钥导出/rekey 编排/数据面封装,§7.2)与隧道 L2 §7.1 同口径、经审查。身份经证书认证后由 PoP 据 (tenant,site) 登记 `Router`,**使隔离权威落在密钥+证书身份而非 UDP 源地址**(收口隧道 L2 §4.3/§8 留的 srcAddr-仅解复用 / NAT receiver-index 待办)。算法由租户策略经 xDS 下发(防降级),撤销/续期复用 ZTP。**⚠️ 含密码学协议组合(尤其 TLCP 密钥导出 7.3),编码定稿前须经第三方密码学审查。** 形态相对 Noise(B/C)的决定性优势:不为国密自研握手协议(守 L1 2.3)。
