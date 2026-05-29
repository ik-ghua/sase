# SD-WAN 隧道握手 · 密码学审查包

> **状态:** 待第三方密码学审查(审查输入材料)
> **版本:** v0.1
> **日期:** 2026-05-27
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **用途:** 本文是**面向外部密码学审查者的自洽规格 + 问题清单**,目的是解锁 SD-WAN 隧道握手(形态 A)中四项「待密码学审查后编码」的构造:**① 国密档 TLCP 密钥导出 ② tx/rx 双密钥 KDF schedule ③ NAT receiver-index ④ rekey/epoch 编排**。审查通过/给出修正后方可编码这四项。
>
> **上承:** 握手 L2 `sase-l2-tunnel-handshake.md`(形态 A,§7.3/§8 留的待审查项)、隧道 L2 `sase-l2-data-plane-tunnel.md`(数据面封装/帧/重放/FEC,**已编码 Slice18/19,不在本审查范围**)、gm-crypto 选型 `sase-gm-crypto-selection.md` v0.4(TLCP/铜锁、不自研密码学)、L1 v0.6 R7/3.7。
>
> **已编码不需审查的基线(Slice30,见 §四):** 非国密档 = 互认证 TLS1.3 + RFC5705 exporter,已端到端跑通。本文 §五的四项是其**国密化 + 生产化扩展**。
>
> **诚实声明:** 本文给出的构造均标注「**已确立**(标准/已形式化分析)」或「**拟用,待审查**(组合标准原语,未经审查不得断言其安全性)」。§五的拟用构造是供审查者评判/修正的**提案**,非已证明结论。

---

## 一、背景

形态 A(握手 L2)把握手的**密钥协商 + 互认证**收敛到成熟件(TLS1.3 / TLCP-铜锁),**零自研密钥协商**;残留自研收窄到三处「组合标准原语」:数据面 AEAD 封装(隧道 L2,已编码、已护栏、不在本审查)、**密钥导出绑定**、**rekey/epoch 编排**。Slice30 已落地**非国密档**(TLS1.3 + RFC5705 exporter)并跑通端到端 + FWaaS L4。本文要送审的是把它扩到**生产 + 国密**所需的四项构造——这些一旦定错,数据面密钥学根基返工巨大,故先送审、后编码(设计先行)。

**为什么必须外部审查(而非自评):** ① 国密档密钥导出(TLCP 是否有标准 exporter,无则 SM3-KDF 派生)是**新增组合**,涉及主密钥复用/密钥分离/前向安全,须密码学专业判断;② rekey/epoch 的 nonce 不复用、跨 epoch 重放、并存窗口安全性是经典易错点。设计方(我们)能给精确规格与提案,但**安全性结论应由独立密码学审查给出**。

---

## 二、安全目标 / 非目标

### 2.1 待审查验证的安全目标
1. **机密性 + 完整性**:数据面载荷经 AEAD(SM4-GCM / ChaCha20-Poly1305)保护;隧道密钥仅握手双方可得。
2. **互认证**:CPE 与 PoP 互验 ZTP 证书(国密档 SM2 证书)。
3. **前向安全(FS)**:任一长期私钥(设备/ CA)泄露,不能解密**此前**捕获的隧道流量。**(国密档 FS 取决于 TLCP 套件选择,见 §5.1 关键发现。)**
4. **密钥分离**:数据面隧道密钥与握手通道(TLS/TLCP 记录层)密钥、与其他用途密钥相互独立,互不推导。
5. **抗降级**:攻击者不能把国密租户隧道降到非国密档(算法由控制面定、不在握手协商)。
6. **抗重放**:数据面计数器 + 接收窗口;**跨 epoch 不重放**。
7. **nonce 不复用**:任一密钥下 (nonce) 全局唯一(含 tx/rx 双向、含 rekey 前后 epoch)。
8. **租户隔离权威 = 密钥 + 证书身份**,非 UDP 源地址/receiver-index(后两者仅解复用)。
9. **有界撤销**:撤销设备 → rekey/续期重验证书失败 → 隧道在证书有效期内断。

### 2.2 非目标(不在本审查)
- 数据面 AEAD 封装/帧/XOR-FEC/重放窗口实现(隧道 L2 Slice18/19,已编码、已护栏)。
- TLS1.3 / TLCP 协议本体的安全性(假定其标准实现可信;见 §三信任假设)。
- ZTNA L7(保持 Envoy,不走本隧道)。
- ZTP 证书签发/CA 体系(`internal/enroll`/`devpki`,已有)。

---

## 三、信任模型与威胁模型

### 3.1 信任假设
- **TLS1.3(RFC8446)与 RFC5705 exporter** 的安全性已确立(形式化分析、广泛部署),视为可信原语。
- **TLCP(GB/T 38636)+ 铜锁实现** 视为可信国密 TLS 实现(其本体不在本审查;但**铜锁是否暴露安全的密钥导出接口**是审查关键未知,§5.1)。
- **ZTP CA / 证书链**(`devpki`):CA 私钥受保护(生产入 HSM),证书身份(tenant=Organization、site=CN)可信。
- **控制面 xDS 下发链已是 mTLS**(as-built)。**抗降级前提的成熟度(诚实):** `SiteConfig` 经该 mTLS 链下发已 as-built(Slice14);但 `tunnel_alg`(算法档)经此链下发到 CPE/PoP 是**设计目标**——当前(Slice30)CPE 的 alg 取自本地 env 默认(dev),**生产须改为取自 xDS 下发的租户档**(握手 L2 §9)。即抗降级(T6/§7.4)在「alg 由 xDS 不可篡改下发」前提下成立,该前提**待生产接线**;dev 下"防降级"只防到本地配置层。

### 3.2 攻击者能力(威胁)
| # | 攻击者 | 能力 | 期望防护 |
|---|--------|------|----------|
| T1 | 网络 MITM | 观测/篡改/重放/丢弃 UDP 数据报与握手 TCP 流;不持任何合法证书私钥 | 机密/完整/互认证/抗重放/抗降级全保 |
| T2 | NAT / 地址漂移 | CPE 源地址经 NAT 变化/复用 | receiver-index 正确解复用,不破隔离 |
| T3 | 被撤销/失陷的边缘设备 | 持**曾合法**的 ZTP 证书(已撤销或将撤销) | 撤销后 rekey 失败 → 有界断;失陷设备不能解他会话/他租户流量 |
| T4 | 跨租户攻击者 | 持租户 A 合法证书,试图够到租户 B 流量 | 隔离权威=密钥+证书身份;伪造 srcAddr/receiver-index → AEAD 丢弃 |
| T5 | 长期私钥事后泄露 | 事后得设备/CA 私钥 + 此前捕获密文 | 前向安全(§5.1 FS 套件强制) |
| T6 | 降级攻击者 | 篡改握手试图协商弱档/非国密 | 算法不协商(控制面定),alg 绑入 KDF context |

---

## 四、已确立基线(Slice30 as-built,无需审查 / 供审查者作锚点)

| 项 | 机制 | 状态 |
|----|------|------|
| 互认证 | mutual TLS1.3,双方 ZTP 证书(`RequireAndVerifyClientCert`) | 已确立(标准) |
| 密钥协商 + FS | TLS1.3 ECDHE | 已确立(标准) |
| 非国密档密钥导出 | RFC5705 / RFC8446 §7.5 exporter,`ExportKeyingMaterial(label, context, L)` | 已确立(标准) |
| 身份绑定 | 从已认证证书取 tenant=Organization、site=CN → 登记 Router | 已编码(Slice30) |
| 抗降级 | alg 由控制面经 xDS 定,握手不协商;CPE 校验 `serverHello.alg==期望` | 已编码(Slice30) |

**当前非国密档密钥导出(已编码,供审查者作对照基准):**
```
label   = "EXPORTER-sase-sdwan-tunnel"
context = epoch(4B big-endian) || alg(ascii)        # 当前 epoch 恒 0;KeyLen: ChaCha20-Poly1305=32B
key     = TLS_Exporter(label, context, KeyLen(alg)) # 两端同 label/context → 同密钥
```
> **epoch 两处编码勿混(H1 澄清):** KDF **context** 内 epoch 用 **4B big-endian**(本基线 as-built);数据面 **nonce** 内 epoch 字段是 **3B**(`[1:4]`,§5.2/§六)。二者是**不同位置的独立编码、数值同源**(context 的 epoch 不必等于 nonce 字段宽度)——非笔误,非两个 epoch。
> 审查者请评判:此非国密基线是否已满足 §2.1 目标 1/2/4/7?(目标 3 FS 对非国密档已由 TLS1.3 ECDHE 标准保证;FS 的待审查焦点在国密档 §5.1。)§五是其国密化 + tx/rx + epoch + NAT 扩展。

---

## 五、待审查构造(逐项精确规格 + 提给审查者的问题)

### 5.1 国密档 TLCP 密钥导出 ★最关键未知★

**背景:** TLS1.3 有 RFC5705 标准 exporter;**TLCP 是否有等价标准导出接口待确认**。

**关键发现(请审查者确认):TLCP 前向安全取决于套件。** TLCP(GB/T 38636)定义两类密钥交换:
- **ECDHE-SM2**(临时 ECDH + SM2 签名认证)→ **有前向安全**。
- **ECC-SM2**(用对端加密证书公钥加密 premaster,类 RSA 密钥传输)→ **无前向安全**。

→ **拟强制要求:国密档隧道握手必须使用 ECDHE-SM2 套件**(满足 §2.1 目标 3 FS;ECC-SM2 禁用)。**请审查者确认此约束充分且铜锁支持 ECDHE-SM2。**

**拟用导出构造(待审查):**
- **优先**:若铜锁暴露 RFC5705 式 TLCP exporter(待铜锁 API 实测),直接用,语义同非国密档(§四),仅哈希换 SM3。
- **回退(无标准 exporter 时)**:据 TLCP 协商出的主密钥,经 **HKDF(RFC5869)以 HMAC-SM3 为 PRF** 派生:
  ```
  PRK   = HKDF-Extract(salt = TLS/TLCP transcript_hash(SM3), IKM = TLCP_master_secret)
  k_dir = HKDF-Expand(PRK, info = "sase-sdwan-tunnel/v1" || epoch || alg || dir, L = KeyLen(alg))
  ```
  > 字段同 §六:`epoch`=E;`dir`∈{`"c2p"`,`"p2c"`};`L=KeyLen(alg)`——**SM4-GCM=16B**(非国密档 ChaCha20-Poly1305=32B,但非国密走 RFC5705 不走本回退)。

**提给审查者的问题(5.1):**
1. **TLCP 是否有标准 keying-material exporter?** 若无,HKDF-HMAC-SM3 从 TLCP 主密钥派生是否密码学健全?
2. **主密钥复用**:把 TLCP 主密钥同时用于其记录层密钥**和**本导出,是否违反密钥分离?是否应改用「握手内独立 key_share / 独立导出标签」而非复用主密钥?
3. **HKDF-HMAC-SM3** 作为 KDF 是否健全(SM3 作 HMAC 哈希;extract/expand 语义)?salt 取 transcript_hash 是否恰当?
4. **铜锁工程可达性**:铜锁是否安全暴露主密钥或导出接口?(待实测,本问含实现可行性。)
5. ECDHE-SM2 FS 约束是否充分?是否还有 TLCP 套件层面的其他陷阱(如重协商、会话复用 session resumption 削弱 FS)?

### 5.2 tx/rx 双密钥 KDF schedule

**背景:** 当前(Slice30)用**单共享密钥 + 方向字节 nonce**(`dptunnel.Session`,sendDir≠recvDir 防同密钥两向 nonce 复用,已护栏)。握手 L2 §4.3 主张演进为 **tx/rx 双密钥**(每方向独立密钥,更干净)。

**拟用构造(待审查):** 每方向独立派生(direction 进 KDF context/label):
```
k_c2p = Export/KDF(..., dir = "c2p", L)   # CPE→PoP
k_p2c = Export/KDF(..., dir = "p2c", L)   # PoP→CPE
```
- 非国密档:两次 RFC5705 exporter 调用,context 含 dir tag(exporter 是 PRF,不同 context → 独立密钥)。
- 国密档:两次 HKDF-Expand,info 含 dir。
- **nonce 布局(12B)**:`[0]=保留 0 | [1:4]=epoch(3B) | [4:12]=counter(8B)`。双密钥下方向字节冗余(两向不同密钥),保留 `[0]=0`;counter 单调(隧道 L2 重放窗口 + `1<<48` 阈值 fail-closed 已护栏)。

**提给审查者的问题(5.2):**
1. 双密钥(每向独立)vs 现「单密钥 + 方向字节」——双密钥是否确有安全收益(超出方向字节)?抑或单密钥+dir 已充分、不必增复杂度?
2. 双密钥下 nonce 是否还需方向字节?epoch(3B)+ counter(8B)在**每向独立密钥**下是否足以保证 nonce 唯一?
3. 两次 exporter/HKDF 调用产 k_c2p/k_p2c,仅靠 context 中 dir tag 区分,独立性是否充分?

### 5.3 NAT receiver-index(收口入向解复用)

**背景:** 当前 PoP 按 UDP srcAddr 解复用到会话(非 NAT/dev 可行)。NAT 下源地址漂移/复用 → 须 PoP 分配的 **receiver-index** 作解复用键(握手 L2 §4.4)。

**拟用构造(待审查):**
- **格式**:4 字节,置于数据面 UDP 数据报**最外层**(dptunnel 帧之前)。
- **分配**:PoP 握手时分配,经控制连接(serverHello)告知 CPE;CPE 每个数据报前缀之。PoP 在本机所有活跃会话内唯一;会话拆除后排空窗口过后回收。
- **安全语义**:**明文、仅解复用**。伪造/猜中他会话 index → 命中的会话用其 AEAD 密钥 `Open` 伪造载荷必失败 → 丢弃。**不破隔离**(权威是每会话密钥,§2.1 目标 8)。

**提给审查者的问题(5.3):**
1. index 明文不认证,除「误投→AEAD 丢弃」外,有无其他攻击面(如流量分析/会话关联/DoS 放大)?
2. 分配应**随机**(防枚举/关联)还是**顺序**(实现简单)?随机的碰撞处理?
3. 是否应把 receiver-index 绑进数据帧 AEAD 的 `aad`(认证它)?——但它在解密前用于解复用,绑 aad 仅能事后校验,价值/代价权衡?
4. 长度 4B 是否足够(单 PoP 并发会话上限 vs 枚举难度)?

### 5.4 rekey / epoch 编排

**背景:** 会话密钥须周期轮换(FS + 限单密钥用量);计数器近阈值(`1<<48`,`ErrRekeyRequired` 已护栏)亦须 rekey。

**拟用构造(待审查):**
- **触发**:时间(默认周期**待定**,权衡 FS 粒度 vs 握手开销)**或**计数器近阈值(fail-closed,隧道 L2 已实现)。
- **机制**:**重走一次完整 mutual TLS/TLCP 握手**(全新临时 DH/SM2 ephemeral)→ 新主密钥 → 新 epoch `E+1` 的 tx/rx 密钥。**每 epoch 独立 FS**(新 ephemeral)。
- **epoch 字段**:nonce `[1:4]` = epoch(3B,16,777,216 个);counter 每 epoch 从 0 重起。
- **并存窗口**:rekey 时新旧 epoch 短暂并存——**发送方原子切到 E+1**;**接收方同时接受 E 与 E+1**(排空在途 E 包),时限到后 **E 转只收不发→关闭**。
- **nonce 不复用保证**:每 epoch 独立密钥 → 即便 counter 空间在 E 与 E+1 重叠,密钥不同 → 无 nonce 复用;epoch 入 nonce 为纵深防御。
- **撤销联动**:rekey 重握手即重验证书 → 被撤销设备 rekey 失败 → 隧道在当前 epoch 排空后断(有界,§2.1 目标 9)。

**提给审查者的问题(5.4):**
1. 并存窗口期(同时收 E/E+1)有无跨 epoch 重放风险?**每 epoch 独立重放窗口**是否充分(E 的旧包不能在 E+1 窗口被接受)?
2. epoch 3B 回绕(理论 16M 次 rekey)——拟「回绕即强制重新入网(全新证书/会话)」,是否可接受?是否需更宽 epoch?
3. rekey 期间的降级:重握手重新从控制面取 alg(不协商)→ 是否彻底排除「rekey 时降级」?
4. counter-阈值触发(数据量驱动)与时间触发并存,是否有竞态(同时触发两次 rekey)?
5. 发送方原子切换 + 接收方双 epoch 接受的**最大并存时长**如何定界,使既不丢在途包、又不长期留旧密钥(削弱 FS)?

---

## 六、统一密钥 schedule(把四项串成一张规格,待审查整体)

> **成熟度标记**(诚实区分,勿误以为整图已实现):`[基线]`=Slice30 非国密档已编码;`[提案]`=待本审查通过后编码。

```
每次 (re)握手,epoch = E:
  1. [基线:非国密 TLS1.3 已编码 | 提案:国密 TLCP-ECDHE-SM2]
     mutual TLS1.3(非国密)/ TLCP-ECDHE-SM2(国密)握手 → 主密钥 MS_E(全新 ephemeral → 每 epoch FS)
  2. [基线:非国密单密钥已编码 | 提案:tx/rx 双密钥 + 国密 HKDF 回退]
     导出(非国密 = RFC5705 exporter;国密 = 标准 TLCP exporter 或 HKDF-HMAC-SM3 回退):
       k_c2p_E = KDF(MS_E, info = "sase-sdwan-tunnel/v1" || E || alg || "c2p", L=KeyLen(alg))
       k_p2c_E = KDF(MS_E, info = "sase-sdwan-tunnel/v1" || E || alg || "p2c", L=KeyLen(alg))
     (E = §5.x 的 epoch;dir ∈ {"c2p","p2c"};L=KeyLen(alg):ChaCha20=32B / SM4-GCM=16B)
  3. [提案:NAT receiver-index,§5.3] PoP 分配 receiver-index_E(4B,本机唯一);经 serverHello 告知 CPE
     (基线现状:无 receiver-index,PoP 按 UDP srcAddr 解复用,非 NAT/dev 可行)
  4. [基线:数据面封装/重放/FEC 已编码(隧道 L2)| 提案:epoch 入 nonce + receiver-index 外层]
     发 CPE→PoP:AEAD(k_c2p_E, nonce = 0x00 || E(3B) || counter(8B)), 外层前缀 receiver-index_E
     发 PoP→CPE:AEAD(k_p2c_E, nonce = 0x00 || E(3B) || counter(8B))
       (counter 每方向每 epoch 单调从 0;近 1<<48 → 触发下一次 rekey,E+1)
  5. [提案:rekey/epoch 编排,§5.4] rekey:回 1(新 E),并存窗口排空旧 epoch
身份/隔离 [基线]:tenant/site 来自步骤 1 已认证证书;隔离权威 = 各会话独立 k_*;srcAddr/receiver-index 仅解复用
抗降级 [基线机制,生产前提见 §三 S3]:alg 来自控制面 xDS,绑入步骤 2 的 info;握手不协商算法
```

**提给审查者的整体问题:** 上述 schedule 是否满足 §2.1 全部目标?四项构造组合后有无相互作用引入的新弱点(如 epoch + receiver-index + 双密钥的交叉)?

---

## 七、审查者问题清单(汇总,按优先级)

**P0(阻塞编码):**
- Q1(5.1):TLCP 标准 exporter 是否存在?无则 HKDF-HMAC-SM3 从主密钥派生是否健全 + 是否违密钥分离?
- Q2(5.1):国密档强制 ECDHE-SM2(禁 ECC-SM2)以保 FS——约束是否充分?
- Q3(5.4):rekey 并存窗口 + 每 epoch 独立重放窗口,跨 epoch 重放是否被排除?
- Q4(5.2):nonce(epoch 3B + counter 8B,双密钥每向独立)nonce 唯一性是否成立?

**P1(影响构造选择):**
- Q5(5.2):tx/rx 双密钥 vs 单密钥+方向字节——是否值得?
- Q6(5.3):receiver-index 明文/分配策略/是否绑 aad 的攻击面与权衡。
- Q7(5.4):epoch 回绕策略、时间/计数双触发竞态、并存时长定界。

**待实测(工程,非纯密码学,但影响方案):**
- Q8:铜锁 TLCP API 是否暴露主密钥/导出接口、是否支持 ECDHE-SM2。
- Q9:rekey 周期默认值(FS 粒度 vs 握手开销实测)。

---

## 八、审查范围边界(out of scope,勿评)

- 数据面 AEAD 封装/帧格式/XOR-FEC/重放窗口**实现**(隧道 L2 Slice18/19,已编码、已护栏;本文只在 schedule 中引用其 nonce/counter 接口)。
- TLS1.3 / TLCP 协议本体安全性(假定标准实现可信)。
- ZTP CA / 证书签发 / HSM(`devpki`/`enroll`,另有设计)。
- ZTNA(L7,不走本隧道)。
- 非密码学的工程性能(worker pool / radix LPM 等)。

---

## 九、结论

本审查包把 SD-WAN 隧道握手待解锁的四项构造——**国密档 TLCP 密钥导出(关键未知,含强制 ECDHE-SM2 保 FS 的发现)、tx/rx 双密钥、NAT receiver-index、rekey/epoch 编排**——精确规格化为一张统一密钥 schedule(§六),并给出安全目标(§二)、威胁模型(§三)、与按优先级排序的审查者问题清单(§七)。**所有拟用构造均只组合标准原语(标准 AEAD / RFC5705 exporter / HKDF / HMAC-SM3 / ECDHE-SM2),不发明密码学原语、不改成熟协议本体**——与隧道 L2 §7.1「有限自研、经审查」同口径。**P0 四问(尤 Q1 TLCP 导出、Q2 ECDHE-SM2 FS)是编码前置硬门:获独立密码学审查确认/修正后,方编码这四项(届时 `dptunnel.Session` 演进为 tx/rx 双密钥 + epoch、PoP/CPE 加 receiver-index 外层、握手加 TLCP 档与 rekey 循环)。** 非国密档基线(Slice30)已端到端跑通,作审查锚点。
