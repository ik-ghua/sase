# 数据面隧道 L2(SD-WAN 数据报隧道 + FEC)

> **状态:** L2 组件设计 / 待评审
> **版本:** v0.2
> **日期:** 2026-05-26
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **v0.2(2026-05-26):** 握手机制修正——由原 §4.2/§7.1 拟定的「借 Noise IK 有限自研」改为 **互认证 TLS1.3(非国密)/ TLCP-铜锁(国密)+ 密钥导出**(详见握手 L2 `sase-l2-tunnel-handshake.md`,花刚认可形态 A)。理由:Noise 无国密原语,国密档走 Noise 必自研"国密 Noise"(违 L1 2.3);TLCP 是现成国密件 → 握手的**密钥协商+认证零自研**,残留自研收窄到数据面封装 + 国密密钥导出 + rekey 编排。本次更新 §3/§4.2/§7.1/§8/§9。
>
> **层级与上承:** L2 组件设计,落地 L1 `sase-architecture-design.md`(现 v0.6,本文形态已回写 3.7/R7/附录)的 **3.7(数据面加密栈)、R7(国密)** 与 `sase-gm-crypto-selection.md`(现 v0.4,3.2 隧道形态已收敛)在 **SD-WAN 数据面**的具体形态。形态决策(自研 crypto-agile UDP 数据报隧道)由 2026-05-26 评审拍板(见记忆 `tunnel-form-decision`)。
>
> **✅ 对 L1/gm-crypto 既有结论的修正(已回写 L1 v0.6 / gm-crypto v0.4):** L1 3.7 与 gm-crypto 原隧道结论为「**TLCP/铜锁**(TLS 流隧道)」。本文**修正 SD-WAN 数据面隧道的封装形态**:由「TLCP over TCP/TLS 流」改为「**自研 UDP 数据报隧道**」。**变的是封装形态(TLS 流 → UDP 数据报),不变的是国密算法栈**——国密档仍用铜锁/gmsm 的 **SM4-GCM AEAD + SM2 密钥交换/SM3**,只是不再以 TLCP 记录层承载,而是自研数据报封装内调用同样的国密 AEAD。**TLCP/铜锁继续用于管理面/控制信令面 TLS(gm-crypto 3.8)与 ZTNA 传输层,不受本文影响。** 此修正**已于 2026-05-27 回写 L1 3.7/R7/附录 + gm-crypto 3.2**(backlog `l1-v05-writeback-backlog` W10 已关闭)。
>
> **衔接:** SD-WAN CPE L2(`sase-l2-sdwan-cpe.md`:WAN/选路/链路修复)、PoP 单机编排 L2(`sase-l2-pop-orchestration.md`:per-tenant 路由域、CAP_NET_ADMIN)、客户端 Agent/Connector L2(ZTP 身份)、国密选型(PoC-G M-G3~M-G5)、as-built `internal/{revtunnel,linkmon,enroll,site,cpe}`。
>
> **范围:** 仅 **SD-WAN 站点间 L3 包隧道**的协议形态、加密、FEC、与现有底座的复用、风险与分期。**ZTNA 数据面保持 L7 反向代理(`revtunnel`)不变**(见 2.2)。完整线协议字节布局、握手状态机细节留实施期。

---

## 1. 背景

**现状(as-built stand-in):** SD-WAN 站点 overlay 当前复用 ZTNA 的 L7 反向代理 `revtunnel`(CPE 以 `site_key` 注册为连接器,PoP 在租户路由域内把站点 A 的请求反向送到站点 B 的 CPE)。`revtunnel` 是 **JSON 请求/响应 over TCP/mTLS**——L7、可靠流、按请求语义。这对 Slice14 验证「地基统一」足够,但**不是包隧道**:

- **SD-WAN 站点组网要桥接 L3 网段**(站点 A 的 10.1.0.0/24 ↔ 站点 B 的 10.2.0.0/24,承载任意 IP 流量:TCP/UDP/ICMP/任意应用),L7 请求代理承载不了任意 L3 包。
- **FEC(前向纠错)只在数据报隧道上有意义**:可靠 TCP 流自带重传,FEC 无从插入;高丢包 WAN(4G/卫星/跨境专线)需在**数据报**上加冗余包、丢包直接恢复、免重传往返延迟。

**决策已定(本文档落地):** 形态 **②自研 crypto-agile UDP 数据报隧道**(2026-05-26 评审)。本文档给出其协议形态、加密与 FEC 设计、与现有底座复用、风险与分期。

---

## 2. 目标 / 非目标

### 2.1 目标
1. **SD-WAN 站点间 L3 包隧道**:CPE 经 TUN 设备收发站点 L3 包,封装为 UDP 数据报经 PoP 转发到对端站点 CPE;承载任意 IP 流量。
2. **crypto-agility**:加密算法可插拔——`ChaCha20-Poly1305`(非国密,默认,现可基准)↔ `SM4-GCM`(国密,待国密 CPU),**协议/握手/线格式不随算法变**(延续 `internal/cred` 的 crypto-agility:`Ed25519↔SM2`)。
3. **FEC 可选**:对 UDP 数据报分组做前向纠错(起步 XOR 奇偶),按链路丢包率开/调;crypto 无关。
4. **复用既有底座(不另造)**:ZTP 设备证书(SM2/Ed25519)做隧道对端认证+密钥协商;xDS `SiteConfig` 扩展下发隧道参数;`linkmon` 选 WAN 出口;PoP 每租户路由域隔离不破。
5. **诚实分期**:本阶段交付 ChaCha20 数据报隧道 + XOR-FEC 骨架(可在无国密 CPU 的 PoC VM 上真实基准);SM4-GCM provider 留接口,吞吐基准待国密 CPU(C-G1)。

### 2.2 非目标
- **ZTNA 不改包隧道**。ZTNA(面向人/应用)的 L7 身份感知反向代理是恰当模型(应用级、随会话身份、客户端无需路由网段),`revtunnel` 保留。「真隧道」对 ZTNA 仅指传输硬化(已 mTLS;国密走 TLCP 传输层,属国密选型 3.8,不在本文)。
- **不替换 `revtunnel`**:它继续服务 ZTNA Connector;SD-WAN 站点 overlay 从它迁到本隧道。
- **不做 SM4 吞吐基准**(待国密 CPU,M-G3~M-G5);本文不编造国密性能数。
- **不发明密码学原语**(见 7.1):只组合标准原语。

---

## 3. 形态决策与备选

| 备选 | 依据 | 落选 / 顾虑 |
|------|------|------------|
| **② 自研 crypto-agile UDP 数据报隧道(选定)** | **选定驱动:** 单一数据报路径(FEC 自然层叠、WAN 切换无 TCP 重连)+ 算法可插拔(与 `cred` 一致,SM4 待 CPU 只换实现不换协议)。**握手另用 TLS1.3/TLCP 导出(密钥协商+认证零自研,握手 L2);数据面仅密文封装** | 残留有限自研(数据面封装 + 国密密钥导出 + rekey 编排,经审查),比整包复用现成件风险高(直面见 7.1) |
| ① WireGuard(非国密)+ TLCP(国密)双栈 | WG 成熟;R7 国密侧已定 TLCP/铜锁 | WG **国密化已落选**(gm-crypto v0.3);WG 是 UDP 数据报、TLCP 是 **TLS 流(TCP,隧道内 head-of-line 阻塞)**——两者数据路径形态不一 → **两套包路径 + 两套运维**,且 FEC 无法统一层叠 |
| ③ QUIC(quic-go)可插拔 | 自带流/数据报/拥塞控制 | **国密 QUIC 非标、不成熟**;QUIC 可靠流与 FEC 取舍重叠,增复杂度 |

**结论:** 选②。ZTNA 保持 L7(2.2)。

---

## 4. 隧道协议设计

### 4.1 分层(自顶向下)
```
站点 L3 包(任意 IP) ── TUN 设备(CPE 侧)
        │
   [可选] FEC 编码/解码(对密文数据报分组,见 §5)
        │
   AEAD 封装(crypto provider:ChaCha20-Poly1305 / SM4-GCM)+ 重放计数器
        │
   UDP 数据报 ── 经 linkmon 选定的活动 WAN 出口 ── PoP
        │
   PoP:解封 → 按租户路由域路由到目标站点 CPE(per-tenant 隔离,§6.4)
```

**设计依据:** 分层让「加密」「FEC」「传输」正交——crypto provider 换算法不动 FEC/传输;FEC 开关不动加密。借鉴 WG 的「UDP + AEAD + 计数器重放保护」骨架(成熟、最小),但**密码 provider 抽象化**以支持国密。

### 4.2 加密与 crypto provider 抽象
- **AEAD 接口**(provider):`Seal(key, nonce, plaintext, aad) → ciphertext` / `Open(...)`。实现:`ChaCha20-Poly1305`(Go 标准库 `golang.org/x/crypto/chacha20poly1305`,现可用可基准)、`SM4-GCM`(`emmansun/gmsm`,已在 `cred`/PoC-G 引入;待国密 CPU 基准)。
- **握手与密钥协商(详见握手 L2 `sase-l2-tunnel-handshake.md`,形态 A)**:用 **互认证 TLS1.3(非国密)/ TLCP-铜锁(国密)** 完成对端认证 + 密钥协商,以 ZTP 设备证书(§6.1)为身份,经**密钥导出**(RFC5705 式 / 国密档 SM3-KDF)派生本数据面会话密钥(tx/rx)。**握手的密钥协商+认证零自研**(复用 TLS1.3/TLCP 成熟件,国密档天然有 TLCP、不必自研国密 Noise)。具体密钥导出/rekey/receiver-index 见握手 L2,**须经第三方密码学审查**。
- **会话密钥轮换(rekey)** + **重放保护**(单调递增计数器 nonce + 接收窗口),沿用 WG 同类机制。
- **算法选择**:经 xDS `SiteConfig` 下发租户/站点的 `tunnel_alg`(默认 `chacha20poly1305`,国密租户 `sm4gcm`),与 `cred` 的 `SASE_CRED_ALG` 同范式。

### 4.3 数据路径
- **CPE 侧**:TUN 设备收站点出向 L3 包 → (可选 FEC) → AEAD seal → UDP 发往 PoP(经 linkmon 活动链路);收向反之。
- **PoP 侧**:收 UDP → AEAD open → 按**租户路由域**查目标站点 → 转发到目标站点 CPE 的隧道会话。PoP 是站点间中继(hub),站点不直连(符合控制面/数据面 + 全国 PoP 架构;站点直连 mesh 留后置)。

---

## 5. FEC 设计

**背景:** 高丢包 WAN(无线/卫星/跨境)上,TCP 重传往返放大延迟;FEC 用冗余包让接收端**直接恢复**丢失包,免重传。

**方案(起步→后置):**
- **起步:块状 XOR 奇偶**。每 `k` 个数据报一组,发 `1` 个 XOR 冗余包(`m=1`),可恢复组内**任意 1 个**丢包。简单、计算极轻、零外部依赖。
- **后置:Reed-Solomon**(`k`+`m`,纠多丢包)——丢包率高时需要;引入 RS 库(待选型)。
- **自适应(后置)**:据 `linkmon` 测得丢包率动态开/调 `m`;**拥塞性丢包下 FEC 反而加剧拥塞** → 据丢包性质(随机 vs 拥塞,看 RTT 趋势)决定,起步**固定/手动**(由 xDS `SiteConfig` 下发 `fec_k`/`fec_m`,默认关)。

**在密文上做 FEC(非明文):** FEC 分组对 **AEAD seal 后的密文数据报**做。依据:① 纠的是 UDP 链路丢包,密文层纠错即可;② 不泄露明文结构;③ 冗余包不含可解密内容(XOR of 密文)。接收端 FEC 恢复出密文包后再 AEAD open。

**取舍:** FEC 增带宽开销 `m/k`(如 k=10,m=1 → +10%)换免重传延迟。**开启条件对齐 CPE L2 3.4(`sase-l2-sdwan-cpe.md`):仅「实时业务 + 劣化链路」双条件开**(实时业务维度控带宽 R3),低丢包/拥塞/非实时链路关(否则纯浪费/加剧拥塞)。

**与「包复制/抖动缓冲」的分工:** L1 3.9 / CPE L2 3.4 的链路修复含 FEC + **包复制(双发取先到)** + 抖动缓冲。本隧道层只提供 **FEC** 与多 WAN 出口绑定能力;**包复制/抖动缓冲属 CPE L2 链路修复**(`sase-l2-sdwan-cpe.md` 3.4),本文不重复设计(包复制可在本隧道的多 WAN 出口能力上实现,归 CPE L2)。

---

## 6. 与现有底座的复用(不另造)

### 6.1 身份与密钥(复用 ZTP)
隧道对端认证 + 密钥协商**复用 ZTP 设备证书**(`internal/enroll`:CPE 以 `site_key` 为 CN、租户编进 Organization 的 SM2/Ed25519 证书)。隧道握手以该证书做对端身份校验 + 协商会话密钥。**撤销/续期/轮换沿用**(`RevokeDevice`/`Renew`/`CertRotator`)——撤销设备 → 续期被拒 → 证书过期后隧道握手失败(有界时间断网,与 revtunnel 撤销模型一致)。**避免再造隧道身份体系。**

### 6.2 下发(复用 xDS SiteConfig)
隧道参数(对端站点 UDP endpoint、`tunnel_alg`、`fec_k`/`fec_m`、密钥协商材料引用)经 **xDS `SiteConfig` 扩展字段**下发(复用 MuxCache 第 4 类独立 Delta 流,as-built)。不新增下发通道。

### 6.3 WAN 选路(复用 linkmon)
UDP 隧道的出口走 `linkmon` 选定的活动 WAN 链路;链路失效**亚秒切换**(Slice17)即重绑 UDP socket 到新出口。数据报隧道**无连接重建成本**(无 TCP 握手),切换比 revtunnel 的 TCP/mTLS 重连更平滑——这也是②形态相对 TLCP(TLS 流)的优势之一。
> 注:`linkmon` 当前(Slice17)只做 TCP 探测 + 选路(服务于 revtunnel);**「按 `Best()` 重绑 UDP 隧道 socket 到新出口」是本隧道层新增**(探测器/选路逻辑复用,出口绑定逻辑新写)。探测器可换 UDP 探测(隧道内 keepalive)以贴合数据报路径。

### 6.4 隔离(复用 PoP 每租户路由域,不可破)
PoP 解封后的包路由**必须落在 per-tenant 路由域/netns**,沿用 **PoC-1 实测两条硬要求**(per-tenant 表 `unreachable default` + 进程持 `CAP_NET_ADMIN`,L1 3.7/3.20)。**TUN 设备 + 包路由同样需 `CAP_NET_ADMIN`**(PoP 编排 L2 须保证;与共享 Envoy 同要求)。站点 overlay 路由不得跨租户(隔离测试门禁覆盖)。

### 6.5 与 revtunnel 关系
SD-WAN 站点 overlay 从 `revtunnel`(L7 stand-in)迁到本数据报隧道;`revtunnel` 继续服务 **ZTNA Connector**(L7,不变)。迁移期两者并存。

---

## 7. 风险

### 7.1 自研面与密码学风险 —— 与 L1 2.3「不自研加密协议」的关系
**直面红线:** gm-crypto v0.3 让「WG 国密化(①)」落选的核心理由正是 L1 2.3——改 WireGuard 内部 `Noise_IKpsk2` 套件 = 改成熟协议内部、毁其安全证明。本设计如何守住该原则:

1. **握手(最高危)零自研**:密钥协商 + 互认证用 **TLS1.3 / TLCP-铜锁**(成熟、TLS1.3 有形式化分析、TLCP 是国密标准实现),不自研握手协议(见握手 L2 §3/§7.2)。这正是相对原 Noise 方案、相对 ①/③ 的关键:**国密档天然有 TLCP,无须自研"国密 Noise"**。
2. **残留有限自研(收窄、须审查)**:① 数据面 AEAD 封装/帧/FEC(本文);② 国密档密钥导出(TLCP 若无标准 exporter → SM3-KDF 派生,握手 L2 §7.3);③ rekey/epoch 编排。三项**只组合标准原语**(标准 AEAD、SM3-KDF、计数器),不发明原语、不改成熟协议本体。
3. **为何无法零自研**:目标 **数据报(UDP)+ 国密 + 成熟** 无满足三者的现成件(TLCP 是流非数据报、DTLS 无成熟国密、QUIC 国密非标),故数据面封装必有限自研;但**已把最高危的握手移出自研面**。

**花刚已认可(2026-05-26)**:接受上述"残留有限自研(数据面封装+密钥导出+rekey,经审查)",握手核心用 TLS/TLCP 零自研。**上线前须第三方密码学审查**,范围见握手 L2 §8(尤其 TLCP 密钥导出)。

### 7.2 SM4 吞吐(待国密 CPU)
SM4-GCM 软件实现慢 AES-NI ~6×(PoC-G M-G2 实测)→ 承载国密租户的 PoP 须带 **AVX-512+GFNI 或专用 SM4 指令**(C-G1 硬性)。**带加速吞吐 = 待实测(M-G3~M-G5,待国密 CPU)**,本文不编造。本阶段 ChaCha20 档可在 PoC VM 真实基准。

### 7.3 用户态 TUN 吞吐
用户态 TUN 收发有内核↔用户态拷贝开销,吞吐有上限(具体 = **待实测 M**)。后续可借鉴内核 WG / eBPF-XDP 加速(后置);起步用户态验证形态。

### 7.4 MTU / 分片
隧道封装(UDP+AEAD+FEC 头)降有效 MTU → 站点包超 MTU 会分片/丢弃。**缓解:** 钳制隧道内 MSS、或 PMTUD;起步保守钳制 MTU,PMTUD 后置。

### 7.5 FEC 在拥塞下反效果
拥塞性丢包加 FEC 冗余 → 加剧拥塞。**缓解:** 默认关,仅手动/按随机丢包特征开;自适应(看 RTT 区分随机 vs 拥塞)后置(5)。

### 7.6 形态迁移期复杂度
站点 overlay 双路径(revtunnel + 新隧道)并存 → 运维/排障复杂。**缓解:** 按租户/站点灰度迁移,xDS 下发开关;迁完下线 revtunnel 的 SD-WAN 用法。

---

## 8. 分期与待确认

**本阶段(✅ Slice18 已码协议核心 `internal/dptunnel`,VM 真实跑):**
- ✅ AEAD provider 抽象:`ChaCha20-Poly1305`(默认)/`SM4-GCM`(gmsm),`NewAEAD(alg,key)`,印证 crypto-agility。
- ✅ 密文数据报帧 + 单调计数器重放窗口(64,RFC6479 式)+ 块状 XOR-FEC(`k`/`m=1`,`k<=1` 关)。
- ✅ **安全护栏(评审 B1/B2)**:帧头(Type/BlockID/Index/K)作 AEAD `aad` 认证(篡改/伪造帧头 → 认证失败丢弃);计数器达阈值(`1<<48`)→ `ErrRekeyRequired` fail-closed(防 nonce 回绕复用);`sendDir!=recvDir` 断言;FEC 解码缓冲滑窗(64)+ 硬顶(256)防伪造 parity 撑爆内存;只缓冲已认证 data 帧。
- ✅ **基准(PoC VM Xeon E5,无 SM4 加速,单核 seal 1400B)**:ChaCha20-Poly1305 **611.9 MB/s≈4.9 Gbps/核**;SM4-GCM(gmsm 软件)**207.4 MB/s≈1.66 Gbps/核**(~3× 慢,与 PoC-G M-G2 一致)。**带加速 SM4 待国密 CPU(C-G1,M-G3~M-G5)**;此为 seal-only 加密成本,非端到端隧道吞吐。
- ✅ **集成(Slice19)**:`PacketIO` 抽象(TUN 接缝)+ CPE `Endpoint`(TUN↔Session↔UDP 双 pump)+ PoP `Router`(srcAddr 解复用 → 源会话解封 → 按内层目的 IP 在**源租户内** LPM 选路 → 目的会话重封转发)+ `Serve` UDP 循环。**租户隔离**:选路只在源租户路由域内,权威锚点是每会话独立 AEAD 密钥(srcAddr 仅解复用提速,伪造源无密钥 → AEAD 失败丢弃)。Linux TUN 经 `/dev/net/tun`+TUNSETIFF(原始 IP 包),特权容器验证设备创建(`tun0`)。e2e 回环测:A→PoP→B 送达 + 无路由丢弃 + 同 CIDR 跨租户不泄漏 + 伪造源丢弃 + 混合 v4/v6 选路;`-race` 干净。
  - 骨架性能限(已注释):单 `Serve` goroutine 串行、线性 LPM —— 生产需 worker pool/SO_REUSEPORT + radix LPM。
- ⬜ **待密码学审查后接**:**TLS1.3/TLCP 导出握手 + ZTP 证书密钥协商**(形态 A,握手 L2;当前 Session 接受外部注入会话密钥);rekey/epoch(nonce `[1:4]` 预留)。NAT 下的入向解复用须 receiver-index(握手协商)。
- ⬜ **待**:`cmd/cpe`/PoP-agent 接 Endpoint/Router(需握手才能真协商密钥跑通)、把 SD-WAN 站点 overlay 从 revtunnel 迁到本隧道、FEC 自适应/Reed-Solomon、PMTUD。

**后置:** Reed-Solomon、FEC 自适应、PMTUD、内核/eBPF 加速、站点直连 mesh、SM4 基准(待国密 CPU)。

**待确认 / 待实测:**
- 用户态 TUN 吞吐(M,待实测)。
- SM4 带加速吞吐(M-G3~M-G5,待国密 CPU)。
- 握手机制见握手 L2 `sase-l2-tunnel-handshake.md`(TLS1.3/TLCP 导出,形态 A);其密码学审查项(尤其 TLCP 密钥导出)见该文 §8。
- FEC 默认 `k`/`m`(待真实链路丢包数据)。
- MTU 钳制值 / 是否上 PMTUD(待实测)。

---

## 9. 结论

SD-WAN 数据面采用**自研 crypto-agile UDP 数据报隧道**:分层(TUN→FEC→AEAD→UDP)正交,加密算法 `ChaCha20-Poly1305↔SM4-GCM` 可插拔(协议不变,延续 crypto-agility),FEC 对密文分组做 XOR 起步。**复用 ZTP 身份、xDS 下发、linkmon 选路、PoP 每租户路由域隔离**,不另造体系。**ZTNA 保持 L7 反向代理不变。** 本阶段交付 ChaCha20 隧道 + XOR-FEC 骨架(PoC VM 可真实基准),SM4 与吞吐基准待国密 CPU(C-G1);**握手用 TLS1.3/TLCP 导出(形态 A,握手 L2),密钥协商+认证零自研**,残留有限自研(数据面封装+密钥导出+rekey)上线前需密码学审查。形态相对 WG+TLCP 双栈的关键优势:单一数据报路径(FEC 可统一层叠、WAN 切换无 TCP 重连)。
