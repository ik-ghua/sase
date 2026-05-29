# PoC-G 国密性能验证 · 结果(M-G1 SM4 吞吐)

> **日期:** 2026-05-25
> **环境指纹:** Intel **Xeon E5-2696 v4(Broadwell, 2016)**,flags 仅 **aes avx2**(**无 AVX-512 / 无 GFNI / 无专用 SM4 指令**);Ubuntu 20.04 VM;单核 `openssl speed`(16KB 块,bulk 吞吐)。
> **对应:** `sase-gm-crypto-selection.md` M-G1;验证 SM4 吞吐是否支撑 10Gbps/PoP(L1 2.2)。
> **范围:** 单核合成基准(openssl speed),给**相对量级**;真实数据面有 framing/RSS 开销,绝对值另测。

## M-G1 数据(单核,Gbps/核,16KB 块)

| 实现 | SM4 | ChaCha20-Poly1305 | AES-128-GCM |
|------|-----|-------------------|-------------|
| OpenSSL 1.1.1f | 0.77 (CBC) | 11.1 | 29.6(AES-NI)|
| OpenSSL 3.5.4 | 0.71 (CBC) / 0.72 (GCM) | 11.0 | 27.3 |
| **铜锁(Tongsuo,github HEAD,自建)** | **0.76 (CBC) / 0.79 (GCM)** | 11.0 | — |

## 关键结论

1. **在这颗 CPU 上,SM4 ≈ 0.75–0.8 Gbps/核,且与实现无关**——OpenSSL 1.1.1、OpenSSL 3.5、**铜锁**三者几乎一致。即:**我们选的优化库(铜锁)在此硬件上也没拉开 SM4 性能。**
2. **SM4 比 ChaCha20(当前数据面隧道算法)慢约 14×**(0.8 vs 11 Gbps/核)。按此,**10Gbps/PoP 光 SM4 加密就要 ~13 核**(ChaCha20 仅 ~1 核)。
3. **根因 = 硬件,不是实现:** 铜锁等的 SM4 大提速依赖 **AVX-512 + GFNI**(Intel Ice Lake+/Sapphire Rapids、AMD Zen4+)或**专用 SM4 指令**(海光/兆芯、ARMv8.4、最新 Intel)。这颗 **2016 Broadwell 只有 AVX2、无 GFNI/AVX-512/SM4-ISA**,优化路径吃不到 → 各实现收敛到 ~0.8 Gbps 基线。

## 对设计的影响(决策级)

- **印证国密选型 RG1**(SM4 无 ChaCha20 那种"免硬件即快"特性)——已实测坐实。
- **C-G1 升级为硬性部署要求:PoP CPU 必须带 SM4 加速**(AVX-512+GFNI,或专用 SM4 指令)。否则国密租户的单 PoP 承载暴跌(~14×),**直接恶化单位经济性(L1 5.1)**。
- **"国密 CPU/新 CPU"被正确定位**:不是 PoC 阻碍(本结论无需它即得出),而是**部署硬件选型要求** + 一个**聚焦的后续实测**(在带 AVX-512+GFNI 或 SM4-ISA 的 CPU 上确认 SM4 恢复到可用吞吐——这才是需要那类 CPU 的地方,属 M1/C-G1 硬件验证)。

## 未覆盖 / 下一步

- **带 SM4 加速的 CPU 上复测 M-G1**(AVX-512+GFNI 的新 Xeon/EPYC,或海光/兆芯/ARMv8.4)——确认 SM4 恢复到接近 ChaCha20/AES 量级(这是"国密 CPU"真正用武之处)。
- **M-G2 TLCP/SM2 握手延迟**:`openssl speed sm2` 在该版未出数;留铜锁 `s_time` 做 TLCP 握手压测(SM2 握手是每连接一次、非每包,预期非瓶颈)。
- **M-G3 铜锁-Envoy / M-G4 TLCP-over-QUIC / M-G5 控制面国密 mTLS**:功能/吞吐待做(不依赖国密 CPU)。

## 复现

```
# 在 VM(docker 免 sudo)上:
openssl speed -evp sm4-cbc / chacha20-poly1305 / aes-128-gcm        # 系统 openssl 1.1.1
docker run --rm nicolaka/netshoot openssl speed -evp sm4-gcm ...    # openssl 3.5
# 铜锁:golang 容器内 git clone github.com/Tongsuo-Project/Tongsuo → ./config → make -j → apps/openssl speed
```

> 数据为目标 Linux 主机(x86 Broadwell)真实运行;**该 CPU 无 SM4 硬件加速,SM4 数为该档硬件的实测值**;带加速硬件的 SM4 上限待该类 CPU 复测。

---

## M-G2 国密代码栈 + Go gmsm 基准(2026-05-26,同一 VM)

> **背景:** 进入编码后,把凭证签名做成**算法可插拔**(crypto-agility):`internal/cred` 同一 Claims/令牌契约下,签名 scheme 可在 **Ed25519(默认)↔ 国密 SM2(gmsm)** 间换,部署期经 `SASE_CRED_ALG` 选,**契约/TrustBundle 形态不变**(单测 `TestSignerVerifierAgility` 双算法往返通过)。本节给 gmsm(Go,纯软件)在同一 Broadwell VM 上的真实基准。
> **环境:** 同 M-G1(Xeon E5-2696 v4,aes+avx2,**无 GFNI/AVX-512/SM4-ISA**);`go test -bench`,`github.com/emmansun/gmsm v0.29.0`,go1.22 容器。

### 非对称(凭证/PKI 签名,每次操作)

| 算法 | Sign | Verify |
|------|------|--------|
| **SM2(gmsm)** | 27.4 µs/op(~36.6k/s) | 97.0 µs/op(~10.3k/s) |
| Ed25519(stdlib) | 36.2 µs/op(~27.6k/s) | 85.5 µs/op(~11.7k/s) |

→ **SM2 ≈ Ed25519(同量级,sign 反而更快、verify 慢 ~14%)。凭证/PKI 用 SM2 无性能顾虑**(签名是每连接/每凭证一次,非每包)——印证选型「SM2 PKI」决策,**M-G2 SM2 侧结论:非瓶颈**。

### 对称(隧道,1500B/包)

| 算法 | 吞吐 | 相对 AES-NI |
|------|------|-------------|
| AES-128-GCM(AES-NI) | 1449 MB/s ≈ **11.6 Gbps** | 1× |
| ChaCha20-Poly1305 | 947 MB/s ≈ **7.6 Gbps** | 0.65× |
| **SM4-GCM(gmsm,软件)** | 237 MB/s ≈ **1.89 Gbps** | **0.16×(慢 6.1×)** |

### 关键结论(补充 M-G1)

1. **gmsm 的 SM4 软件实现(1.89 Gbps)显著快于 OpenSSL/铜锁的 ~0.8 Gbps(同 CPU)**——因 gmsm 有 **AVX2 bitsliced SM4** 路径,这颗 Broadwell 有 AVX2 吃得到。即:**软件层"实现确实有影响"(修正 M-G1「与实现无关」的措辞——M-G1 比的 OpenSSL/铜锁都没走 AVX2-bitsliced)。**
2. **但即便 gmsm 最优软件 SM4,仍比 AES-NI 慢 6.1×、比 ChaCha20 慢 4×。** → **C-G1 结论不变**:要 SM4 达到 AES/ChaCha 量级,仍须 **GFNI/AVX-512 或专用 SM4 指令**;纯软件(含 AVX2)不够。10Gbps/PoP 的 SM4 隧道仍需国密加速 CPU。
3. **crypto-agility 已在代码坐实**:Ed25519↔SM2 切换不动契约,SM4 隧道接入点(数据面 WireGuard/TLCP)留 provider 抽象,待硬件就绪即换。

### 仍未覆盖

- 带 **GFNI/AVX-512 或 SM4-ISA** 的 CPU 上复测 SM4(确认恢复到 ~AES 量级)——仍是"国密 CPU"真正用武之处。
- TLCP 握手延迟(SM2 握手,预期非瓶颈)、铜锁-Envoy、数据面隧道真正换 SM4/TLCP(当前隧道是标准 TLS/mTLS stand-in)。
