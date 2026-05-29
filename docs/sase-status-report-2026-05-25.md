# SASE 项目 · 阶段性进度总览(汇报)

> **日期:** 2026-05-25
> **报告人:** 花刚 <ghua@ikuai8.com>
> **阶段:** 架构设计 + 关键技术验证(PoC)——**尚未进入产品编码**
> **用途:** 向上汇报全貌、留痕关键决策、提出资源请求。

---

## 一、一句话现状

多租户 SASE(对外 SaaS,ZTNA + SD-WAN 两轨 + SWG/FWaaS/CASB-DLP,控制面/数据面分离 + 全国 PoP)的**系统架构(L1)已成型并评审、全套组件架构(L2)已设计闭环、两项最大技术风险已用 PoC 实测**;当前卡点已收敛为**少量需外部输入/硬件的验证**,设计层面无重大未知。

---

## 二、进度全景

| 层 | 产出 | 状态 |
|----|------|------|
| **L1 系统架构** | `sase-architecture-design.md` v0.4 | 评审**有条件通过**;开放项待 PoC/数据后升 v0.5 |
| **国密选型(横切,R7)** | `sase-gm-crypto-selection.md` v0.3 | 评审通过;PoC-G 进行中 |
| **L2 控制面(6 份)** | 总览 + 数据访问/RLS + 策略编译器 + xDS + 身份IdP + 计费计量 | **交叉体检 + Q&A 评审双通过** |
| **L2 前端控制台** | `sase-l2-frontend-console.md` | 完成(reviewer 过) |
| **L2 SD-WAN CPE** | `sase-l2-sdwan-cpe.md` | 完成(加密栈待国密) |
| **L2 PoP 单机编排** | `sase-l2-pop-orchestration.md` | 完成(隔离 PoC-1 背书) |
| **L2 客户端 Agent/Connector** | `sase-l2-client-agent-connector.md` | 完成(加密栈待国密) |
| **L2 信任/风险引擎**(新增) | `sase-l2-cp-trust-risk-engine.md` | 完成——动态访问控制/持续自适应风险评估(对标行业补强) |
| **L2 ZTNA 接入硬化**(横切,新增) | `sase-l2-ztna-access-hardening.md` | 完成——SPA 单包授权(网络隐身)+ 终端实时控制通道 |
| **PoC-1 隔离验证** | `poc/poc1-isolation/` | **核心完成(实测)** |
| **PoC-G 国密性能** | `poc/pocG-gmcrypto/` | M-G1 初步完成(实测);上限待硬件 |

**ZTNA(P1)端到端链路 L2 闭环**:端 Agent → 入网 →(SPA 敲门)→ RTT 选 PoP → 隧道 → PoP 策略执行 → App Connector(应用零入站)→ 内网应用。

**设计补强(对标行业领先 ZTNA/SASE 的公开做法 + 通用零信任原则 NIST SP 800-207):** 在底座/ZTNA 链路之上补两块差异化方向——① **信任/风险引擎**(动态访问控制、持续自适应风险评估,把姿态/行为/上下文派生成风险分喂决策);② **接入硬化**(SPA 单包授权使 PoP 接入面"网络隐身"抗扫描/DDoS + 终端实时控制通道使撤销/重认证到端秒级)。均为通用零信任能力、按我们多租户/RLS/XDP 栈适配。我们的网络/SD-WAN 基因(爱快)为天然差异化强项。

---

## 三、两项关键技术风险 —— 已用 PoC 实测(不再是推测)

### 1. 多租户隔离(L1 最硬约束:跨租户 0 泄漏)—— PoC-1 已实测
在 Linux 真机上(含真实 Envoy)验证"共享 Envoy + per-tenant 路由域"的隔离,得出**两条硬性要求**:
- **per-tenant 路由表必须加 `unreachable default`** —— 否则打了租户 A 标记的连接会经主路由表**跨租户够到 B**(已复现);加上即封死、且不影响正常路径。
- **共享 Envoy 进程必须有 CAP_NET_ADMIN** —— 否则打标(SO_MARK)静默失败,**出口连接全挂**(已复现)。
> 结论:隔离方案成立,但**依赖上述两条显式构造**;已写入 PoP 单机编排 L2 并纳入隔离测试门禁。

### 2. 国密(R7,等保/金融/央国企强制)—— PoC-G M-G1 已实测
在 x86 真机上实测 SM4 数据面吞吐:
- **无 SM4 加速的 CPU 上,SM4 ≈ 0.75–0.8 Gbps/核,且与软件实现无关**(OpenSSL 与我们选的铜锁一致),**约慢当前算法 ChaCha20 14×**。
- **根因是硬件**:SM4 高吞吐依赖 **AVX-512+GFNI 或专用 SM4 指令**;无此能力的 CPU 上各实现都受限。
> 结论:**国密数据面可行,但 PoP 服务器 CPU 必须选带 SM4 加速的型号**(否则国密租户单机承载暴跌、单位经济性恶化)。这是一条**明确的硬件选型要求**。

---

## 四、决策与评审留痕(可追溯)

- 评审记录:`docs/reviews/`(L1 架构评审、国密选型评审、控制面 L2 整体 Q&A 评审)。
- 已定关键决策:客群=金融/政企/央国企/网络科技公司;国密=必须;起步全上云;ZTNA 先行;计费=席位+带宽超量;等。
- 设计规范:四要素(背景/目标/风险/结论)、无空话(每决策配依据/备选/可行方案)、不编造数据(未定标"待确认/待实测")——全程执行,每份文档过一致性体检。

---

## 五、待办与**资源请求**(需上级/业务支持)

| # | 事项 | 性质 | 请求 |
|---|------|------|------|
| 1 | **一台带 SM4 加速的 CPU**(AVX-512+GFNI 的新 Xeon/EPYC,或海光/兆芯/ARMv8.4 国密 CPU) | 硬件 | **复测 SM4 上限**(确认国密吞吐恢复到可用),并作为 PoP 选型基准 —— 这是 PoC-G 收尾与硬件选型的关键 |
| 2 | **云带宽报价**(按量 0.x 元/GB、固定 xx 元/Mbps/月) | 商务 | 复核单位经济性(带宽主导成本) |
| 3 | **首批客户区域** | 业务 | 锁定 PoP 选址与盲区 SLA |
| 4 | PoP 服务器选型(CPU/网卡)+ 10Gbps 实测 | 硬件 | 与 #1 合并,验单 PoP 吞吐(国密后按 SM4) |

**说明**:#1 的 CPU 不是 PoC 阻碍(关键结论已得出),而是**确认上限 + 部署选型**所需;它同时服务 #4。

---

## 六、下一步

1. 拿到带加速 CPU → 复测 SM4 上限(M-G1 收尾)+ 单 PoP 10Gbps 实测。
2. 取云带宽报价 + 首批客户区域 → 清 L1 开放项。
3. 上述齐备 → **L1 升 v0.5**(一次性回写国密结论、PoC-1 隔离要求、TrustBundle/CPE 入网/content_hash 等契约项,共 8 条,见 `l1-v05-writeback-backlog`)。
4. v0.5 + L2 定稿 → 评估进入**编码阶段**(搭 Go monorepo,从 P0 统一底座起)。

---

## 附录:文档索引

- **L1:** `docs/sase-architecture-design.md`
- **横切选型:** `docs/sase-gm-crypto-selection.md`、`docs/sase-poc-plan.md`
- **L2 控制面:** `docs/sase-l2-control-plane-overview.md` + `sase-l2-cp-{data-access-rls,policy-compiler,xds-server,identity-idp,billing-metering,trust-risk-engine}.md`
- **L2 边缘/前端:** `docs/sase-l2-{frontend-console,sdwan-cpe,pop-orchestration,client-agent-connector}.md`
- **L2 横切硬化:** `docs/sase-l2-ztna-access-hardening.md`(SPA + 终端实时通道)
- **PoC 实测:** `poc/poc1-isolation/RESULT.md`、`poc/pocG-gmcrypto/RESULT.md`
- **评审记录:** `docs/reviews/`

> 本报告为阶段性快照;设计/实测细节以各文档为准。
