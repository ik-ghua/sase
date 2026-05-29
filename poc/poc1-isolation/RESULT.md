# PoC-1 隔离验证 · 结果报告(Phase 1 / 1b)

> **日期:** 2026-05-25
> **环境指纹:** Ubuntu 20.04.6,内核 5.4.0-216-generic,x86_64(Intel Xeon E5-2696 v4,无 SM4);
> 在特权容器(`nicolaka/netshoot`,iproute2-6.18.0)内运行,host 未污染。
> **机制:** 每租户 server 在独立 netns(复用同一 overlay 地址 `100.64.0.10`);"共享 Envoy" = root netns 内打 `SO_MARK` 的 egress 连接,`ip rule fwmark → per-tenant table` 选路。
> **对应:** L1 3.7 方案B(SO_MARK+ip rule)、3.6 地址复用;sase-poc-plan.md I-2/I-3。
> **范围:** Phase 1 为**路由层**验证(未含真实 Envoy/TPROXY,见"未覆盖")。

---

## 结论摘要

| # | 验证点 | 结果 |
|---|--------|------|
| I-2 | 两租户复用同一地址 `100.64.0.10`,按 `SO_MARK` 消歧 | ✅ **成立**:mark=1→TENANT-A,mark=2→TENANT-B,正确消歧 |
| — | 无身份(mark=0,main 表)访问复用地址 | ✅ 不可达(main 表无该 /32 路由) |
| I-3 | `SO_MARK + ip rule` 单独是否足以隔离 | ❌ **不足**(关键发现,见下) |
| I-3-fix | 每租户表加 `unreachable default` 后是否隔离 | ✅ **成立**,且不误伤正常路径 |

---

## 关键发现(负→正)

### 发现 1:`SO_MARK + ip rule + per-tenant 表` 单独【不足以】隔离(实证)
- 现象:`mark=1`(租户 A)直连租户 B 接口 `169.254.20.2:9090` → **拿到 `TENANT-B-IFACE`**(完整够到 B 的服务)。
- 根因:**ip rule fall-through**——目标不在租户 A 的 table 101 时,`ip rule` 默认继续匹配后续规则,最终落到 **main 表**;而"共享 Envoy"所在 netns 的 main 表对各租户子网**连通可达**(`ip route get 169.254.20.2` 经 vethb 可达)→ 跨租户泄漏。
- 意义:**实证了 L1 3.7 的警告**——"SO_MARK+ip rule 只选表、不跳 namespace…隔离语义以 PoC 验证为准"。该机制只解决"复用地址消歧",**不自动提供跨租户兜底**。

### 发现 2:每租户表 `unreachable default` 可堵 fall-through(实证)
- 措施:`ip route add unreachable default table 101/102`,使表内无匹配即丢、**不 fall-through 到 main**。
- 结果:`mark=1` 再连 t-b → **OSError(网络不可达,封死)**;回归:复用地址 mark=1→A / mark=2→B 仍正确。
- 意义:**兜底不是自动的,需显式构造**——per-tenant 表必须**自包含 / 非 fall-through**(`unreachable default` 或 blackhole),或令 egress 真正绑入 per-tenant netns。

---

## 对设计的影响(待回写)

- **L1 3.7 方案B**:把"目标是 PoC 验证后由 L3/namespace 提供兜底"细化为**明确要求**:per-tenant 路由表须加 `unreachable default`(非 fall-through),否则 SO_MARK+ip rule 会经 main 表跨租户泄漏。
- **L1 3.2 数据面隔离**:同上,内核兜底需此显式构造,非"开了 per-tenant 表就隔离"。
- **PoP 单机编排 L2**:PoP 侧给租户建路由表时,必须同时下 `unreachable default`(或等价 blackhole);纳入隔离测试门禁(对接 L1 3.20)。
- 记入 L1 v0.5 回写待办(W6)。

---

## Phase 2:真实共享 Envoy 复测(2026-05-25,已完成)

环境同上;真实 `envoyproxy/envoy:v1.31`,`--network container:poc-root` 共享 netns;Envoy cluster 用 `upstream_bind_config.socket_options` 在上游打 SO_MARK(cluster_a=1 / cluster_b=2),外加错配 cluster(mark=1 却指向 t-b 接口 169.254.20.2)。

| 验证点 | 修法 ON(unreachable default) | 修法 OFF |
|---|---|---|
| `:10001` cluster_a(SO_MARK=1) | **TENANT-A** ✅ | — |
| `:10002` cluster_b(SO_MARK=2,同复用地址) | **TENANT-B** ✅(真 Envoy 正确消歧) | — |
| `:10003` 错配(mark=1→B 接口) | **空/被拦** ✅ | **TENANT-B-IFACE** ❌(跨租户泄漏复现) |

**Phase 2 结论:Phase 1 的路由层结论在真实 Envoy 下完全成立**——SO_MARK+per-tenant 表+`unreachable default` 三者齐时隔离成立(L7 配错也兜底);缺 `unreachable default` 则真 Envoy 下同样泄漏。

### 发现 3(部署级,Phase 2 新增):Envoy 打 SO_MARK 必须有 CAP_NET_ADMIN
- 现象:默认 `envoyproxy/envoy` 镜像 entrypoint 降权到 `envoy`(uid 101),即便 `--privileged --user 0`,Envoy 设 SO_MARK 仍 **EPERM(Operation not permitted)** → SO_MARK 失效 → **所有上游连接 connect_fail**(出口全挂)。
- 修法(本 PoC):`-e ENVOY_UID=0` 保持 root;**生产应给 Envoy 进程显式授予 CAP_NET_ADMIN**(ambient cap / file cap),而非全 root。
- 影响:**PoP 单机编排 L2 必须保证共享 Envoy 持 CAP_NET_ADMIN**,否则 L1 3.7 的"Envoy 上游打 SO_MARK"机制根本不生效(且是静默失败)。

## 未覆盖 / 下一步

- **TPROXY/ORIGINAL_DST 下行透明重定向**:Phase 2 验的是**上游出口隔离**(SO_MARK+表,隔离命门);下行 TPROXY 透明入流未单独验(对出口隔离结论无影响,属入流保真)。
- **I-4 namespace 规模/开销**(数千租户)未测。
- **I-5 转发性能**(TPROXY+per-tenant routing 开销)未测;且本机为 VM,perf 仅趋势。
- **VRF 路径**:本次用 SO_MARK+ip rule(L1 3.7 原文之一);VRF enslave 路径未单独验(`ip vrf exec` 在容器内 cgroup 约束疑似失效,Phase 1 初版卡住即因此——也是一条提示:VRF 方案在容器/特定环境下需额外验证)。

---

## 复现

```
poc/poc1-isolation/phase1_kernel_isolation.sh   # I-2 + 初步 I-3
poc/poc1-isolation/phase1b_fallthrough.sh        # 坐实 fall-through 漏洞 + unreachable default 修法
# 在 VM 上:docker cp 进特权 netshoot 容器(挂 /lib/modules)后 bash 执行
```

> 数据均为目标 Linux 主机(x86 VM)真实运行输出;SM4 性能(PoC-G)不在本报告,待国密 CPU。
