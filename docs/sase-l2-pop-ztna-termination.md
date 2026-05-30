# PoP 侧 ZTNA-over-packet 终结 + PEP(L2 设计,v0.1 草案)

> 状态:草案,待花刚确认 cred 绑定安全模型 + 第一刀范围后编码。薄文档:只锁「会错且难改」的安全契约与复用边界(§3/§4),实现细节(flow 表/出站后端/app 解析)随码定稿。
> 上承:真 OS Agent L2 `sase-l2-ztna-agent.md`(§3.4 数据面承载里程碑 B);MVP 路线图 `sase-mvp-roadmap.md`;[[dev-direction-mvp]]。

## 一、背景

Slice76 让真 OS Agent(`internal/agentd`)把 TUN 抓的 L3 包经 `dptunnel` 隧道(`tunhandshake.Dial` 互认证 + RFC5705 派生会话)送到 PoP,但 **PoP 侧没有「终结 Agent 隧道 + 按会话凭证 PEP 授权 + 出站到内部应用」**——ZTNA-经-Agent 到不了内部应用(端到端缺口)。现有 PoP 侧两条路径都不适用:
- `dptunnel.Router`(SD-WAN):终结隧道但只在**已登记站点 CIDR** 间 LPM 转发(出口永远是另一条隧道 re-seal),**无 ZTNA PEP**(cred 身份/组/姿态/风险)。
- `pop/ingress.go`(ZTNA HTTP `/access`,W1):有 PEP,但每请求带 `Authorization` 凭证,是 app 层 HTTP 路径,承载不了任意 L3/TCP。

## 二、目标

PoP 侧补一块独立数据面件:**终结 Agent 的 dptunnel → 解封内层包 → 按会话 principal 逐流 PEP 授权 → 出站到内部应用**,与 SD-WAN Router 平级、共享下层件、不污染其转发语义。安全:cred 验签/租户交叉核对/时效/撤销在包路径成立;隔离:跨租户严格分域。

## 三、关键决策(锁定,不随码改)

### 3.1 会话凭证与包隧道绑定(安全 crux)——**握手 hello 携带 cred**

**背景** PEP `subjectMatch`(`pop/pep/pep.go`)要 `claims.Subject/Groups/Posture/RiskLevel`;但握手只从设备证书取 `(tenant, device CN)`,**给不出 principal 全维**(groups/posture/risk 在会话凭证 `cred.Claims`,非证书)。Agent 已持 `SessionTok`(`agentd.Config.SessionTok`)。

**结论(方案①)** `clientHello` 增字段 `Cred string`(会话凭证 token)。PoP `tunhandshake.Server.handle` 在取证书身份后、`onEstablished` 前:
1. `verifier.Verify(hello.Cred, now)` → `cred.Claims`;失败/过期 → **拒绝握手(fail-closed,关连接)**。
2. **交叉核对 `claims.TenantID == 证书 Org(tenant)`** —— 不一致即拒(防 A 租户设备证书 + B 租户凭证拼接绕隔离)。**第一刀必做。**
3. 查吊销 `RevocationStore.IsRevoked(tenant, claims.JTI)` → 命中拒(入口闸)。
4. `claims` 随 `Established` 透出,终结器把 `claims`(含 JTI)连同 session/srcAddr 存入终结表项(`srcAddr → {session, claims, tenant, deadline}`)。**运行期复用此表项里握手时存的 `claims.JTI`(同一 session 内 jti 不变),不重新 Verify、不重新解析凭证**(包路径无凭证可重解析,见 §3.1 落选②)。

**安全契约(时效,必须写死)** claims 是**握手时刻快照**,隧道长连期内会过期/被撤销/姿态风险突变。故四道闸(缺一不可):
- **(入口闸)握手验 cred**:`Verify` 返 error(签名失败/过期)→ **Claims 不可信必须丢弃、拒握手**。**绝不可在 Verify 失败时仍用 Claims**——`cred.Verify` 失败返零值 Claims+error,严禁"先 Unmarshal 拿 Claims 再判 error"绕验签(包路径独有的新代码面,与 Slice75 nonce 陷阱同级写死)。
- **(主撤销路径,已建长连的权威闭合,与 HTTP 路径秒级对齐)**:`RevocationStore` 更新时(xDS 撤销下发回调)**主动遍历终结表,jti 命中即拆该 session**(关 UDP 解复用项 + 断其出站流)。HTTP 路径靠每请求重查 `IsRevoked` 使撤销下一请求生效;包路径无"每请求"检查点,故靠**撤销下发回调主动驱逐**达成同等秒级时效——**这是已建长连(不再新建流,如长驻 SSH/DB 连接)被撤销后的唯一权威闭合路径**。
- **(兜底闸)session deadline = min(cred.exp − now, 上限[上限值待确认,参照 connector `connMaxAge`])**:到期强制重握手(重新验最新 cred),**绝不无限承载过期凭证的流**;覆盖撤销 NOTIFY 到达前的窗口 + cred 自然过期。
- **(新流闸)每新流建连时再查吊销(复用表项 jti)**:拦截撤销命中后才发起的新 TCP 流。**注意:对已建、不再新建流的长连无效**——长连撤销靠上面的「主撤销路径」驱逐,故"每新流查"不单独作长连缓解(M-1 闭合)。
- **posture/risk 时效**:claims 的 posture/risk 是签发时点快照;突变即时性靠「控制面撤销旧 cred + Agent 实时通道收 reauth + 重握手带新 cred」补,**不在包路径做实时 risk 重算**(第一刀定界)。

**备选与落选**:
- **控制通道绑定 principal**(`control.Hub` 已验出 claims):落选——控制通道是 best-effort(断/丢不影响安全,权威在 PoP),把数据面**授权身份的权威来源**挂 best-effort 链路违背设计前提;且控制通道连控制面 api-server(:8082)非 PoP,PoP 拿不到其注册表,且缺「UDP 流 ↔ control 连接」的关联键。控制通道适合做撤销下推/posture 重采(已在做),不做授权身份来源。
- **每包/每流自带 cred**(类比 HTTP 每请求 Authorization):落选——Agent 发裸 L3 包,无凭证载体;塞 cred 需改 dptunnel 帧格式 + 每包验签性能灾难。
- **principal 塞设备证书**:落选——证书是 device 级长期身份,principal 是 session 级短 TTL(随 risk/posture 变);混入会使每次 risk 变就重签证书,与 cred 短 TTL 重复。证书管 device 认证、cred 管 session 授权,职责分离是现有清晰边界。

### 3.2 终结器 vs SD-WAN Router 边界——**新建独立 `internal/pop/ztnaterm`**

**结论** 不复用 `dptunnel.Router`(其语义是站点间 LPM 转发、出口是另一条隧道、无 principal/PEP;`siteEntry`/`byTenant`/LPM trie 全为站点选路建)。新建 `internal/pop/ztnaterm` 终结器,与 Router 平级:持独立 UDP 数据面端口 + 握手端口,`srcAddr → {session, claims, tenant, deadline}` 表,收包 → `session.Open` 解封 → 解 5 元组 → flow 表查/建 → 首流 PEP + 查吊销 → allow 建出站 + 桥接。

**共享的下层件(真正该复用的)**:`dptunnel.Session`(Open/Seal/AEAD/replay/FEC,零改)、`tunhandshake` 握手骨架(加**可选 `verifyCred` hook + `Established.Claims`**;**以 functional-option 或新构造 `NewServerWithCred` 加 hook,使 SD-WAN 现有 `NewServer` 调用点[cmd/pop-agent]编译/运行均零改**;SD-WAN 不设 hook → 行为不变,加测试守 SD-WAN 回归)、`verifier`/`BundleStore`/`RevocationStore`/`metrics`(`cmd/pop-agent` 单实例共享)、`pop/pep.Decide`(零改)。

**不冲突**:端口隔离(SD-WAN `SDWAN_*` vs ZTNA `ZTNA_TUNNEL_ADDR`/`ZTNA_DATA_ADDR`);解复用键各查各表;租户隔离同以「证书 tenant + cred tenant 交叉核对」为锚 + flow/session 表按 tenant 分域 + 出站目的解析只在本租户 app 集内。**nonce 复用陷阱(Slice75 H1)**:ZTNA session 同样绝不在重登记时重建归零计数器,沿用「原地保留 session」模式。

### 3.3 逐流 PEP(复用 `pop/pep`,连接级缓存)

**结论** 复用 `pep.Decide(bundle, claims, resource, "connect")` 纯函数(**零改**;它不依赖 HTTP,HTTP 只是把 `app` query 当 resource 传)。包路径:解内层 5 元组 → 解析目的为 resource(§3.4 app 解析)→ `Decide` → **按 flow key 缓存裁决**(allow/deny/inspect + 目标 + TTL),后续包命中复用不重判(PEP 查 bundle/解析 resource 贵,必须连接级缓存)。首刀:仅 TCP(SYN 作流起点);**inspect = allow**(SWG/DLP 在包路径需 TCP 重组+HTTP 解析,留后续刀;该拒的已被 PEP deny 拦下,对齐 ingress 非对称哲学);deny = 丢首包不建连。

### 3.4 出站到内部应用 + app 解析(给方向,随码定稿)

**出站后端**(第一刀范围见 §4):真正工程长杆是「内层 L3 包 → TCP 流终结」。两条路:
- **(a) 用户态 TCP 终结(gVisor netstack)→ `net.Dial` 到 app**:纯 Go 用户态栈(tailscale/wireguard-go 同款),无容器特权/内核依赖,per-flow 控制干净(accept→PEP→dial→io.Copy 双向,回程包 Seal 写回 Agent);代价=引入 gVisor 依赖(重)。
- **(b) PoP 侧 TUN + 内核 + SNAT/conntrack**:复用 `dptunnel.OpenTUN`(Slice75/76 已证 docker 可跑),PEP 在解封点(Go)对首包裁决 → allow 写入 PoP-TUN → 内核 SNAT+路由到 app → 回程经 TUN Seal 回 Agent;代价=容器 NET_ADMIN + iptables MASQUERADE/ip 规则(entrypoint 配,类比 CPE)。
- **(c) 复用 revtunnel connector**(内部 app 零暴露面):PoP 终结流 → 经已注册 connector 反向送 app。**ZTNA 卖点(私网无入站开口)**,但仍需先做包→流终结,故作**第二刀**(复用第一刀终结器,只换出站后端)。

**app 解析**(目的 dst IP:port → 内部 resource):第一刀用 PoP 侧 `appResolver` 表 `(tenant, dstCIDR, dstPort) → (appKey, upstream)`,**env/静态注入**(demo 的 `INTERNAL_CIDR` 已知);生产化经 xDS 下发(类比 `SubscribeSites`,后续刀)。不改 `resource.App` schema(给 App 加 VIP/CIDR 字段=碰 DB/migration,过重,后续刀)。

## 四、有界第一刀范围(锁定 + 后续刀清单)

**第一刀目标**:`Agent → PoP 终结 dptunnel → 解封 → 解析目的为 resource → 逐流 PEP allow/deny → (allow) 出站到内部 app`,docker 三件(agent + pop-agent + internal-app)端到端互通、deny 流被拒,**真实证明 cred 绑定 + 逐流 PEP 这两块新增的、与现有件交互最深的部分**。

**复用(零/极小改)**:cred.Verifier、pop/pep.Decide、dptunnel.Session/aead、BundleStore/RevocationStore、cmd/echo-app。
**改**:`tunhandshake`(clientHello+Cred、Established+Claims、Server 验 cred hook)、`agentd.daemon.runTunnelOnce`(Dial 携带 SessionTok)、`cmd/pop-agent`(加 `startZTNATermination` 装配,共享 verifier/bundles/revoked)。
**新建**:`internal/pop/ztnaterm`(终结器 + flow 表 + appResolver)+ docker-compose 加 agent/internal-app + seed app 注册 + policy bundle。

**出站后端**:三选一**待花刚定**(与 §3.4 对 gVisor「重」的判断一致,本节不擅自锁):
- **(a) gVisor netstack + net.Dial**:纯 Go、无容器特权、per-flow 控制干净、docker app 直达;代价=引入 gVisor 依赖(重)。**真闭合「到内部应用」端到端,最demoable。**
- **(b) PoP-TUN + 内核 + SNAT**:复用 `dptunnel.OpenTUN`(Slice75/76 已证 docker 可跑),不引 gVisor;代价=容器 NET_ADMIN + iptables MASQUERADE/ip 规则(entrypoint 配,类比 CPE)。
- **(退化)终结到 PEP + 决策可观测**:解封→解析目的→PEP allow/deny 计数+log,**出站留 1.5 刀**;先验 cred 绑定 + 逐流 PEP 这两块**新增、与现有件交互最深**的部分,gVisor/TUN 集成单独成刀降风险。**不 demoable「到 app」,但最快验最关键新架构。**

**第一刀诚实不做(后续刀)**:① inspect/SWG/DLP 在包路径(TCP 重组+HTTP 解析);② UDP/QUIC 流;③ revtunnel 零暴露面出站(§3.4c,第二刀换后端);④ PoP NAT/raw socket 出站(§3.4b);⑤ app 解析 xDS 下发 + schema 化;⑥ 运行期逐包查吊销/risk 实时重算(第一刀:握手入口验 cred+查吊销 + cred.exp 作 session deadline + 每新流查吊销);⑦ 性能(SO_REUSEPORT/零拷贝/flow 表分片锁)。

## 五、风险

- **cred 时效**:claims 握手快照,长连期内突变不自动反映 → 缓解=session deadline(cred.exp)+ 每新流查吊销 + 控制面撤销→reauth→重握手。**必须做,否则做成「验一次永久信任」。**
- **cred↔证书绑定**:必须交叉核对 `cred.TenantID == 证书 Org`,否则跨租户拼接绕隔离。第一刀必做。
- **跨租户隔离**:flow/session 表按 tenant 分域,app 解析只在本租户集内(同 Router「仅源租户内选路」)。
- **性能**:PEP/解析/查吊销逐包做会爆 CPU → 连接级缓存裁决;flow 表锁竞争(类比 Router worker pool)后续刀。
- **与 SD-WAN 复用冲突**:`tunhandshake` 加 cred hook 须可选(nil=旧行为)+ 测试守 SD-WAN 回归;不复用 Router 避免污染转发语义。
- **gVisor 依赖重**(若选 §3.4a):成熟库(tailscale 同款),clean-room 友好,但体积/复杂度大 → 若顾虑,退化为「终结到 PEP」第一刀(见 §4)。
- **nonce 复用(Slice75 H1)**:ZTNA session 绝不重建归零计数器。

## 六、结论

PoP 侧 ZTNA 终结 = **新建 `internal/pop/ztnaterm` 独立终结器**,共享 `dptunnel.Session`/`tunhandshake`(加 cred hook)/`pep`/verifier/吊销;**安全锚点 = 证书(tenant 隔离+device 认证)叠加握手携带的 cred(principal 授权),握手时交叉核对绑定 + session deadline=cred.exp + 每新流查吊销**;逐流 PEP 复用 `pep.Decide` 连接级缓存;出站第一刀 gVisor netstack+net.Dial(或退化为终结到 PEP,待定);与 SD-WAN 端口/表/租户严格隔离、共享下层、不污染 Router。第一刀做到「agent→PoP 终结→PEP→到内部 app」docker 端到端,inspect/UDP/revtunnel/NAT/xDS-app 解析/性能 留后续刀。
