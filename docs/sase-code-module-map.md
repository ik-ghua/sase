# SASE 代码模块映射(快速查找索引)

> **用途:** 模块/组件 → 代码路径 → 对应 L2 设计文档 → 状态。改代码/找位置先看这张表。
> **随编码更新**(新增模块/单元时回写)。布局总览见 `sase-monorepo-structure.md`。

## 控制面(`cmd/api-server` 模块化单体 + 单元②③)

| 模块/组件 | 代码路径 | 对应 L2 设计 | 状态 |
|-----------|---------|-------------|------|
| 进程引导(DI/生命周期/可选 TLS) | `internal/system/booting/` | 总览 3.5 | ✅ Slice0/8(`WithTLS` 管理面 HTTPS) |
| 数据访问层(RLS/事务 InTx·InTxRO·InPlatformTx) | `internal/data/` | 数据访问层 RLS | ✅ Slice1/32(pgx 双池 app_rw/app_ro 事务级 RLS;**Slice32 加平台跨租户只读路径 `InPlatformTx`**:可选 app_platform_ro 池、不注入 app.current_tenant、未配 fail-loud) |
| 租户 tenant | `internal/tenant/` | 总览 3.2 | ✅ Slice1/33b/33c/33d(Get/Create/**Update**[PATCH name/status/**plan/quota** 3 项]/**Decommission+Cancel**[注销宽限期软删,硬删 DEK 待 secret 模块];tenantColumns 单一来源;TODO LP-PC1 *int 不能置 null) |
| 身份 identity(IdP/凭证/令牌交换) | `internal/identity/` | 身份与 IdP | ✅ Slice1/3(User CRUD + Ed25519 会话凭证签发/TrustBundle 公钥) |
| 会话凭证机制(签发/离线验/TTL/crypto-agility) | `internal/cred/` | 身份与 IdP / 国密 R7 | ✅ Slice3/12(算法可插拔 Ed25519↔国密 SM2,`SASE_CRED_ALG`,契约不变;SM4 隧道待硬件) |
| 国密性能 PoC-G(M-G2 代码层) | `poc/pocG-gmcrypto/bench_test.go` + `RESULT.md` | 国密选型 M-G2 | ✅ Slice12(SM2≈Ed25519;SM4 软件慢 AES 6×→C-G1) |
| 策略 policy(编写 authoring / 编译 compiler) | `internal/policy/` + `internal/policy/compiler/` | 策略编译器 | ✅ Slice2(纯函数编译器+落库原子激活+幂等;authoring 子包/L34/遮蔽检测待) |
| 资源 resource(应用/连接器注册) | `internal/resource/` | 总览 3.2 / 编译器 3.3 | ✅ Slice5(apps/connectors CRUD;apps 被编译器消费校验引用) |
| 凭证撤销(秒级失效) | `internal/identity`(RevokeCredential)+ `internal/pop`(RevocationStore)+ `RevocationList` 资源 | ZTNA 硬化 3.4 / xDS 3.7 | ✅ Slice5(吊销表+NOTIFY+独立 Delta 流+PoP 查吊销;短TTL兜底) |
| 终端实时控制通道(端提速+自适应) | `internal/control/`(Hub)+ `internal/agent`(Session)+ `cmd/api-server` 托管 | ZTNA 硬化 3.4 层② | ✅ Slice6(Agent↔控制面 gRPC 双向流,撤销秒级下推+姿态上报驱动自适应撤销;明文 stand-in,权威仍 PoP) |
| 实时控制通道契约 | `api/proto/sase/control/v1/`(AgentControl gRPC) | ZTNA 硬化 3.4 | ✅ Slice6 |
| 计费 billing(计量/计费) | `internal/billing/`(待) | 计费计量 | ⬜ |
| 信任/风险 risk(动态访问控制) | `internal/risk/`(model+engine+Service,实现 `dlp.FindingSink`) | 信任/风险引擎 | 🟡 Slice22(规则/加权评分 0-100+级 low/med/high/critical+可解释 factors;信号=姿态+DLP命中;**升入 critical→自适应撤销**[滞后按 jti、事件因子 TTL 衰减];**姿态→风险→撤销已端到端**;DLP→风险跨进程上报已通(遥测管道 Slice23);**risk 进会话凭证 claim→PEP risk_gte 已通(Slice25)**;RLS持久化/Redis/CEL/阈值可配待) |
| 平台 platform(跨租户只读 + PoP 注册 + 容量/CA/RBAC 等) | `internal/platform/`(Service+PopRegistry) | 总览 3.2 / 平台控制台 L2 `sase-l2-frontend-platform-console.md` | 🟡 Slice32/35/36/**38a**(`ListTenants` + `ListDecommissionsDue` 经 `InPlatformTx` 读策展视图跨租户;`GET /platform/tenants` + `POST /platform/decommissions/sweep` 限 platform_admin;`RunDecommissionSweep` narrow 接口 Option 注入;**Slice38a `PopRegistry` 子领域接口**[CRUD 经 `InPlatformTxRW`/`InPlatformTx` 双路;**Patch 不含 name/region/endpoint 防 ID 漂移**;SQLSTATE 经 `data.IsUniqueViolation` 类型化判定]。**剩余 PoP Heartbeat / 容量看板 / 平台 RBAC / CA·KEK 双人控制 = 后续刀**) |
| Admin API 路由 | `internal/admin/httpapi/` | 总览 3.2 / 前端契约 | ✅ Slice1/2…/38a(43 端点;**Slice33 路由表 + 导出权威清单 `AdminRoutePatterns` + 启动 fail-loud assert + OpenAPI 双向对账门禁**;33b PATCH /tenants/{tid};33c /platform/tenants/{tid}/decommission[+cancel];33e /platform/admin-tokens;35 /platform/decommissions/sweep[端到端硬删];36 /tenants/{tid}/idp/configs CRUD[5 端点];37a /idp/login+/callback[公开,oidcDeps nil→503];38a /platform/pop-nodes CRUD[4 端点,popReg nil→503]) |
| 横切:authz(管理面 RBAC) | `internal/authz/` | 总览 3.2 / L1 RBAC | ✅ Slice9(admin 令牌认证 + 角色×租户作用域授权中间件) |
| 横切:csrf(管理面 CSRF 防御) | `internal/csrf/`(Double-Submit Cookie + Origin/Referer 同源校验) | Slice37c 评审 / 前端启动前置 | ✅ Slice40:GET 颁发 csrf_token cookie(非 HttpOnly JS 可读)+ 写方法校验 cookie==X-CSRF-Token + Origin 同源;authz 之前;白名单 enroll/idp/* GET/trust/pubkey;`SASE_CSRF_ALLOWED_ORIGINS` 生产严格 |
| **前端:平台运维控制台**(SPA) | `web/admin/`(React 18 + TS 5.5 strict + Vite 5 + antd v5 + React Router v6 + TanStack Query v5 + openapi-fetch + Zustand;pnpm) | 前端控制台 L2 `sase-l2-frontend-console.md` + 平台控制台 L2 `sase-l2-frontend-platform-console.md` | 🟡 Slice41/42/43/**44**:骨架 + 登录鉴权框架 + 租户列表真业务页 + **错误处理基础设施**(ApiError 统一类型 + toApiError 解析 + 401 集中登出[onResponse middleware→logout→AuthGuard 响应式跳登录,非 hard reload] + ErrorBoundary[渲染期异常→Result 500] + AppError[403/404/5xx→Result,其它→Alert] + QueryClient 全局 retry 401/403 不重试);TanStack Query + antd Table 9 列模板(status filter/Tag 色映射/quota null→"不限"/date locale + sorter);16/16 测试;**业务页待:PoP/RBAC/Audit 接 API(c/d)+ 详情 PATCH(g)+ 包体 manualChunks(e)**;**真 IdP sandbox 端到端待真 corpid/appid(f)** |
| 横切:audit(管理面操作审计) | `internal/audit/` | 总览 3.2 / 运维 3.x / 等保 / `sase-l2-audit-transactional.md` | ✅ Slice10/16/**29**:audit_log RLS append-only + 读端点;**两层审计**——DB 触发器(`migrations/0012`,source=data,业务事务内原子写,「凡变更必留痕」DB 层不变量)+ HTTP 中间件(source=api,best-effort,含失败/2xx-零变更);actor 经 per-tx GUC(`data.WithActor`+`audit.ActorMiddleware`);CI catalog 门禁防漏挂;ZTP 经 `WithAudit` 钩子留痕 |
| 平台 RBAC platformrbac(平台管理员持久化) | `internal/platformrbac/` + `platform_admins` 表(无 tenant_id;subject UNIQUE;触发器自动平台审计) | 总览 3.2 / 平台控制台 L2 | ✅ Slice38c:Admin/CreateRequest/Patch + Service(CRUD + IsActive 接入 /admin-tokens 平台路径)+ DELETE 自己/PATCH disable 自己拦防锁死 + 启动期表空告警(B4);**待:① admin 令牌撤销表(disable/delete 即时生效);② last-admin 强制保留;③ subject 保留字黑名单** |
| 横切:platformaudit(平台级操作审计) | `internal/platformaudit/` + `platform_audit_log` 表(无 tenant_id,挂触发器 `platform_audit_row`) | 总览 3.2 / `sase-l2-audit-transactional.md` / Slice38c CA·KEK 前置 | ✅ Slice39:Record/List(InPlatformTxRW 写 + InPlatformTx 读)+ 双层审计同 Slice29 模式(source=data DB 触发器原子层挂 pop_nodes + source=api handler 显式补充层覆盖失败/零变更);actor 经 InPlatformTxRW 注入 GUC 复用现有 ActorMiddleware 链;触发器 detail='id='+行 PK(挂表必有 id 列,migration 自检 fail-loud);GET /platform/audit?limit≤1000 platform_admin only;**PoP CRUD + issueAdminToken 已接入双写** |
| 横切:ratelimit(限流) | `internal/ratelimit/`(令牌桶+janitor+中间件) | 总览 3.2 / ZTP 硬化 | ✅ Slice16(按 IP 令牌桶,挂 ZTP 公开 `/enroll`+设备 `/renew` 防枚举/暴力;进程内、分布式限流属网关) |
| 设备入网 enroll(ZTP 签发/续期/撤销) | `internal/enroll/`(service+client+rotate)+ `device_enrollments` 表 + Admin `POST /enrollments`·`/devices/revoke`、公开 `POST /enroll`、mTLS `POST /renew` | L1 3.5 PKI/ZTP · 3.11 入网契约 | ✅ Slice15(激活码`<tid>.<rand>`一次性签发;**续期=当前 mTLS 证书认证+密钥轮换+撤销闸(status=revoked 拒续);CertRotator 热轮换;连接限活强制重握手使撤销有界生效**;CA 私钥 dev 落盘,生产 HSM 待;速率限制待) |
| 横切:secret | `internal/secret/` | 总览 3.2 / 数据访问层 3.8 / L1 3.5/3.16 | 🟡 Slice34/36(Provider 接口 + DevProvider[ChaCha20-Poly1305 KEK,生产严禁] + Service[Create/Get/Destroy/IsDestroyed,DB CHECK 二元销毁不变量、COALESCE 幂等];tenant.Create 同事务建 DEK[KeyCreator 解耦];audit_tr 原子审计密钥生命周期;**Slice36 加 Encrypt/Decrypt[基于 GetDEK + ChaCha20-Poly1305,nonce(12B)||ct+tag,DEK 用完 zeroize]——IdPConfig 为首个加密消费者,DEK 销毁后 Decrypt→ErrDestroyed 链路证据测试通过**。生产 KMS/HSM Provider 待 R7) |
| IdP 配置 idp(身份提供者凭证持久化) | `internal/idp/`(Config/Patch/CreateRequest 模型,**Config 不含 ClientSecret 防序列化泄漏**)+ `idp_configs` 表(RLS+FORCE+audit_tr) | 总览 3.2 / 身份 IdP L2 `sase-l2-cp-identity-idp.md` / L1 3.5 | 🟡 Slice36(CRUD + GetClientSecret 解密+ status enum 校验[与 OpenAPI 同源 active|disabled];client_secret 明文仅请求体内存短窗,服务端 Encrypt 落 encrypted_client_secret bytea NOT NULL;`secret.ErrNotFound|ErrDestroyed`→409) |
| OIDC 登录 oidc(IdP 认证→换发 SASE 凭证;**多 IdP 派发+SPA 闭环**) | `internal/oidc/`(Adapter 接口 + `DispatchFactory`[四 Kind 全覆盖+Extra AuthHost] + 四 adapter[generic/wecom/dingtalk/feishu] + `InMemoryStateStore` + LoginHandler[return_to 防 open-redirect] + CallbackHandler[Accept 分流 cookie+302/JSON] + `InvalidateForIDP`[wecom/feishu Range 清]) | 总览 3.2 / 身份 IdP L2 / L1 3.4 令牌交换 | 🟡 Slice37a+**37b-1**+**37b-2**+**37c**(标准 OIDC + 三家国产 IdP 全到位;EnsureUser 多 IdP 隔离;**SPA 登录闭环**:浏览器 text/html→Set-Cookie sase_session+302→return_to[sanitizeReturnTo 防 open-redirect+控制字符];编程客户端默认 JSON 向后兼容;**Delete IdP 联动淘汰 token cache** + AuthHost 经 Extra 可配私有化部署;**待 Slice37d:SCIM 同步、真实厂商沙箱冒烟、refresh_token**) |
| 单元② xDS server | `cmd/xds-server/` + `internal/xds/` | xDS server | ✅ Slice2/4(go-control-plane ADS/Delta + LinearCache 自定义资源 + 双向 mTLS + LISTEN/NOTIFY 增量推送;撤销独立流/对账兜底待) |
| mTLS 开发证书(CA/server/client)+ ZTP 签发 | `cmd/devpki/` + `internal/devpki/`(含 `csr.go`:GenerateCSR/SignCSR/TenantFromCert/LoadCA) | xDS server 3.9 / L1 3.5 PKI | 🟡 Slice4/7/15(自签 dev PKI;全链路 mTLS 共用;ZTP 把 tenant 编进证书 Organization、identity 进 CN;**角色编进 OU**:`SignCSR`→role:device、`SignPoP`→role:pop、`RoleFromCert`;`WritePEM` 按角色产 pop.crt/device.crt/client.crt;`LoadPoPClientTLS`/`LoadDeviceClientTLS`(共享证书已按角色拆分:PoP↔pop、边缘↔device);生产 PoP CA+HSM 待) |
| 可观测指标(单元③ 起步) | `internal/metrics/`(Recorder 数据面 + ControlRecorder 控制面)+ PoP/xds-server `/metrics` | 运维/部署 3.4/3.10 / L1 3.14 | 🟡 Slice13(数据面接入面决策+上游耗时直方图;控制面 xDS 下发计数;Tracing/CH/采样/告警待) |
| 单元③ 遥测管道(事件上报起步) | `internal/telemetry/`(Event/Sink + Ingest gRPC + 异步 Reporter)+ `api/proto/sase/telemetry/v1` | 运维/部署 3.4 / 风险引擎信号源 | 🟡 Slice23(PoP→控制面事件上报:DLP 命中跨进程喂风险引擎闭环;Reporter 异步缓冲满即丢、Ingest 派发 Sink、同控制 gRPC mTLS;**指标/Tracing/ClickHouse 待;**W11 角色门控已实现**:Ingest 取对端 mTLS 证书角色、`SASE_TELEMETRY_REQUIRE_POP_ROLE` 开则非 PoP 拒(`devpki` 角色证书);生产开门控+PoP 持 role:pop 证书) |
| 下发资源契约(L7PolicyBundle 等) | `api/xdsv1/`(Go 结构体,临时单一来源) | xDS server 3.1 / 编译器 3.9 | 🟡 Slice2(待 protoc 落 api/proto) |

## 数据面 / 边缘(后续 slice;加密栈待国密 PoC-G)

| 组件 | 代码路径 | 对应 L2 | 状态 |
|------|---------|---------|------|
| PoP 本机编排(PoP-agent) | `cmd/pop-agent/` + `internal/pop/`(+`pep/`) | PoP 单机编排 | 🟡 Slice2/3(xDS 订阅→BundleStore + 接入面验凭证+PEP裁决+反向转发;eBPF/Envoy/SPA 待) |
| PEP(策略执行点) | `internal/pop/pep/` | 策略编译器 3.5 / PoP | ✅ Slice3/25(纯函数:默认拒绝+优先级首次匹配+subject 选择器 user/group/posture/**risk_gte**,有界查表;**risk_gte 按凭证 risk_level 阈值比较→动态访问控制阶梯**) |
| App Connector 反向通道 | `cmd/connector/` + `internal/revtunnel/` | 客户端 Agent/Connector | 🟡 Slice3/15(出站反向+代理上游;**W9:注册校验 Hello.Tenant⊆mTLS 证书租户,`WithRequireCertTenant` 生产 fail-closed**;`cmd/connector` 设 `ZTP_CODE` 即走 ZTP 取证书;多路复用待) |
| 设备入网客户端(ZTP) | `internal/enroll/client.go`(FetchCert/DeviceTLS) | L1 3.5/3.11 | ✅ Slice15(设备本地 CSR→取租户绑定证书;cmd/connector·cmd/cpe 经 `ZTP_CODE` 接入) |
| 客户端 Agent | `cmd/agent/` + `internal/agent/` | 客户端 Agent/Connector | 🟡 Slice3(携凭证访问接入面;enroll/姿态/选路/隧道待) |
| 目标应用(端到端用) | `cmd/echo-app/` + `internal/echo/` | — | ✅ Slice3(测试用 echo) |
| SD-WAN 站点(服务端) | `internal/site/` + `SiteConfig` xDS 资源 + PoP `SiteIngress` | SD-WAN CPE 3.8 | 🟡 Slice14(站点注册+xDS下发+PoP overlay 入口,复用底座) |
| SD-WAN CPE(客户边缘) | `cmd/cpe/` + `internal/cpe/`(SiteStore/SendToSite + revtunnel 终结) | SD-WAN CPE | 🟡 Slice14/15/17(薄桩;`ZTP_CODE` 走 ZTP 取证书;**`WAN_LINKS` 启用多链路:linkmon 健康探测+优先级选路+活动链路失效亚秒切换+滞后回切**;隧道国密/FEC 待) |
| SD-WAN WAN 多链路选路 | `internal/linkmon/`(Monitor 探测/评分/Best + TCPProber) | SD-WAN CPE WAN/选路 | ✅ Slice17(探测器可注入纯逻辑;RTT EWMA+滑窗丢包率,优先级选路) |
| SD-WAN 数据面隧道 | `internal/dptunnel/`(AEAD provider + 帧 + 重放 + XOR-FEC + Session + Endpoint + Router + TUN) | 数据面隧道 L2 | ✅ Slice18/19/30(协议核心:ChaCha20↔SM4-GCM 可插拔、密文数据报、计数器重放、XOR-FEC,aad 认证帧头/rekey fail-closed/FEC 有界;集成:PacketIO+CPE Endpoint+PoP Router 租户内 LPM 选路+Linux TUN,e2e+跨租户隔离+`-race` 净;**Slice30 经 tunhandshake 真握手密钥接进 cmd/pop-agent+cmd/cpe**。基准 ChaCha20 4.9 / SM4 软件 1.66 Gbps/核@PoC VM,带加速待国密 CPU) |
| SD-WAN 隧道握手 | `internal/tunhandshake/`(Server/Dial + RFC5705 密钥导出) | 握手 L2 `sase-l2-tunnel-handshake.md` + 密码学审查包 `sase-tunnel-handshake-crypto-review.md` | 🟡 Slice30/31(形态 A 非国密档:互认证 mutual TLS1.3 + RFC5705 exporter 派生 dptunnel 密钥;证书身份[tenant=Org/site=CN]绑定登记 Router;防降级;接进 pop-agent/cpe;e2e+`-race` 净。**Slice31 把待解锁四项[国密档 TLCP 导出/tx-rx 双密钥/NAT receiver-index/rekey-epoch]打包送外部密码学审查;编码阻塞于审查结论,关键发现:国密档须强制 ECDHE-SM2 保 FS**) |

## 契约 / 迁移 / 部署

| 项 | 路径 | 对应 L2 |
|----|------|---------|
| xDS 自定义资源 proto(PolicyBundleResource) | `api/proto/sase/xds/v1/`(protoc 生成,`scripts/protoc-gen.sh`) | xDS server 3.1 / 总览 3.6 | ✅ Slice4 |
| 下发 payload 契约(PolicyBundle/L7Rule) | `api/xdsv1/`(Go 结构体,JSON payload) | 编译器 3.4/3.9 | ✅ Slice2 |
| Admin REST OpenAPI | `api/openapi/admin.yaml` | 前端控制台 / 总览 3.6 | ✅ Slice33(手写 OpenAPI 3.1 权威契约,27 路径;CI 双向对账门禁 `openapi_conformance_test.go` 防 spec↔实现漂移;前端从它生成 TS) |
| schema 迁移(含 RLS catalog 门禁) | `migrations/`:`0001_init`…`0006_sdwan_sites`、`0007-0009`(ZTP)、`0010_fw_rules`、`0011_dlp_rules`、`0012_audit_triggers`、`0013_platform_readpath`、`0014_tenant_decommission`、`0015_tenant_quota`、`0016_tenant_keys`、**`0017_idp_configs`**(Slice36:RLS+FORCE+audit_tr+encrypted_client_secret bytea NOT NULL)、**`0018_users_external_id_unique`**(Slice37a:UNIQUE(tenant_id, external_id))、**`0019_pop_nodes_and_platform_rw`**(Slice38a:`app_platform_rw` 角色 NOBYPASSRLS + `pop_nodes` 无 RLS 平台全局表 + 角色 BYPASSRLS 自检 fail-loud)、**`0020_users_idp_id`**(Slice37b-1:users.idp_id + UNIQUE NULLS NOT DISTINCT 三元组 + PG≥15 自检)、**`0021_platform_audit_log`**(Slice39:平台审计表无 tenant_id + 通用触发器 platform_audit_row 挂 pop_nodes + 挂表 id 列自检 fail-loud)、**`0022_platform_admins`**(Slice38c:平台管理员持久化 RBAC,挂 platform_audit_tr 自动审计) | 数据访问层 RLS 3.7 |
| IaC / systemd | `deploy/`(待) | 运维/部署 |

## 横切安全/硬化(设计已就绪,落到上述组件)

| 能力 | 落点代码 | 对应 L2 |
|------|---------|---------|
| SPA 单包授权 | `internal/pop/`(XDP 白名单)+ `internal/agent`/`cpe`(敲门) | ZTNA 接入硬化 |
| 终端实时控制通道 | `internal/agent/` + 控制面 push | ZTNA 接入硬化 |
| 安全能力 SWG(P2) | `internal/swg/`(引擎+服务)+ `SWGRuleSet` xDS 资源 + PoP `SWGStore` + ingress inspect 钩子 | 安全栈 | ✅ Slice11(rule-based URL 过滤,复用下发管线挂 inspect) |
| 安全能力 FWaaS(P4,L3/L4) | `internal/fw/`(模型+纯函数引擎+authoring)+ `FWRuleSet` xDS(第5类独立流)+ PoP `FWStore`(桥接 dptunnel.Firewall)+ dptunnel Router 转发前裁决 | 安全栈 | ✅ Slice20(每租户分段:默认拒+优先级首次匹配,复用 authoring→xDS→PoP 管线挂 Router;eBPF 下沉/L7 防火墙[复用 Envoy/SWG L7]待;**✅ Slice30 执行点已接 pop-agent(dptunnel Router 进 cmd + SubscribeFW),FWaaS L3/L4 真数据面裁决生效**) |
| 安全能力 CASB-DLP(P5) | `internal/dlp/`(规则模型+纯函数引擎+authoring+FindingSink)+ `DLPRuleSet` xDS(第6类独立流)+ PoP `DLPStore`+`LogFindingSink` + ingress inspect 钩子 | 安全栈 | ✅ Slice21(关键词/正则检测,block 拒+alert 告警,命中喂 FindingSink[风险引擎接口];复用 authoring→xDS→PoP 挂 inspect。**内容源 stand-in 扫 path[无 body],ext_proc body/指纹/ML 待;风险引擎 internal/risk 未编码用 LogSink 兜底**) |
| 国密加密栈 | crypto provider 抽象(隧道/TLS/凭证签名)| 国密选型(待 PoC-G)|

> 图例:✅ 已码并验证 · 🟡 接口/桩 · ⬜ 待开发。状态随 slice 推进更新。
