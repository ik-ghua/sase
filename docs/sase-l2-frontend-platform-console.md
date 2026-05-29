# 平台运维控制台 L2(功能深化 + 后端契约)

> **状态:** L2 组件设计 / 待评审(功能深化;不写代码)
> **版本:** v0.1
> **日期:** 2026-05-27
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **层级与上承:** 前端控制台 L2 `sase-l2-frontend-console.md` 的 `app-admin`(平台运维)入口的**功能深化**。上承 L1 `sase-architecture-design.md` v0.6 的 **3.18(平台/租户双控制台、平台访租户须理由记录+审计、CA/KEK 双人控制)、3.16(租户生命周期、密钥销毁式删除)、3.5(PKI/CA/KEK、HSM、双人控制)、3.13(PoP 部署/选址/灰度)、3.14(可观测/SLO)**;消费控制面 L2 总览的 `platform`/`tenant`/`admin` 模块 + `data` 横切层。
>
> **为什么先做平台控制台(花刚 2026-05-27 拍板):** 它是爱快**自己**运营 SaaS 的必备工具(开租户、看 PoP、排障、管 CA);ZTNA/安全能力后端已成体系,缺的是运营面。
>
> **范围:** 平台控制台**逐功能域**的功能点、UI/交互、**所需后端 API 契约(多为新建)**、数据来源、RBAC 与敏感操作处理;头号架构前提(跨租户数据路径);后端 API 缺口汇总(可执行清单)。
>
> **不含:** 写前端/后端代码(设计先行,须另行授权);租户控制台(另文);可观测监控 UI 本体(复用 Grafana,见 3.2);UX 视觉稿;库级选型(前端 L2 3.8)。
>
> **诚实声明:** 平台控制台**几乎全部功能 today 缺后端端点**(仅 `tenant` create/get 存在)。本文把每功能所需后端契约显式列出(§五汇总),使"做平台控制台"=「补后端 API + 前端页面」两件事可分别排期。**最大前提是跨租户数据路径(§3.1),不解决则平台控制台无法看全租户。**

---

## 一、背景

前端 L2 列了平台控制台模块(PoP/容量、租户管理、安全运营、跨租户支持、平台 RBAC/CA 管理),但**功能点、交互、后端契约未深化**。而平台控制台与租户控制台的根本差异是:**它要跨租户**(看全平台租户、PoP、安全事件),而本系统的隔离基石是 RLS——`app_rw`/`app_ro` 均 **NOBYPASSRLS**,且 `tenants` 表自身 RLS(`id = current_setting('app.current_tenant')`)→ **应用连全租户列表都枚举不出来**(Slice28 撤销表 GC 已撞到此约束:跨租户清扫交 DB 维护作业)。

故平台控制台不是"租户控制台去掉租户过滤"——它需要一条**受控的跨租户数据路径**(§3.1),这是头号设计前提。其余功能域(§3.3)在此前提上展开。

---

## 二、目标 / 非目标

### 2.1 目标
1. 定平台控制台**各功能域的功能点 + 交互**(运营动作为主,非监控看板)。
2. 为每功能定**所需后端 API 契约**(方法/路径/数据/鉴权),标现状(✅ 有 / ⚠️ 新建)。
3. 定**跨租户数据路径**(平台如何受控访问全租户/指定租户数据,不破 RLS 隔离哲学)。
4. 定**敏感操作处理**:平台访租户的理由记录+审计(L1 3.18)、CA/KEK 双人控制(L1 3.5)。
5. 产出**后端 API 缺口汇总**(可执行清单,供后端排期)。

### 2.2 非目标
- 写代码/脚手架;UX 稿;库选型(前端 L2)。
- 监控/指标看板 UI 本体(复用 Grafana,§3.2,不自研重造)。
- 租户控制台(另文);SecOps 完整能力(L2 SS6 后置,本文只占位)。

---

## 三、设计

### 3.1 头号架构前提:跨租户数据路径

**背景** 平台控制台要看全租户(租户列表/某租户详情/跨租户安全事件);但 `app_rw`/`app_ro` 受 RLS,枚举不出全租户。

**目标** 给平台一条受控跨租户读路径,**不削弱租户隔离哲学**(misuse-resistant、可审计)。

**设计 —— 承接数据访问层 L2 既有 `InPlatformTx`,不另立平行机制**

数据访问层 L2(`sase-l2-cp-data-access-rls.md` §3.6)**已定平台访问路径**:`data` 层单独入口 **`InPlatformTx`**(用平台角色、**不注入 `app.current_tenant`**、权限由 `authz` 平台 RBAC 控制而非 RLS);平台级表 = **不含 `tenant_id`** 的表(如 `PoP`);"平台入口**不能读租户表,除非显式**"(隔离测试类 5)。本文据此细化,**不发明新机制**:
- **跨租户只读聚合**(租户列表/状态/用量概览/PoP 注册):经既有 `InPlatformTx`,由其**承载角色 `app_platform_ro`**(平台只读)执行。
  - PoP 等**无 `tenant_id` 的平台表**:天然在平台入口可读(数据访问层 L2 已涵盖)。
  - **租户表的跨租户聚合**(如租户列表)属"**除非显式**"口子:**定义只读平台视图**(如 `tenant_summary`:租户名/状态/配额/用量数,**不含**用户明细/策略内容),`app_platform_ro` 仅授该视图 SELECT。**该视图须纳入数据访问层 L2 的平台表白名单(CI 断言 G3)+ 隔离测试类 5**——否则新视图绕过既有「0 泄漏」门禁未被覆盖(衔接要求,见风险)。
- 控制面新增 **`platform` 模块**(总览第 1 平台级模块,此前未编码):经 `InPlatformTx`/`app_platform_ro` 提供上述只读聚合;**写操作(开租户/改配额/注销)仍走业务 data 路径**(`InTx(ctx, 目标租户)`,在该租户 RLS 上下文内,平台身份经 authz)。
- **平台访"单个租户明细"**(排障)→ **不绕 RLS**,而是**平台身份 + 指定 tenant_id 进入该租户 RLS 上下文**(`InTx(ctx, targetTenant)`)+ **强制理由**(§3.4)+ 审计。即"以平台身份合法进入该租户上下文",非"绕过"。

**依据:** 隔离哲学 misuse-resistant(RLS 不可绕过)。平台跨租户能力 = **显式、最小、可审计**——承接既有 `InPlatformTx`,跨租户读收敛到「无 tenant_id 平台表」+「白名单平台视图」,跨租户写/明细走「进目标租户 RLS 上下文 + 理由」。**绝不给业务角色(`app_rw`/`app_ro`)开 BYPASSRLS**。
- 备选:给 `app_rw` BYPASSRLS。落选:业务路径一旦 BYPASSRLS,RLS 兜底全失,任何 SQL 疏漏即跨租户泄漏——违 L1 3.2 / CI 断言 G2。
- `app_platform_ro` **用最小授权视图、不走 BYPASSRLS(LP-PC6 已定)**:仅授平台视图(及无 tenant_id 平台表)SELECT;**CI 断言 G2「角色无 BYPASSRLS」不松动**(含 `app_platform_ro`)。即跨租户读靠"白名单视图授权"而非"绕过 RLS"。

**风险** ① 平台视图泄露租户敏感数据 → 视图只放运营必需聚合(非用户/策略明细)+ 最小授权 + 审计;**② 新平台视图须同步进数据访问层 L2 的平台表白名单(G3)+ 隔离测试类 5**,否则脱离既有 0 泄漏门禁(衔接硬要求)。**待确认:** 平台视图清单与字段(LP-PC1)。

**结论** 跨租户读 = **承接既有 `InPlatformTx`**(`app_platform_ro` + 无 tenant_id 平台表 + 白名单平台视图,且视图入 CI G3/隔离测试);跨租户写/明细 = 平台身份进目标租户 RLS 上下文 + 理由 + 审计;**不给业务角色 BYPASSRLS**。这是平台控制台所有跨租户功能的前置。

> **✅ as-built(Slice32):** 本节地基已编码——`migrations/0013`(`app_platform_ro` NOBYPASSRLS + 策展视图 `tenant_summary` + owner 绕 RLS 自检防沉默失败)、`data.InPlatformTx`(平台只读、不注入 current_tenant)、`internal/platform.ListTenants`、`GET /platform/tenants`(限 platform_admin)。e2e 验:跨租户读到多租户 / 角色 NOBYPASSRLS / 直读基表 permission denied / 业务路径 RLS 仍 0 泄漏。**✅ 平台视图已入 RLS catalog 门禁:`internal/data/rls_catalog_gate_test.go`(G3 断言 tenant_summary 在平台白名单 + owner 绕 RLS;G2 断言 app_platform_ro NOBYPASSRLS)+ 平台路径隔离行为(G4)已测——衔接既有 0 泄漏门禁完成。**

### 3.2 可观测看板:内部运维监控复用自托管 Grafana(对客看板自研)

**背景** 平台要看 PoP 健康/容量/SLO/xDS 滞后等指标;这些已由 metrics(Prometheus,Slice13)+ 运维 L2(VictoriaMetrics/ClickHouse)产出。

**设计(LP-PC2 已定,花刚 2026-05-27):**
- **平台控制台(爱快内部运维自用)的指标/日志看板 = 自托管 Grafana**(对接 VM/CH),平台控制台不自研监控图表;聚焦**运营动作**(开租户/管 PoP/管 CA/排障)与**运营态对象**(租户/PoP 注册表)。
- **Grafana 是自托管开源组件**(部署在我方基础设施、**指标数据不出域**),与 Envoy/Postgres/Prometheus/React 同属第三方开源依赖,**同一套供应链治理**(自托管 + 钉版本 + 扫 CVE + 网络隔离到管理网);**非外部 SaaS、不把数据交给第三方**。
- **平台控制台是内部工具,客户不可见** → 内嵌第三方组件无品牌/合规观感顾虑。
- **接入:起步外链 → 目标内嵌(iframe + SSO)**;内嵌+SSO 作体验升级后置,不卡 MVP;内嵌需处理 SSO(OAuth/反代认证)+ iframe 安全(CSP/防点击劫持)。
- **边界(重要):对客的租户控制台用量看板 ≠ Grafana**——那是客户可见的产品界面,**自研轻量看板、数据走我方 billing/metrics API、不内嵌任何第三方**(可控 + 品牌一致 + 合规观感,见前端 L2 3.6 用量看板)。即"**对内省事(Grafana 自托管)、对客自研(不嵌第三方)**"。

**依据:** 监控可视化是成熟领域(Grafana),自研重造时序/告警/PromQL UI 是巨大浪费、长期劣于 Grafana,且**非我方差异化价值**(价值在 SASE 安全/网络);自研监控 UI 反而**增大攻击面**(自写代码 bug 多于全球审计多年的成熟项目),不增安全。安全 = 供应链可控(自托管/隔离),非"全自研"——否则比 Grafana 关键得多的 Envoy/Postgres 都不能用。
- 备选:平台内部监控也全自研。落选:重造 Grafana,数月投入 + 长期维护 + 体验短期不及,且反增攻击面;内部工具客户不可见,自研收益不匹配成本。
- 备选:给 `app_rw` 直连/superuser 看全量。落选:见 §3.1(隔离基石)。

**结论** 平台**内部**运维监控 = 自托管 Grafana(开源、数据不出域、同栈治理、客户不可见;起步外链→目标内嵌 SSO);平台控制台本体 = 运营动作 + 运营对象;**对客用量看板自研、不嵌第三方**(租户控制台,前端 L2 3.6)。

### 3.3 功能域(逐个:功能点 / UI / 后端契约 / RBAC)

> 契约现状标记:✅ 已有端点 / ⚠️ 新建端点。所有写操作经 `admin` authz + 审计(Slice29 两层)。

#### 3.3.1 租户管理(平台视角)
- **功能点:** 全租户列表(状态/档/用量概览)、开通新租户、改配额(`Quota`)、改加密档(国密/非国密 crypto profile)、停用/恢复、**注销**。
  - **注销走宽限期(LP-PC5 已定):软删(标记注销、停服务、保留 DEK)→ 宽限期(可恢复,时长待定)→ 硬删(销毁 DEK,L1 3.16 密钥销毁式删除,此刻起不可逆)**。前端二次确认 + 全程审计;宽限期内可"撤销注销"。非立即不可逆——给误操作/客户挽留留窗口。
- **UI:** 租户列表(跨租户)→ 租户详情(概览 + 配额 + 档 + 生命周期动作);注销走危险操作确认 + 审计。
- **后端契约:**
  - ⚠️ `GET /api/v1/platform/tenants`(跨租户列表,经 §3.1 platform 视图)
  - ✅ `GET /api/v1/tenants/{tid}`(详情,已有)/ ✅ `POST /api/v1/tenants`(开通,已有)
  - ⚠️ `PATCH /api/v1/tenants/{tid}`(配额/状态/档)
  - ⚠️ `POST /api/v1/tenants/{tid}/decommission`(注销+DEK 销毁,L1 3.16;**最敏感、宜双人或强确认**)
- **RBAC:** platform_admin(全权)/ 运维(开通/配额)/ 只读支持(只读)。

#### 3.3.2 PoP / 容量 / 选址
- **功能点:** PoP 注册表(节点/区域/状态/版本)、容量态(每 PoP 隧道数/吞吐/近上限,**来自 metrics**)、选址数据(客户端 RTT 分布 → 建议)、PoP 上线/下线/**drain(灰度,运维 L2 不断流)**。
- **UI:** PoP 列表 + 详情(容量来自 Grafana 内嵌)+ 灰度/drain 动作。
- **后端契约:**
  - ⚠️ `GET /api/v1/platform/pops`(PoP 注册表;数据来自 xds-server 已知连接的 PoP + 注册元数据)
  - ⚠️ `POST /api/v1/platform/pops/{id}/drain`(发起 drain,对接运维 L2 灰度)
  - 容量/健康指标:Grafana(§3.2),非本控制台 API。
- **RBAC:** platform_admin / 运维;drain 属运维动作 + 审计。
- **依据/缺口:** `platform` 模块 + PoP 注册表是新建;PoP 健康源是 metrics + xDS 连接态,需 platform 模块聚合。

#### 3.3.3 跨租户支持(代客排障)
- **功能点:** 运维/支持带**理由**进某租户,只读查其策略/审计/会话/站点状态帮排障;**全程审计**(谁/何时/为何/看了什么租户)。
- **UI:** "进入租户支持模式"入口 → **强制填理由** → 进入该租户的只读视图(复用租户控制台只读组件)→ 退出。顶部常驻"支持模式 · 租户 X · 理由 Y"横幅。
- **后端契约:**
  - ⚠️ 平台身份带 `X-Support-Reason` 头访问 `/api/v1/tenants/{tid}/...`(经 §3.1 平台进目标租户 RLS 上下文);authz 校验平台角色 + **理由必填**;Slice29 审计记 actor=平台运维 + 理由 + target 租户。
- **RBAC:** 运维/只读支持;**默认只读**(排障不改租户数据;改需更高权限 + 单独审计)。
- **依据:** L1 3.18「平台访租户须理由记录」——理由在 API 层强制(空理由拒),审计落库。

#### 3.3.4 平台 RBAC / admin 令牌
- **功能点:** 管理平台账号与角色、签发/吊销 admin 令牌、查看首个 platform_admin 引导态(Slice28 bootstrap)。
- **后端契约:**
  - ⚠️ `POST /api/v1/platform/admin-tokens`(签发 admin 令牌,后端已有 `IssueAdminToken`,缺端点;**签发本身是敏感操作**,审计 + 限 platform_admin)
  - ⚠️ `GET/POST /api/v1/platform/principals`(平台/租户管理员账号与角色)
- **RBAC:** platform_admin only;令牌签发审计。
- **注:** admin/会话令牌当前共用签发器靠 Role 区分(CLAUDE.md stand-in),生产宜分 audience——平台令牌签发端点应推动此分离。

#### 3.3.5 CA / KEK 管理(最敏感,双人控制)
- **功能点:** 查 CA 层级 + 证书签发/撤销记录;**中间 CA 轮换**、**应急吊销**、**KEK 轮换/恢复**——均 **双人控制(propose → 第二人 approve → execute)**,L1 3.5。
- **UI:** CA 概览(只读)+ 敏感动作走**审批流**:发起人提交(带理由)→ 待第二 CA 管理员审批 → 批准后执行 → 全程审计。控制台只呈现**流程状态**,不"一键执行"敏感操作。
- **后端契约:**
  - ⚠️ `GET /api/v1/platform/ca`(CA 层级/证书记录,只读)
  - ⚠️ `POST /api/v1/platform/ca/operations`(发起敏感操作:轮换/吊销/KEK,状态=pending-approval)
  - ⚠️ `POST /api/v1/platform/ca/operations/{id}/approve`(第二人批准 → 执行;**发起人≠批准人**强制)
  - 实际 CA/KEK 操作对接 `devpki`/HSM(生产 KEK 入 HSM,L1 3.5)。
- **RBAC:** 仅 CA 管理员;**双人控制是后端状态机强制**(前端只呈现),发起人与批准人必须不同主体。
- **依据:** L1 3.5「敏感操作双人控制」——前端不能是安全边界(前端 L2 RF1),双人控制在后端流程强制。**待确认:** 双人控制状态机与审批超时(LP-PC3)。

#### 3.3.6 安全运营 SecOps(占位,后置)
- **功能点(后续):** 跨租户安全事件聚合(DLP 命中/风险升级/撤销事件)、威胁情报 feed 管理、SWG 分类库。
- **现状:** risk/telemetry 数据在内存/日志,无聚合查询;L2 列为 SS6 后续。**本文仅占位**,待 SecOps 子 L2 + risk 持久化(ClickHouse,运维 L2)就位再深化。

### 3.4 敏感操作横切(贯穿 3.3)
- **平台访租户:理由必填 + 审计**(3.3.3):API 层强制非空理由,Slice29 审计记 actor/target/reason。
- **双人控制**(3.3.5 CA/KEK、可选 3.3.1 注销):后端审批状态机,发起≠批准,全审计;前端仅呈现流程。
- **危险操作确认**:注销租户(DEK 销毁不可逆)、应急吊销——前端二次确认 + 后端审计;不可逆操作前端明确警示。
- **全审计**:平台侧所有写操作经 Slice29 两层审计(source=api 记动作 + 触发器记数据变更),actor=平台主体。

---

## 四、风险

- **RF-PC1 跨租户路径成隐患**:platform 视图/角色设计不当 → 跨租户泄漏。缓解:最小授权视图(§3.1)、不给业务角色 BYPASSRLS、平台路径独立审计。**最高风险项**。
- **RF-PC2 把前端当安全边界**(继承前端 L2 RF1):双人控制/理由记录/越权防护**全后端强制**,前端只呈现。
- **RF-PC3 平台控制台被攻陷=全平台**:平台控制台权限大,故**强认证须 MFA(LP-PC4 已定)** + 强审计;网络隔离(内部网/堡垒)作纵深叠加(待运维 L2)。
- **RF-PC4 监控自研浪费**:已由 §3.2 复用 Grafana 规避。
- **RF-PC5 注销不可逆误操作**:DEK 销毁式删除不可逆 → 二次确认 + 宜双人 + 宽限期(软删→宽限→硬删)?**待确认:** 注销宽限期(LP-PC5)。

---

## 五、后端 API 缺口汇总(可执行清单,供后端排期)

平台控制台依赖的后端端点,**几乎全部新建**。按优先级(P0=平台控制台 MVP 前置):

| # | 端点 | 现状 | 优先级 | 依赖 |
|---|------|------|--------|------|
| PC-API-0 | **跨租户数据路径**:`app_platform_ro` 角色 + 平台视图 + `platform` 控制面模块 | ✅ **已编码(Slice32)**:`migrations/0013`(角色 NOBYPASSRLS + `tenant_summary` 视图 + owner 绕 RLS 自检)+ `data.InPlatformTx` + `internal/platform` | P0(头号前置,**已完成**) | §3.1 |
| PC-API-1 | `GET /platform/tenants`(跨租户列表) | ✅ **已编码(Slice32)**:authz 限 platform_admin;e2e 跨租户读+RLS 隔离不破 | P0(**已完成**) | PC-API-0 |
| PC-API-2a | `PATCH /tenants/{tid}`(状态/改名/改档/改配额) | ✅ **已编码(Slice33b+33d)**:name+status(Slice33b)+ plan(Slice33d,DB 已有列、暴露 PATCH)+ 3 项 quota(max_users/policies/bandwidth_mbps,*int,nil=不限/0=完全限死,DB CHECK ≥0);`tenant.Update` 经业务 InTx + authz 收紧(租户本身的写仅 platform_admin)+ tenantColumns 单一来源。**TODO(LP-PC1):*int 不能"置回 null/不限",待 clear-flag/sentinel 扩展** | P0(**已完成**) | 租户生命周期 3.16 |
| PC-API-2b | `POST /platform/tenants/{tid}/decommission`(+`/cancel`)注销宽限期 + `POST /platform/decommissions/sweep` 硬删清扫 | ✅ **已编码端到端(Slice33c+34+35)**:软删 Slice33c(status→offboarding + decommission_at=now+grace,默认 30 天≤365 天);硬删 Slice34/35(secret DEK 销毁+状态→decommissioned;手动 sweep 端点)。各自原子幂等→重跑安全。审计经触发器(密钥+状态变更)。**⚠️ DEK 销毁当前为符号性**(Slice34 无业务数据用 DEK 加密);**周期自动 sweep**(cron 包裹) + **首个加密消费者**=后续刀 | P1(**端到端已完成**) | 3.16 / LP-PC5 |
| PC-API-3 | `GET /platform/pops`、`POST /platform/pops/{id}/drain` | ⚠️ 新建 | P1 | platform 模块 + metrics |
| PC-API-4 | 平台访租户带 `X-Support-Reason` + 审计 | ⚠️ 新建 | P1 | §3.1 + Slice29 审计 |
| PC-API-5 | `POST /platform/admin-tokens`(本刀 role ∈ {tenant_admin, auditor});`GET/POST /platform/principals` 后续 | 🟡 **部分已编码(Slice33e)**:平台签发 tenant 作用域 admin 令牌(临时机制,IdP-based 登录到位前;≤12h TTL);显式审计落 target tenant、`sanitizeDetail` 不含 token;platform_admin 自签发不支持(避平台级审计缺口)。**待后续**:真 IdP 登录、tenant_id 存在性校验、令牌主动撤销、principal 账号持久化 | P1(令牌签发**已完成**;principal 持久化后续) | LP-PC7 |
| PC-API-6 | CA/KEK 双人控制审批流(propose/approve/execute) | ⚠️ 新建 | P2 | devpki/HSM + 状态机 |
| PC-API-7 | **OpenAPI 规格产出**(L1 3.11 单一来源,前端生成类型靠它) | ✅ **已编码(Slice33)**:手写 `api/openapi/admin.yaml`(27 路径)+ `AdminRoutePatterns` 权威清单 + CI 双向对账门禁(`openapi_conformance_test.go`);前端从 spec 生成 TS | P0(前端前置,**已完成**) | 前端 L2 3.3 |
| PC-API-8 | SecOps 聚合查询 | ⚠️ 新建 | P3(后置) | risk 持久化 + SecOps 子 L2 |

> **结论性观察:** 平台控制台的**真实第一刀不是前端,是后端 PC-API-0(跨租户数据路径)+ PC-API-7(OpenAPI 规格)**——这两个是一切平台前端功能的地基。**✅ 二者均已编码(Slice32/33)**:跨租户读路径 + OpenAPI 权威契约 + CI 防漂移就位 → 前端现已有可消费的契约,可起步(前端编码须另行授权)。剩余为更多平台端点(PC-API-2~6)与前端页面本身。

---

## 六、结论

平台运维控制台 = 爱快内部运营 SaaS 的工具,**与租户控制台的根本差异是跨租户**。本文深化其功能域:**租户管理(开通/配额/档/注销)、PoP/容量/选址(运营动作 + Grafana 看指标)、跨租户支持(理由记录+审计)、平台 RBAC/令牌、CA/KEK(双人控制审批流)、SecOps(占位后置)**;并把每功能落到**所需后端 API 契约**(§五汇总,几乎全新建)。**头号前置是跨租户数据路径(§3.1):专用 `app_platform_ro` + 平台视图(最小授权)+ 平台进目标租户 RLS 上下文,绝不给业务角色 BYPASSRLS**——守住 RLS 隔离哲学。**敏感操作(平台访租户/CA·KEK/注销)全后端强制(理由+双人+审计),前端仅呈现流程,不是安全边界。** 监控看板复用 Grafana,不自研。**真实第一刀在后端 PC-API-0(跨租户路径)+ PC-API-7(OpenAPI 规格),非前端页面。**

**衔接:** 前端控制台 L2(`app-admin` 入口/双入口/生成消费/RBAC 体验层)、控制面 L2 总览(新增 `platform` 模块编码)、数据访问层 L2(`app_platform_ro` + 平台视图)、审计事务化(Slice29,平台操作审计)、运维/部署 L2(PoP drain/灰度、Grafana/VM/CH)、PKI(L1 3.5,CA/KEK 双人控制)。**写代码须另行授权(设计先行)。**

---

## 附录:待确认

| # | 项 | 性质 | 去向 |
|---|----|------|------|
| LP-PC1 | 平台视图清单与字段(只放运营必需聚合,不泄租户明细) | 数据契约 | 与数据访问层 L2 / `platform` 模块定 |
| LP-PC2 | ✅ **已定(2026-05-27):平台内部监控用自托管 Grafana**(开源、数据不出域、同栈治理、客户不可见;起步外链→目标内嵌+SSO);**对客租户用量看板自研、不嵌第三方** | 集成 | 实施期(SSO/CSP) |
| LP-PC3 | CA/KEK 双人控制状态机 + 审批超时 | 流程 | 与 PKI / `platform` 模块定 |
| LP-PC4 | ✅ **已定(2026-05-27):平台控制台访问须 MFA**;堡垒/内网隔离作纵深叠加(待运维 L2) | 安全 | MFA 与运维 L2 协同 |
| LP-PC5 | ✅ **已定(2026-05-27):租户注销走宽限期(软删→宽限→硬删 DEK)**,非立即不可逆;宽限期时长 + 注销是否再叠双人控制 待定 | 流程 | 与 L1 3.16 定 |
| LP-PC6 | ✅ **已定(2026-05-27):`app_platform_ro` 用最小授权视图**(只授平台视图 SELECT,**不走 BYPASSRLS**;CI G2「角色无 BYPASSRLS」断言不松动) | 安全 | §3.1,与数据访问层 L2 协同 |
| LP-PC7 | admin/会话令牌分 audience(借 PC-API-5 平台令牌签发端点推动) | 契约 | 与 `identity`/`authz` 协同 |

> 说明:平台控制台是运营工具,跨租户是其本质;**跨租户数据路径(§3.1)与敏感操作后端强制(§3.4)是两条不可让的安全底线**。功能虽多,后端契约几乎全新建(§五)——做平台控制台 = 先补后端(PC-API-0/7 为地基),再前端页面。
