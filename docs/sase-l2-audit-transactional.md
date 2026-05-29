# 审计事务化 L2(DB 触发器原子审计)

> **状态:** L2 组件设计 / **已编码(Slice29)**
> **版本:** v0.2
> **日期:** 2026-05-27
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **v0.2(2026-05-27,Slice29 as-built):** 方案 A 已编码(花刚认可方案 A 即评审通过)。§六 编码前须定项全部收口(见 §八 实现现状),并经 go-code-reviewer 审过(无硬错误)、VM 真实 PG 集成测试通过(原子性/source 两层/actor 归因/CI catalog 门禁)。migration 0012。
>
> **层级与上承:** L2 机制深挖,落地「审计与业务变更**原子**」——补当前 `internal/audit` HTTP 中间件「业务提交后独立事务写审计、best-effort」的原子性缺口(`internal/audit/middleware.go` 注释自陈的 known-limitation)。上承 L1 `sase-architecture-design.md`(现 v0.6,本设计已回写 3.14「审计事务化设计待评审编码」)的 **3.14(可观测/审计)、3.22(合规并行 R1,等保审计留存 C13)**;控制面 L2 总览(横切 audit)、数据访问层 L2(RLS/事务)。
>
> **衔接:** `internal/audit`(中间件/服务/schema)、`internal/data`(事务 + RLS 上下文 GUC)、`internal/authz`(actor/role principal)、各 mutating 业务模块、migrations(audit_log + 触发器)。
>
> **范围:** 审计写的**原子性**机制(与业务变更同事务)、actor 归因传递、审计粒度迁移、与现 HTTP 中间件分工、多租户与防篡改、风险与待确认。
>
> **不含:** 审计外发 SIEM/告警(后置)、审计 UI、读端点(已有)、审计内容的 PII 脱敏策略(单列,见 §7 待确认)。
>
> **设计先行:** 含机制说明,不写代码。每决策配依据 / 备选及落选 / 可行方案;未定项标「待确认」。

---

## 一、背景

当前审计(`internal/audit`):HTTP 中间件在 authz 之后、业务 handler 返回**之后**,用**独立事务**(非业务事务)写 `audit_log`,best-effort。缺口(中间件注释自陈):

- **原子性缺口**:业务变更已 COMMIT,但随后审计写失败 / 进程崩溃 → **变更成功而无审计**。等保(C13)/不可抵赖要求"凡变更必留痕",此窗口违背。
- **粒度**:现审计是 **API 动作级**(`actor` / `role` / `action="POST /api/v1/tenants"` / `result`=HTTP 码),由中间件从请求 + 响应得。

目标是让审计与业务变更**同生共死**(同一 DB 事务,原子)。

---

## 二、目标

1. **原子**:审计写与业务变更在**同一 DB 事务**——业务回滚则审计回滚,业务提交则审计必提交(消除"变更成功无审计"窗口)。
2. **可归因**:审计含 actor(谁)/ role / tenant,与现有 schema 兼容。
3. **多租户隔离**:审计行受 RLS 按 `tenant_id` 隔离(与全平台一致)。
4. **防篡改**:审计 append-only(已有:`app_rw` 仅 `INSERT,SELECT` on `audit_log`,migration 0004)。
5. **低侵入**:尽量不改每个业务模块的代码。

**非目标:** SIEM 外发、审计 UI、读端点(已有)、PII 脱敏(待确认)。

---

## 三、形态决策

| 备选 | 做法 | 落选 / 顾虑 |
|------|------|------------|
| **A. DB 触发器(选定)** | 受审计表加 `AFTER INSERT/UPDATE/DELETE` 触发器,在**触发它的业务事务内**自动 `INSERT audit_log`;actor/role 经 per-tx GUC(`app.current_actor`)传入,触发器 `current_setting` 读 | **零业务代码改动 + 真原子**(触发器随业务事务提交/回滚);代价:审计粒度由「API 动作」转「**数据行变更**」(无 HTTP 结果码;捕获不到"被拒/无变更的尝试")——缓解见 §5/§6 两层分工 |
| B. joinable-tx(服务在自身事务内写审计) | data 层支持 actor 入上下文;每个 mutating service 方法在自己的 `InTx` 内追加 audit 写 | 保留 API 动作语义 + 原子;但**改动每个 mutating service**(面广、易漏);新增模块须记得加 |
| C. outbox + relay | 业务事务内写 `audit_outbox`(同 B 的注入面),后台 relay 搬到 audit_log | 原子 + 解耦下游(适合审计要外发);比 B 多一张表 + relay 进程,当前无外发需求,过度 |

**结论:选 A。** 关键:A 把"原子审计"做成**数据库层不变量**(挂了触发器的表,任何成功变更必有同事务审计,且无法被应用代码绕过遗漏),改动最小;粒度转变用「两层审计分工」(§6)弥补。B/C 的 per-service 注入面广、易漏,与"低侵入 + 不可绕过"目标相悖。

依据:审计完整性应是**数据层强制**而非应用层自觉(与 RLS 同哲学:misuse-resistant、不可绕过)。
- 备选 B 落选:逐服务注入,新增模块漏写即审计缺失,违"不可绕过"。
- 备选 C 落选:当前无审计外发需求,relay 进程是过度工程;需要外发时可在 A 之上加(触发器写的 audit_log 本身可作 outbox 源)。

---

## 四、设计

### 4.1 触发器与审计写(原子核心)
- 受审计表加**通用触发器函数** `audit_row()`(`AFTER INSERT OR UPDATE OR DELETE ... FOR EACH ROW`),在业务事务内 `INSERT INTO audit_log(...)`。因触发器在**触发它的事务**内执行,业务 ROLLBACK 则审计 INSERT 一并回滚、业务 COMMIT 则审计一并提交 → **原子**。
- `audit_log` 字段填充(复用现 schema:tenant_id/ts/actor_subject/actor_role/action/result/detail):
  - `tenant_id` = `COALESCE(NEW.tenant_id, OLD.tenant_id)`(行自带租户,最准;与 RLS WITH CHECK 一致)。
  - `actor_subject`/`actor_role` = `current_setting('app.current_actor', true)` / `app.current_actor_role`(per-tx GUC,见 4.2;未设 → 空/`'system'`)。
  - `action` = `TG_OP || ' ' || TG_TABLE_NAME`(如 `INSERT tenants` / `DELETE revocations`)——**数据变更级**(非 HTTP 动作)。
  - `detail` = 行标识(如 `id` / 关键字段;**不含整行旧/新值**,避免 PII 入审计,见 §7)。
  - `result` = 不适用(DB 层无 HTTP 码;成功变更才触发)。填 0 或省(schema `result int`,置 0 表"数据变更类")。
- **RLS**:触发器以业务事务身份(`app_rw`,已在该 tenant 上下文)`INSERT audit_log`,`tenant_id` 取自行 → RLS WITH CHECK 通过;`app_rw` 对 `audit_log` 有 INSERT 权限(0004)。**待确认**:触发器函数是否需 `SECURITY DEFINER`(若 RLS/权限在 INVOKER 身份下不足),见 §7。

### 4.2 actor 归因传递(per-tx GUC)
- data 层 `InTx` 现每事务 `set_config('app.current_tenant', tenantID, true)`;**新增** `set_config('app.current_actor', actor, true)` + `app.current_actor_role`,actor/role 取自请求 `ctx`(authz.Principal,`authz.FromContext`)。
- **设计点(待确认)**:data 层如何拿 actor——① `InTx` 从 `ctx` 取 `authz.Principal`(data 层导入 authz,轻耦合);② 或 data 层提供 `InTxAs(ctx, tenant, actor, role, fn)` 由 handler 传;③ 或 ctx 里放一个中性的 `data.Actor` 值(authz 中间件注入,data 层读,避免 data→authz 依赖)。**倾向 ③**(中性 ctx 值,无模块反向依赖)。无 actor(内部任务/无 HTTP)→ GUC 空 → 审计记 `system`。

### 4.3 受审计表范围(关键:排除高频非业务变更)
挂触发器的表 = **租户业务变更**:`tenants`/`users`/`apps`/`connectors`/`policies`/`policy_bundles`/`swg_rules`/`sites`/`fw_rules`/`dlp_rules`/`device_enrollments`。
**显式排除**(否则审计风暴 / 噪声):
- `revocations`:撤销本身值得审计,但**机会式 GC 的批量 DELETE 会触发审计风暴**(GC L2,Slice28)→ 撤销审计宜走"撤销动作"语义(可由 INSERT 触发器记、DELETE[GC] 不记),或 revocations 不挂触发器、撤销审计由应用显式记。**待确认**。
- `audit_log` 自身:绝不挂(自触发死循环)。
- **待确认**:`policy_bundles`(编译产物,非人工变更)是否审计;按 `TG_OP` 过滤(如只审计 DELETE/UPDATE 不审计 bundle 的高频 INSERT)。

### 4.4 与现 HTTP 中间件的分工(两层审计)
DB 触发器粒度是「成功的数据变更」,**捕获不到**:① HTTP 结果码;② **被拒/无变更的尝试**(如 authz 通过但业务 422、或 deny 的访问尝试)。故:
- **DB 触发器 = 权威、原子的"数据变更审计"**(合规核心:什么变了、谁、原子)。
- **HTTP 中间件 = 保留作补充层**,记触发器看不到的:**失败/无变更的授权操作尝试**(API 动作 + 结果码),best-effort。为避免对同一成功变更双重记账,**拟**让中间件对"成功且产生数据变更"的请求不再记(由触发器记)、只记"被拒/无变更"的尝试。**待确认**:分工边界(中间件如何判定"已由触发器覆盖")——候选简化为中间件只在 4xx/5xx 时记(成功交触发器)。
- **⚠️ 盲区(待确认必须解决)**:"**2xx 成功但零行变更**"的请求——幂等 PUT、`ON CONFLICT DO NOTHING`(现成例子:`RevokeCredential` 重复撤销同 jti 不产生行变更 → 触发器不触发)。若中间件采"只记 4xx/5xx",则这类请求**既不被触发器记、也不被中间件记 → 漏记**。分工边界须显式覆盖"2xx 零变更"(如中间件对 2xx 但无对应触发器审计的也补记),否则简化方案落地即埋漏。

---

## 五、风险

1. **审计风暴(最需注意)**:高频写表(尤 `revocations` 机会式 GC 批量 DELETE)挂触发器 → 每行一条审计。缓解:§4.3 排除 GC 类操作(按 `TG_OP`/表过滤),触发器只挂"人工业务变更"语义的表/操作。
2. **粒度转变**:API 动作级 → 数据变更级,丢 HTTP 结果码与"失败尝试"。缓解:§4.4 两层分工(中间件补失败尝试)。审计读端点/格式需适配(action 语义变;result 置 0)。
3. **触发器维护成本**:新增受审计表须记得挂触发器,易漏。缓解:迁移规范 + **CI catalog 断言**(类比 RLS 门禁:断言"含 tenant_id 的业务表均挂 audit 触发器,排除清单除外")。
4. **actor GUC 未设**:非 HTTP 路径(内部任务/未来定时作业)写表 → actor 空 → 记 `system`(可接受,且可识别)。须确保 HTTP 路径都经中间件设 GUC。
5. **触发器权限/SECURITY DEFINER**:若 INVOKER(app_rw)身份下 RLS/权限不足以写 audit_log,需 DEFINER(以函数 owner 身份),但 DEFINER 绕 RLS 须谨慎(显式置 tenant_id from row)。**待确认**(实测)。
6. **性能**:每行变更多一次 INSERT(同事务,本地)。业务写多为低频控制面操作,可接受;高频表已排除(风险 1)。
7. **detail/PII**:detail 含行标识而非整行值,避免敏感数据入审计(审计留存期长,PII 入审计扩大合规面)。**待确认**:detail 粒度。

---

## 六、待确认 / 待评审

- **触发器函数权限**:INVOKER(app_rw)是否够,还是需 SECURITY DEFINER(实测 RLS/权限)。**张力**:DEFINER 若 owner 为 superuser/`BYPASSRLS`,`WITH CHECK` 不再兜底,`tenant_id` 正确性完全靠触发器代码自填——把"数据层不变量"部分移回"函数代码自觉",与 §3 选 A 的 misuse-resistant 初衷相悖,评审须摊开权衡(优先 INVOKER)。
- **受审计表范围 + 操作过滤**:`revocations`(GC DELETE 不审计)、`policy_bundles`(编译 INSERT 是否审计)的具体排除/过滤规则。
- **actor 传递机制**:倾向方案 ③(中性 `data.Actor` ctx 值,避免 data→authz 依赖);需新增 authz 中间件→data 的 ctx 注入接缝(现 `authz.FromContext` 返回 `authz.Principal`,要转成 data 层可读的中性值),确认接口形态。
- **两层分工边界**:中间件保留"失败尝试"审计的判定逻辑,避免与触发器双重记账。
- **schema 适配**:`result` 字段对数据变更类置 0;`action` 语义从 HTTP 动作转 `TG_OP table`——读端点/前端展示是否需区分两类审计来源(加 `source` 列?待确认)。**迁移隐患**:未加 `source` 列前,`result=0`(数据变更哨兵)与真实 HTTP 码同列混义,读端点/告警规则须能区分两类来源(known migration hazard)。
- **detail 内容**:行标识粒度,PII 边界。
- **失败鉴权审计**(现 known-limitation):authz 拒绝前于审计中间件,失败鉴权不留痕——是否借本次一并补(中间件层,与触发器正交)。

---

## 七、结论

审计事务化采用 **DB 触发器**:受审计的租户业务表挂通用 `AFTER` 触发器,在业务事务内原子写 `audit_log`,actor/role 经 per-tx GUC(`app.current_actor`)传入——**把"凡变更必留痕"做成数据库层不可绕过的不变量**(与 RLS 同哲学),零业务代码改动。粒度从「API 动作」转「数据变更」,用**两层分工**弥补:触发器=权威原子的数据变更审计,HTTP 中间件保留作补充记失败/无变更尝试。**关键护栏**:排除高频/GC 类操作防审计风暴(§4.3/§5.1)、CI catalog 断言防漏挂触发器。**编码前须定**:触发器权限(DEFINER?)、受审计表/操作过滤清单、actor 传递接口、两层分工边界(§六)——均已收口,见 §八。

---

## 八、实现现状(Slice29 as-built)

§六 编码前须定项的**最终决策**(均已编码、VM 真实 PG 测试通过、go-code-reviewer 审过):

| §六 项 | 决策 | 落地 |
|--------|------|------|
| 触发器权限 | **INVOKER(app_rw),不用 SECURITY DEFINER** | 触发器在业务事务内、`app.current_tenant` 已设、`tenant_id` 取自行 → audit_log RLS `WITH CHECK` 必过(行 tenant_id 与 current_tenant 同源,reviewer 核全 10 表写入路径确认)。守 misuse-resistant,不把不变量移回函数自觉。 |
| 受审计表范围 | **10 张租户业务表**:tenants(id 列)/users/apps/connectors/policies/sites/swg_rules/fw_rules/dlp_rules/device_enrollments(tenant_id 列) | `migrations/0012`;**排除** revocations(GC 风暴)、policy_bundles(编译高频)、audit_log(自触发)。 |
| actor 传递 | **方案 ③ 中性 ctx 值** | `data.Actor` + `data.WithActor`(data 不依赖 authz);`runTx` 设 per-tx GUC `app.current_actor[_role]`;`audit.ActorMiddleware`(authz 后)读 Principal→注入。无主体→`role='system'`。 |
| 两层分工 + **D1 盲区** | 加 **`source` 列**(api/data);触发器=`data`(原子权威、result=0 哨兵、`TG_OP 表名`),中间件=`api`(**全部变更请求含 2xx/4xx/5xx**,best-effort) | **D1 收口**:中间件对所有变更请求都记 → 2xx-零变更必有 api 行,无盲区;source 同时消解「result=0 vs HTTP 码」同列混义(原 §108 隐患)。 |
| schema 适配 | `source text NOT NULL DEFAULT 'api'` + CHECK;既有行(中间件写)默认 api | 读端 `ListByTenant` 返回 source;**消费者按 result 过滤须同时看 source**(data 行 result 恒 0)。 |
| detail/PII | 仅记行标识 `id=<uuid>`,不落整行值 | 触发器 `to_jsonb(rec)->>'id'`。 |
| gen_random_uuid | PG13+ core;迁移顶部 `CREATE EXTENSION IF NOT EXISTS pgcrypto` 兜底 | 事务化把"审计写失败"放大为"业务变更失败"→ 该函数可用性钉成硬前提(reviewer 建议)。 |

**测试(`internal/audit/trigger_integration_test.go`,VM 真实 PG,`-race` 净):** ① 原子性(业务回滚→审计 0 行;提交→恰 1 条 data 行);② source/action/result/detail 字段正确;③ actor 归因(alice/tenant_admin)+ 无主体→system;④ 跨租户隔离;⑤ **CI catalog 门禁** `TestAuditTriggerCatalogGate`(凡含 tenant_id 业务表除排除清单外必挂 audit_tr;tenants 单独断言)。既有端到端审计测试(`audit_integration_test.go`)在触发器并存下仍绿。

**已知特性 / 后续(reviewer 低优先建议):**
- **ZTP 设备路径**(Redeem/Renew/RevokeDevice 写 device_enrollments)不经 admin 中间件链 → data 审计行 actor 记 `system`;同时 `enroll.WithAudit` 另写带语义的 api 行(`ZTP_ENROLL_REDEEM`/`ZTP_RENEW`)。**ZTP 变更归因以 api 行为准,data 行仅作不可绕过的存在性证明。**
- **source/result 耦合**须在 API/前端文档显式标注(data 行 result=0 非"成功码")。
- actor 长度:`Subject` 来自我方签发令牌 claims,长度上限在签发侧(纵深,非阻断)。
- **后续(非本刀)**:SIEM 外发(可在触发器写的 audit_log 上加 relay,即 §3 备选 C 的演进)、审计 UI、失败鉴权审计(authz 拒绝前于中间件,与触发器正交,待补)、policy_bundles/revocations 的语义化审计(若需)。
