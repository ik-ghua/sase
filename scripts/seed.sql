-- scripts/seed.sql —— demo 种子数据(供 deploy/docker-compose 一键演示)。
-- 由 migrate 容器以 superuser 执行(在所有迁移之后)。幂等:ON CONFLICT DO NOTHING。
--
-- 内容:
--   ① 一个固定 UUID 的 demo 租户(active/standard)——固定 UUID 让 pop-agent 的 TENANT 环境变量可预先配置。
--   ② 该租户下一个 demo 用户(idp_id=NULL,手建用户)。
--
-- 注:此处经**直接 SQL** 种子,故 demo 租户**没有** tenant_keys(DEK)行——
--   tenant.Create() 走 API 才会同事务建 DEK。本 demo 数据路径(tenant 列表 + ZTNA/SD-WAN 下发)
--   不依赖 DEK;DEK 仅 idp_config 加密等场景需要。要演示"建带 DEK 的真租户",经控制台/管理 API 新建即可。
--
-- platform_admin:不在此 seed,由 api-server 的 SASE_BOOTSTRAP_PLATFORM_ADMIN 启动时带外签发令牌(见 .env / README)。
--
-- RLS:tenants/users 均 FORCE ROW LEVEL SECURITY。superuser 默认绕过 RLS,但为稳妥(并对 WITH CHECK 显式),
--   先设 app.current_tenant GUC 再插,使策略 USING/WITH CHECK 通过(与应用运行期一致)。

\set demo_tenant '11111111-1111-1111-1111-111111111111'
\set demo_user   '22222222-2222-2222-2222-222222222222'

-- 设当前租户上下文(本会话有效),让 RLS WITH CHECK 通过。
SELECT set_config('app.current_tenant', :'demo_tenant', false);

INSERT INTO tenants (id, name, status, plan)
VALUES (:'demo_tenant', 'Demo 公司', 'active', 'standard')
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, tenant_id, external_id, email, status)
VALUES (:'demo_user', :'demo_tenant', 'demo-alice', 'alice@demo.local', 'active')
ON CONFLICT (tenant_id, idp_id, external_id) DO NOTHING;

-- 输出种子结果摘要(便于 init 容器日志确认)。
SELECT 'seeded tenant' AS what, id, name, status FROM tenants WHERE id = :'demo_tenant';
SELECT 'seeded user' AS what, id, email, status FROM users WHERE id = :'demo_user';
