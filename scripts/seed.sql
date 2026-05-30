-- scripts/seed.sql —— demo 种子数据(供 deploy/docker-compose 一键演示)。
-- 由 migrate 容器以 superuser 执行(在所有迁移之后)。幂等:ON CONFLICT DO NOTHING。
--
-- 内容:
--   ① 一个固定 UUID 的 demo 租户(active/standard)——固定 UUID 让 pop-agent 的 TENANT 环境变量可预先配置。
--   ② 该租户下一个 demo 用户(idp_id=NULL,手建用户)。
--   ③ 两个 SD-WAN 站点(site-a 10.10.0.0/24 / site-b 10.20.0.0/24)——供 PoP 经 xDS SiteConfig 下发,
--      Router 据各站点 CIDR 在租户路由域内选路(站点互通,T1 SD-WAN 真隧道 demo)。
--   ④ 两条 CPE 设备入网(ZTP)记录(kind=cpe,identity=site_key,固定一次性激活码)——CPE 容器凭
--      ZTP_CODE 换取**租户绑定证书**(tenant=Org / site=CN,W9),隧道握手 peerIdentity 据此取 tenant/site。
--      ⚠️ 固定激活码仅 demo 用;生产经管理 API 动态签发、一次性。
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

-- ③ SD-WAN 两站点(经 xDS SiteConfig 下发 PoP;Router 据 CIDR 选路)。
--    CIDR 为规范 v4(承接 Slice71 CIDR 校验:v4 地址须 v4 掩码,本处直插 superuser 不过 site.CreateSite,故显式用规范形)。
INSERT INTO sites (id, tenant_id, site_key, name, cidr) VALUES
  ('33333333-3333-3333-3333-333333333331', :'demo_tenant', 'site-a', '北京分支', '10.10.0.0/24'),
  ('33333333-3333-3333-3333-333333333332', :'demo_tenant', 'site-b', '上海分支', '10.20.0.0/24')
ON CONFLICT (tenant_id, site_key) DO NOTHING;

-- ④ 两条 CPE ZTP 入网记录(kind=cpe;identity=site_key=证书 CN;固定一次性激活码 <tenant>.<hex>)。
--    CPE 容器以 ZTP_CODE=<下方激活码> 换证书:enroll.Redeem 据码前缀定位租户、据 identity 作证书 CN、
--    把 tenant 编进证书 Organization(W9)。status='pending' → 首次兑换置 'redeemed'(一次性)。
--    ⚠️ 激活码硬编码仅供 demo 重复起栈;生产经管理 API 动态签发。
INSERT INTO device_enrollments (id, tenant_id, kind, identity, activation_code, status) VALUES
  ('44444444-4444-4444-4444-444444444441', :'demo_tenant', 'cpe', 'site-a',
   '11111111-1111-1111-1111-111111111111.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'pending'),
  ('44444444-4444-4444-4444-444444444442', :'demo_tenant', 'cpe', 'site-b',
   '11111111-1111-1111-1111-111111111111.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'pending')
ON CONFLICT (tenant_id, identity) DO NOTHING;  -- 唯一键 0009 收紧为 (tenant_id, identity)(kind 不参与)

-- ⑤ FWaaS 规则:**默认拒绝**(无规则集→PoP Router fail-closed 丢全部站点间转发);故须显式 allow 站点互通。
--    本 demo 放行两站点子网双向(分段策略可见:只放行 site-a↔site-b,体现"每租户网络分段")。
--    经 xDS FWRuleSet 下发 PoP,dptunnel Router 转发前裁决(承接 Slice30 "FWaaS L4 真生效")。
INSERT INTO fw_rules (id, tenant_id, priority, action, protocol, src_cidr, dst_cidr, dst_port_min, dst_port_max) VALUES
  ('55555555-5555-5555-5555-555555555551', :'demo_tenant', 10, 'allow', 'any', '10.10.0.0/24', '10.20.0.0/24', 0, 0),
  ('55555555-5555-5555-5555-555555555552', :'demo_tenant', 11, 'allow', 'any', '10.20.0.0/24', '10.10.0.0/24', 0, 0)
ON CONFLICT (id) DO NOTHING;

-- 输出种子结果摘要(便于 init 容器日志确认)。
SELECT 'seeded tenant' AS what, id, name, status FROM tenants WHERE id = :'demo_tenant';
SELECT 'seeded user' AS what, id, email, status FROM users WHERE id = :'demo_user';
SELECT 'seeded site' AS what, site_key, cidr FROM sites WHERE tenant_id = :'demo_tenant' ORDER BY site_key;
SELECT 'seeded enroll' AS what, kind, identity, status FROM device_enrollments WHERE tenant_id = :'demo_tenant' ORDER BY identity;
SELECT 'seeded fw' AS what, action, src_cidr, dst_cidr FROM fw_rules WHERE tenant_id = :'demo_tenant' ORDER BY priority;
