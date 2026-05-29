-- 0013 平台跨租户只读路径(PC-API-0 地基,平台控制台 L2 §3.1)。
-- 平台控制台需跨租户看全租户,但 app_rw/app_ro 均 NOBYPASSRLS 且 tenants 表 RLS → 枚举不出全租户。
-- 解法:专用只读角色 app_platform_ro(**仍 NOBYPASSRLS**,LP-PC6 最小授权)+ 策展只读视图。
-- 跨租户能力收敛在"视图所有权"这条窄边界:视图由 RLS-bypass 主体拥有(迁移期 owner/superuser),
-- app_platform_ro 仅获视图 SELECT、对基表无任何授权 → 它只能经策展视图看安全字段、看不到基表明细。
-- ⚠️ 部署要求:视图须由**绕过 RLS 的主体**拥有(superuser 或 BYPASSRLS owner);本迁移以 owner/superuser 执行即满足。

-- 平台只读角色:NOBYPASSRLS(守 CI 断言 G2:跨租户不靠角色绕 RLS,靠策展视图授权)。
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_platform_ro') THEN
    CREATE ROLE app_platform_ro LOGIN PASSWORD 'app_platform_ro_dev' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END$$;

-- 策展平台视图:只暴露运营必需的租户元数据(id/name/status/plan/created_at),
-- **不含**用户明细/策略内容/任何租户业务数据(LP-PC1 起步字段;用量聚合后续刀)。
-- 视图默认以 owner 权限访问基表(非 security_invoker)→ owner 绕 RLS → 跨租户可见。
CREATE OR REPLACE VIEW tenant_summary AS
  SELECT id, name, status, plan, created_at
  FROM tenants;

-- 仅授平台只读角色对**视图**的 SELECT;基表 tenants 不授(它经视图看,绕不过基表 RLS 直读)。
GRANT SELECT ON tenant_summary TO app_platform_ro;

-- 显式不授 app_platform_ro 对任何基表的权限(它只能读 tenant_summary 及后续平台视图)。
-- 平台表白名单(数据访问层 L2 CI 断言 G3):tenant_summary 是"显式跨租户读租户表"的策展口子,须在白名单。
COMMENT ON VIEW tenant_summary IS 'platform-view: 平台跨租户只读策展视图(PC-API-0);含 tenant_id 派生但属平台白名单口子,见数据访问层 L2 §3.6/CI G3';

-- 部署自检(防沉默失败,go-code-reviewer Slice32 建议):跨租户读依赖"视图 owner 绕 RLS"。
-- 若本迁移被非 superuser、非 BYPASSRLS 的 owner 执行,视图会**静默少行/空**(而非报错)。
-- 此处把该隐患转为**响亮的迁移失败**:断言 tenant_summary 的 owner 是 superuser 或带 BYPASSRLS。
DO $$
DECLARE
  v_owner       name;
  v_bypass      bool;
  v_super       bool;
BEGIN
  SELECT pg_get_userbyid(c.relowner) INTO v_owner
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relname = 'tenant_summary' AND n.nspname = 'public';
  SELECT rolbypassrls, rolsuper INTO v_bypass, v_super FROM pg_roles WHERE rolname = v_owner;
  IF NOT (COALESCE(v_bypass, false) OR COALESCE(v_super, false)) THEN
    RAISE EXCEPTION 'tenant_summary 视图 owner=% 既非 superuser 也无 BYPASSRLS → 平台跨租户读会静默少行;须由绕 RLS 的主体拥有该视图(平台控制台 L2 §3.1)', v_owner;
  END IF;
END$$;
