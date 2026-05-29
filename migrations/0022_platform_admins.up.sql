-- 0022 platform_admins:平台管理员持久化(Slice38c,多枚 platform_admin 管理 / 角色分配)。
--
-- 现状(Slice38c 之前):
--   - bootstrap_platform_admin env 启动时签发**短期**(15min)platform_admin token(应急通道);
--   - `/api/v1/platform/admin-tokens` 平台签发 **tenant 作用域** admin token,**禁止 platform_admin 自签发**(避审计缺口);
--   - **没有"平台管理员"持久化表**——authz 仅查 token claim,谁拿到 platform_admin token 谁就是 platform_admin,缺持久化 RBAC。
--
-- Slice38c 设计:
--   1. 持久化 platform_admins 表(平台全局,无 tenant_id;与 pop_nodes / platform_audit_log 同侧);
--   2. `/platform/admin-tokens` 扩展:role=platform_admin 必查本表(IsActive);tenant_admin/auditor 保持原行为;
--   3. bootstrap 路径**绕过表**(应急,生产应立即用该令牌登记自己);
--   4. 双层审计:挂 platform_audit_tr 触发器(Slice39 模式)。

CREATE TABLE IF NOT EXISTS platform_admins (
  id           uuid        PRIMARY KEY,
  subject      text        NOT NULL UNIQUE,           -- 主体标识(IdP sub / 运营 ID);用于 token 签发时查表
  email        text        NOT NULL DEFAULT '',       -- 联系邮箱(可空)
  status       text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  created_by   text        NOT NULL DEFAULT ''        -- 谁加的(审计;bootstrap 加自己时为空)
);
CREATE INDEX IF NOT EXISTS idx_platform_admins_status ON platform_admins (status);

-- updated_at 自动维护(同 pop_nodes 模式)
CREATE OR REPLACE FUNCTION platform_admins_touch() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END$$;
DROP TRIGGER IF EXISTS platform_admins_touch_tr ON platform_admins;
CREATE TRIGGER platform_admins_touch_tr BEFORE UPDATE ON platform_admins
  FOR EACH ROW EXECUTE FUNCTION platform_admins_touch();

-- 挂平台审计触发器(Slice39 双层审计:source=data 原子层)
DROP TRIGGER IF EXISTS platform_audit_tr ON platform_admins;
CREATE TRIGGER platform_audit_tr
  AFTER INSERT OR UPDATE OR DELETE ON platform_admins
  FOR EACH ROW EXECUTE FUNCTION platform_audit_row();

-- 权限(纵深):
--   app_platform_rw:全 CRUD(handler 写 + 触发器写)
--   app_platform_ro:只读(列表/IsActive 经 InPlatformTx)
--   app_rw / app_ro:**不授权**(租户路径不应见平台 RBAC 表)
GRANT SELECT, INSERT, UPDATE, DELETE ON platform_admins TO app_platform_rw;
GRANT SELECT                          ON platform_admins TO app_platform_ro;

COMMENT ON TABLE platform_admins IS 'platform-global RBAC: platform_admin 持久化(Slice38c); no RLS; managed by app_platform_rw';
