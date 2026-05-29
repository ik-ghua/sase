-- 0015 租户配额(PC-API-2a 续:补完 PATCH 的"改配额")。
-- 配额是平台限定的上限(防滥用/计费分级);NULL=不限(unlimited),业务校验由 admission 路径在具体写入时执行。
-- 当前 3 项:max_users(用户数上限)、max_policies(策略数上限)、max_bandwidth_mbps(带宽上限 Mbps)。
-- 后续可加(如 max_apps/connectors/sites)。
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_users           int;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_policies        int;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS max_bandwidth_mbps  int;

-- 配额必须 ≥ 0(NULL 表"不限",非负表"上限");防误写负数。
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_quota_nonneg_chk;
ALTER TABLE tenants ADD CONSTRAINT tenants_quota_nonneg_chk
  CHECK (
    (max_users          IS NULL OR max_users          >= 0) AND
    (max_policies       IS NULL OR max_policies       >= 0) AND
    (max_bandwidth_mbps IS NULL OR max_bandwidth_mbps >= 0)
  );

-- 平台视图带上配额(平台运维看上限分布);CREATE OR REPLACE 保留 owner/授权(0013 owner 绕 RLS 自检结论不变,列仅追加)。
CREATE OR REPLACE VIEW tenant_summary AS
  SELECT id, name, status, plan, created_at, decommission_at,
         max_users, max_policies, max_bandwidth_mbps
  FROM tenants;
