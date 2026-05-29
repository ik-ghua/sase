-- 0015 down:视图回退(去 quota 列)+ 删约束 + 删列。
CREATE OR REPLACE VIEW tenant_summary AS
  SELECT id, name, status, plan, created_at, decommission_at
  FROM tenants;
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_quota_nonneg_chk;
ALTER TABLE tenants DROP COLUMN IF EXISTS max_users;
ALTER TABLE tenants DROP COLUMN IF EXISTS max_policies;
ALTER TABLE tenants DROP COLUMN IF EXISTS max_bandwidth_mbps;
