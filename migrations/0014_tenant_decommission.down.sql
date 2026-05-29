-- 0014 down:视图回退到不含 decommission_at + 删列。
CREATE OR REPLACE VIEW tenant_summary AS
  SELECT id, name, status, plan, created_at
  FROM tenants;
ALTER TABLE tenants DROP COLUMN IF EXISTS decommission_at;
