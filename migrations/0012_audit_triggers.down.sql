-- 0012 down:摘触发器 + 删函数 + 去 source 列。
DROP TRIGGER IF EXISTS audit_tr ON tenants;
DROP TRIGGER IF EXISTS audit_tr ON users;
DROP TRIGGER IF EXISTS audit_tr ON apps;
DROP TRIGGER IF EXISTS audit_tr ON connectors;
DROP TRIGGER IF EXISTS audit_tr ON policies;
DROP TRIGGER IF EXISTS audit_tr ON sites;
DROP TRIGGER IF EXISTS audit_tr ON swg_rules;
DROP TRIGGER IF EXISTS audit_tr ON fw_rules;
DROP TRIGGER IF EXISTS audit_tr ON dlp_rules;
DROP TRIGGER IF EXISTS audit_tr ON device_enrollments;

DROP FUNCTION IF EXISTS audit_row();

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_source_chk;
ALTER TABLE audit_log DROP COLUMN IF EXISTS source;
