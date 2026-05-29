-- 0004 down:回滚(开发用)。
DROP POLICY IF EXISTS tenant_isolation ON audit_log;
DROP TABLE IF EXISTS audit_log;
