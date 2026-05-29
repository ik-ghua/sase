-- 0003 down:回滚(开发用)。
DROP POLICY IF EXISTS tenant_isolation ON revocations;
DROP POLICY IF EXISTS tenant_isolation ON connectors;
DROP POLICY IF EXISTS tenant_isolation ON apps;
DROP TABLE IF EXISTS revocations;
DROP TABLE IF EXISTS connectors;
DROP TABLE IF EXISTS apps;
