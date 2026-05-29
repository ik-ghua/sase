-- 0002 down:回滚(开发用)。
DROP POLICY IF EXISTS tenant_isolation ON policy_bundles;
DROP POLICY IF EXISTS tenant_isolation ON policies;
DROP TABLE IF EXISTS policy_bundles;
DROP TABLE IF EXISTS policies;
