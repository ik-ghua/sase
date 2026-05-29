-- 0006 down:回滚(开发用)。
DROP POLICY IF EXISTS tenant_isolation ON sites;
DROP TABLE IF EXISTS sites;
