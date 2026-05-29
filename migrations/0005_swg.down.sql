-- 0005 down:回滚(开发用)。
DROP POLICY IF EXISTS tenant_isolation ON swg_rules;
DROP TABLE IF EXISTS swg_rules;
