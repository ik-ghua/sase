-- 0001 down:回滚(开发用)。
DROP POLICY IF EXISTS tenant_isolation ON users;
DROP POLICY IF EXISTS tenant_isolation ON tenants;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
-- 角色保留(可能被其它库引用);如需删:DROP ROLE IF EXISTS app_rw, app_ro;
