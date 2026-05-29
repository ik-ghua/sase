-- 0001 init:应用角色 + tenants/users + RLS(数据访问层 L2 3.2/3.5)。
-- 迁移以 owner/superuser 执行;应用运行用 app_rw/app_ro(非 owner、NOBYPASSRLS),故受 RLS 约束。

-- 应用角色:app_rw(读写)、app_ro(只读),均 NOSUPERUSER NOBYPASSRLS。
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_rw') THEN
    CREATE ROLE app_rw LOGIN PASSWORD 'app_rw_dev' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_ro') THEN
    CREATE ROLE app_ro LOGIN PASSWORD 'app_ro_dev' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

-- 租户注册表(每行=一个租户;RLS:只能见/写自身 id 的行)。
CREATE TABLE IF NOT EXISTS tenants (
  id         uuid        PRIMARY KEY,
  name       text        NOT NULL,
  status     text        NOT NULL DEFAULT 'active',   -- active / suspended / offboarding
  plan       text        NOT NULL DEFAULT 'standard',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 用户表(租户作用域)。
CREATE TABLE IF NOT EXISTS users (
  id          uuid        PRIMARY KEY,
  tenant_id   uuid        NOT NULL,
  external_id text        NOT NULL,
  email       text        NOT NULL,
  status      text        NOT NULL DEFAULT 'active',
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);

-- RLS:ENABLE + FORCE(连 owner 也受约束,纵深)。
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE  ROW LEVEL SECURITY;
ALTER TABLE users   ENABLE ROW LEVEL SECURITY;
ALTER TABLE users   FORCE  ROW LEVEL SECURITY;

-- 策略:missing_ok=true → 未设上下文时 current_setting 返回 NULL → 比较为假 → 0 行(fail-closed)。
DROP POLICY IF EXISTS tenant_isolation ON tenants;
CREATE POLICY tenant_isolation ON tenants
  USING      (id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON users;
CREATE POLICY tenant_isolation ON users
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- 授权:app_rw 读写、app_ro 只读(均受 RLS)。
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, users TO app_rw;
GRANT SELECT ON tenants, users TO app_ro;
