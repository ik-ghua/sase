-- 0006 SD-WAN 站点:轨道二的站点注册(L1 3.3 Site/CPE、3.8 租户路由域内站点互通)。租户作用域、RLS。
-- 起步:站点 = 逻辑键 + 子网 CIDR;每租户独立路由域(同租户站点互通)。CPE 入网/隧道加密待后续刀/国密。

CREATE TABLE IF NOT EXISTS sites (
  id         uuid        PRIMARY KEY,
  tenant_id  uuid        NOT NULL,
  site_key   text        NOT NULL,            -- 站点逻辑标识(如 "site-bj")
  name       text        NOT NULL,
  cidr       text        NOT NULL,            -- 站点子网(如 "10.0.1.0/24")
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_sites_tenant_key ON sites (tenant_id, site_key);

ALTER TABLE sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE sites FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON sites;
CREATE POLICY tenant_isolation ON sites
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON sites TO app_rw;
GRANT SELECT ON sites TO app_ro;
