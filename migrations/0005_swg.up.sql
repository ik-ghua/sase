-- 0005 SWG 规则:安全能力 SWG(P2)的 URL 过滤规则(安全栈 L2:起步采购/规则)。租户作用域、RLS。
-- 起步 allow-by-default + 阻断名单(kind=host|path_prefix);引擎接口隔离,后续可换 ML/采购规则源。

CREATE TABLE IF NOT EXISTS swg_rules (
  id         uuid        PRIMARY KEY,
  tenant_id  uuid        NOT NULL,
  kind       text        NOT NULL,            -- host | path_prefix
  pattern    text        NOT NULL,            -- 如 "evil.com" | "/admin"
  action     text        NOT NULL DEFAULT 'block', -- 起步仅 block(allow 为默认)
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_swg_rules_tenant ON swg_rules (tenant_id);

ALTER TABLE swg_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE swg_rules FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON swg_rules;
CREATE POLICY tenant_isolation ON swg_rules
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON swg_rules TO app_rw;
GRANT SELECT ON swg_rules TO app_ro;
