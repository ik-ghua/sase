-- 0011 CASB-DLP 规则:安全能力 DLP(P5)的每租户敏感数据规则(安全栈 L2)。租户作用域、RLS。
-- 关键词/正则匹配 + action block(阻断)/alert(告警+喂风险);执行点 PoP L7 inspect(与 SWG 同检查点)。
-- 起步规则匹配;指纹/ML/采购规则源后续(接口隔离)。内容源生产经 Envoy ext_proc 取 body。

CREATE TABLE IF NOT EXISTS dlp_rules (
  id         uuid        PRIMARY KEY,
  tenant_id  uuid        NOT NULL,
  name       text        NOT NULL,
  match_type text        NOT NULL,            -- keyword | regex
  pattern    text        NOT NULL,
  action     text        NOT NULL DEFAULT 'alert', -- block | alert
  severity   text        NOT NULL DEFAULT 'medium', -- low | medium | high
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_dlp_match    CHECK (match_type IN ('keyword','regex')),
  CONSTRAINT chk_dlp_action   CHECK (action     IN ('block','alert')),
  CONSTRAINT chk_dlp_severity CHECK (severity   IN ('low','medium','high'))
);
CREATE INDEX IF NOT EXISTS idx_dlp_rules_tenant ON dlp_rules (tenant_id);

ALTER TABLE dlp_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_rules FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON dlp_rules;
CREATE POLICY tenant_isolation ON dlp_rules
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON dlp_rules TO app_rw;
GRANT SELECT ON dlp_rules TO app_ro;
