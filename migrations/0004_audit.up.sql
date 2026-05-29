-- 0004 审计日志:管理面操作留痕(等保合规;配套 Slice 9 RBAC)。租户作用域、RLS 强隔离。
-- tenant_id = 操作目标租户(平台级建租户记在被建租户名下)。append-only(无 UPDATE/DELETE 授权)。

CREATE TABLE IF NOT EXISTS audit_log (
  id            uuid        PRIMARY KEY,
  tenant_id     uuid        NOT NULL,
  ts            timestamptz NOT NULL DEFAULT now(),
  actor_subject text        NOT NULL,            -- 操作者(admin 令牌 subject)
  actor_role    text        NOT NULL,            -- platform_admin / tenant_admin / auditor
  action        text        NOT NULL,            -- "POST /api/v1/tenants/{tid}/credentials"
  result        int         NOT NULL,            -- HTTP 状态码
  detail        text        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_log (tenant_id, ts DESC);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON audit_log;
CREATE POLICY tenant_isolation ON audit_log
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- 授权:app_rw 仅 INSERT + SELECT(append-only,不授 UPDATE/DELETE);app_ro 只读。
GRANT SELECT, INSERT ON audit_log TO app_rw;
GRANT SELECT ON audit_log TO app_ro;
