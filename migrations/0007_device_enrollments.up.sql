-- 0007 设备入网(ZTP):Connector/CPE 凭激活码 + CSR 换取租户绑定证书(L1 3.5 自建 PKI/ZTP、3.11 入网契约)。
-- 私钥由设备本地生成(CSR 流程),永不离开;控制面只签发,把 tenant 编进证书 Organization。租户作用域、RLS。
-- 激活码一次性:redeemed 后不可复用(防重放);kind 区分 connector(ZTNA)/cpe(SD-WAN)。

CREATE TABLE IF NOT EXISTS device_enrollments (
  id              uuid        PRIMARY KEY,
  tenant_id       uuid        NOT NULL,
  kind            text        NOT NULL,            -- 'connector' | 'cpe'
  identity        text        NOT NULL,            -- 签入证书 CommonName(connector app / cpe site_key)
  activation_code text        NOT NULL,            -- 一次性激活码(设备凭此 + CSR 换证书)
  status          text        NOT NULL DEFAULT 'pending', -- 'pending' | 'redeemed'
  redeemed_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_enroll_kind   CHECK (kind   IN ('connector','cpe')),
  CONSTRAINT chk_enroll_status CHECK (status IN ('pending','redeemed'))
);
-- 激活码全局唯一(兑换端点无租户上下文,凭码定位租户);租户内同 kind+identity 唯一。
CREATE UNIQUE INDEX IF NOT EXISTS uq_enroll_code     ON device_enrollments (activation_code);
CREATE UNIQUE INDEX IF NOT EXISTS uq_enroll_identity ON device_enrollments (tenant_id, kind, identity);

ALTER TABLE device_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_enrollments FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON device_enrollments;
CREATE POLICY tenant_isolation ON device_enrollments
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON device_enrollments TO app_rw;
GRANT SELECT ON device_enrollments TO app_ro;
