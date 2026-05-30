-- 0025 device_enrollments 支持 ZTNA Agent 形态(Slice 80,L2 docs/sase-l2-ztna-agent.md §3.10.1)。
-- 真 OS 级 ZTNA Agent 的 per-user IdP 入网:Agent 经 /agent/enroll 编排(IdP 认证 → 设备 CSR 签证),
-- 设备入网记录的 kind 增 'agent'(放宽,Connector/CPE 不破),并关联签发该证书时的 SASE user(可空)。
--
-- 身份分层(不混):设备证书 CN=device-id、Org=tenant(**设备身份**;一台设备可多用户登录);
-- 会话凭证 Subject=user.ID(**用户身份**)。device↔user 关联落本表 user_id 列(Connector/CPE 为 NULL)。

-- ① kind CHECK 增 'agent'(幂等 DROP+ADD,对齐 0008/0009 写法)。
ALTER TABLE device_enrollments DROP CONSTRAINT IF EXISTS chk_enroll_kind;
ALTER TABLE device_enrollments ADD  CONSTRAINT chk_enroll_kind
  CHECK (kind IN ('connector','cpe','agent'));

-- ② user_id 关联签发时的 SASE 用户(可空:Connector/CPE 无 user;ON DELETE SET NULL:删用户后记录保留,关联置空)。
ALTER TABLE device_enrollments ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_enroll_user ON device_enrollments (tenant_id, user_id);

COMMENT ON COLUMN device_enrollments.user_id IS 'Agent 入网时关联的 SASE 用户(可空;Connector/CPE 为 NULL);与会话凭证 Subject 同源(Slice80 cert↔cred 双绑定)';
-- RLS 不变(沿用 0007 tenant_isolation;新列受同一策略约束)。app_rw 已有 INSERT/UPDATE(0007 GRANT),无需新授权。
