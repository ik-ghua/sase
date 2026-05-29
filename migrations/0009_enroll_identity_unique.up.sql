-- 0009 设备身份租户内唯一:把 device_enrollments 唯一键从 (tenant_id, kind, identity) 收紧为 (tenant_id, identity)。
-- 动机:续期/撤销时身份只来自对端证书 CN(=identity),证书不带 kind,无法按 kind 消歧;若同租户允许
-- connector 与 cpe 同名 identity,会致撤销误伤/绕过(评审 B1)。证书 subject 作为 mTLS 身份须租户内无歧义。
-- kind 仍保留为属性(用途/审计),只是不再参与唯一性。

ALTER TABLE device_enrollments DROP CONSTRAINT IF EXISTS uq_enroll_identity;       -- 旧:若以约束存在
DROP INDEX IF EXISTS uq_enroll_identity;                                            -- 旧:以唯一索引存在(0007 建法)
CREATE UNIQUE INDEX IF NOT EXISTS uq_enroll_identity ON device_enrollments (tenant_id, identity);
