-- 0009 down:唯一键回退为 (tenant_id, kind, identity)。
DROP INDEX IF EXISTS uq_enroll_identity;
CREATE UNIQUE INDEX IF NOT EXISTS uq_enroll_identity ON device_enrollments (tenant_id, kind, identity);
