-- 0008 down:status 去掉 'revoked'(回退到 pending/redeemed)。注意:执行前须无 status='revoked' 行。
ALTER TABLE device_enrollments DROP CONSTRAINT IF EXISTS chk_enroll_status;
ALTER TABLE device_enrollments ADD  CONSTRAINT chk_enroll_status
  CHECK (status IN ('pending','redeemed'));
