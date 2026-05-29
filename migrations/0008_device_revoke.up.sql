-- 0008 设备入网撤销:为 device_enrollments.status 增 'revoked',支撑证书续期闸(L1 3.5 PKI/吊销)。
-- 模型:ZTP 证书短期(24h)+ 续期需当前有效证书 mTLS 认证 + 续期校验入网记录仍 'redeemed';
-- admin 撤销设备 → status='revoked' → 续期被拒 → 设备在 ≤证书有效期内自然掉线(有界时间撤销,无需设备 CRL)。

ALTER TABLE device_enrollments DROP CONSTRAINT IF EXISTS chk_enroll_status;
ALTER TABLE device_enrollments ADD  CONSTRAINT chk_enroll_status
  CHECK (status IN ('pending','redeemed','revoked'));
