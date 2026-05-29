-- 0016 down:删 tenant_keys(包括 RLS 策略 + 授权随表删)。
DROP TRIGGER IF EXISTS audit_tr ON tenant_keys;
REVOKE SELECT, INSERT, UPDATE ON tenant_keys FROM app_rw;
REVOKE SELECT ON tenant_keys FROM app_ro;
DROP TABLE IF EXISTS tenant_keys;
