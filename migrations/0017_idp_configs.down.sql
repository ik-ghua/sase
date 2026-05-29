-- 0017 down:删表(随表删 RLS 策略、索引、触发器、授权)。
DROP TRIGGER IF EXISTS audit_tr ON idp_configs;
DROP TABLE IF EXISTS idp_configs;
