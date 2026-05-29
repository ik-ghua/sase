DROP TRIGGER IF EXISTS platform_audit_tr ON platform_admins;
DROP TRIGGER IF EXISTS platform_admins_touch_tr ON platform_admins;
DROP FUNCTION IF EXISTS platform_admins_touch();
DROP TABLE IF EXISTS platform_admins;
