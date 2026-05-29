-- 0013 down:删平台视图 + 收回授权 + 删角色(角色删除前须无依赖对象/连接)。
REVOKE SELECT ON tenant_summary FROM app_platform_ro;
DROP VIEW IF EXISTS tenant_summary;
-- 角色删除:生产须先确认无该角色拥有的对象/活动连接;dev 直接删。
DROP ROLE IF EXISTS app_platform_ro;
