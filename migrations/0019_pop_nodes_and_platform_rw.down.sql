DROP TRIGGER IF EXISTS pop_nodes_touch ON pop_nodes;
DROP FUNCTION IF EXISTS pop_nodes_touch_updated_at();
DROP TABLE IF EXISTS pop_nodes;
-- 角色不删(可能被其它会话占用);手工清理:DROP ROLE app_platform_rw;
