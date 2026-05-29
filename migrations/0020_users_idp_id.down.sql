-- ⚠️ 单向门警告(Slice37b-1 评审 B2):若生产已利用本刀新能力录入了「同租户两个 IdP 都签到了 sub=user1 的用户」,
-- ADD CONSTRAINT (tenant_id, external_id) UNIQUE 会因冲突直接失败并部分回滚。回退前自检:
--   SELECT tenant_id, external_id, count(*) FROM users GROUP BY 1,2 HAVING count(*)>1;
-- 多 IdP 上线后,本 down 仅适用于"刚发布即回退"窗口期。
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_idp_ext_unique;
ALTER TABLE users ADD CONSTRAINT users_tenant_ext_unique UNIQUE (tenant_id, external_id);
DROP INDEX IF EXISTS idx_users_tenant_idp;
ALTER TABLE users DROP COLUMN IF EXISTS idp_id;
