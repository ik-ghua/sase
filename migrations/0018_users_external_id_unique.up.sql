-- 0018 users_external_id_unique:为 (tenant_id, external_id) 加唯一约束。
-- 触发场景:Slice37a OIDC 登录 EnsureUserByExternalID(并发同时建相同 external_id 的两次回调,
-- 需 DB 单点强约束兜底;否则会出现"同一 IdP 用户在租户内有两条 SASE 用户行",
-- 后续登录非确定性命中)。
-- (tenant_id, external_id) 联合:不同租户的同一 external_id 各自合法。
ALTER TABLE users ADD CONSTRAINT users_tenant_ext_unique UNIQUE (tenant_id, external_id);
