-- 0020 users.idp_id + 重建 UNIQUE 约束(Slice37b-1,多 IdP 支持前置)。
-- ⚠️ **最低 PG 版本 15**(NULLS NOT DISTINCT 语法,2022 GA);本检查把版本依赖做成响亮失败,
-- 否则 PG ≤14 上跑会撞 SQL parser error 让人摸不到头脑。
DO $$
BEGIN
  IF current_setting('server_version_num')::int < 150000 THEN
    RAISE EXCEPTION '0020 migration requires PostgreSQL >= 15 (NULLS NOT DISTINCT); current=% (see docs/sase-l2-cp-data-access-rls.md)', current_setting('server_version');
  END IF;
END$$;

-- 背景:Slice37a UNIQUE(tenant_id, external_id) 在同租户配多个 IdP 时(企微+钉钉同时启用),
-- 不同 IdP 间 sub 字符串可能撞车(如企微 "wx-1234" 与钉钉自家 "wx-1234")→ 被合并成同一 SASE 用户。
-- 修复:加 idp_id 列(FK→idp_configs,可空兼容 ZTNA/管理员手建用户),UNIQUE 改 (tenant_id, idp_id, external_id);
-- NULLS NOT DISTINCT(PG15+)保证 idp_id=NULL 的多条手建用户仍受 (tenant_id, external_id) 唯一约束(不退化)。

-- ① 加 idp_id 列(可空;ZTNA 路径/管理员手建用户不带 IdP);ON DELETE SET NULL:删 IdP 配置后,该 IdP 的用户行保留,idp_id 置空(用户仍在,后续可改绑 IdP)。
ALTER TABLE users ADD COLUMN idp_id uuid REFERENCES idp_configs(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_users_tenant_idp ON users (tenant_id, idp_id);

-- ② 删旧 UNIQUE,加新 UNIQUE NULLS NOT DISTINCT 三元组。
-- NULLS NOT DISTINCT 语义:NULL 等于 NULL → idp_id=NULL 时仍按 (tenant_id, external_id) 唯一;
-- 不同 IdP 同 external_id 各自合法(三元组才唯一)。
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_ext_unique;
ALTER TABLE users ADD CONSTRAINT users_tenant_idp_ext_unique
  UNIQUE NULLS NOT DISTINCT (tenant_id, idp_id, external_id);

COMMENT ON COLUMN users.idp_id IS 'IdP 配置 ID(可空;ZTNA/手建用户无 IdP);唯一约束 (tenant_id, idp_id, external_id) NULLS NOT DISTINCT(Slice37b-1 多 IdP 支持)';
