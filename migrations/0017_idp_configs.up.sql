-- 0017 IdP 配置(L1 3.4:OIDC/SAML + 企微/钉钉/飞书三家国产 IdP 适配)。
-- **本表是 secret 模块首个真加密消费者**(Slice36):client_secret 经租户 DEK(secret 模块)加密后落库。
-- 当租户进入注销宽限期末 → sweep 销毁 DEK → 本表所有 encrypted_client_secret 等效不可恢复
-- (印证 L1 3.16 密钥销毁式删除工程链路:Slice33c+34+35 的"硬删"此刻有真实效果)。
--
-- 注:本刀仅持久化 + CRUD;真实 OIDC/SAML adapter(跳转/回调/换 IdP 令牌)= Slice37+ 单独刀。
CREATE TABLE IF NOT EXISTS idp_configs (
  id                       uuid          PRIMARY KEY,
  tenant_id                uuid          NOT NULL,
  name                     text          NOT NULL,                  -- 人类可读名(如"企业微信 OIDC")
  kind                     text          NOT NULL,                  -- oidc/wecom/dingtalk/feishu(与 OpenAPI/oidc.Kind* 同源,validateCreate 白名单校验)
  endpoint                 text          NOT NULL,                  -- IdP issuer URL / SAML SSO URL
  client_id                text          NOT NULL,                  -- 客户端 ID(非密,明文)
  encrypted_client_secret  bytea         NOT NULL,                  -- **DEK 加密**(secret 模块,ChaCha20-Poly1305,nonce(12B)||ct+tag(16B))
  status                   text          NOT NULL DEFAULT 'active', -- active / disabled
  extra                    jsonb         NOT NULL DEFAULT '{}',     -- provider-specific(scopes/certs 等)
  created_at               timestamptz   NOT NULL DEFAULT now(),
  updated_at               timestamptz   NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_idp_configs_tenant ON idp_configs (tenant_id);

ALTER TABLE idp_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp_configs FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON idp_configs;
CREATE POLICY tenant_isolation ON idp_configs
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- 审计触发器(IdP 配置变更属敏感运维事件,密钥销毁式删除涉及范围之一)。
DROP TRIGGER IF EXISTS audit_tr ON idp_configs;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON idp_configs
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

GRANT SELECT, INSERT, UPDATE, DELETE ON idp_configs TO app_rw;
GRANT SELECT ON idp_configs TO app_ro;
