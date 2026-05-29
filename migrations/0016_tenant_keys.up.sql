-- 0016 租户密钥(信封加密 DEK,L1 3.5)。每租户一把 DEK,由 KEK 包裹(wrapped_dek)持久化;
-- KEK 仅在 secret 模块 Provider 内(dev=内存 master key;生产=KMS/HSM,R7 选型衍生)。**KEK 不入库**。
--
-- 本表是"硬删 DEK"(L1 3.16 密钥销毁式删除,不可逆)的载体:destroy 时 wrapped_dek→NULL + destroyed_at=now()
-- → 即便他人持 wrapped_dek 副本,无 KEK 仍不可解密,数据等效失能(若有加密数据用本 DEK)。
--
-- **诚实状态(Slice34):** 当前**无任何业务数据用本 DEK 加密**(IdPConfig 等未建);本表是"基础设施先于消费者"
-- 的密钥生命周期载体,未来加密数据用户(secret-bearing 字段)接入即用。
CREATE TABLE IF NOT EXISTS tenant_keys (
  tenant_id      uuid          PRIMARY KEY REFERENCES tenants(id),  -- 1:1 租户↔DEK
  alg            text          NOT NULL,                            -- DEK 算法(当前 chacha20poly1305;crypto-agility)
  kek_id         text          NOT NULL,                            -- 包裹 DEK 的 KEK 标识(dev="dev-mem";生产=KMS key id),供未来 KEK 轮换/解包路由
  wrapped_dek    bytea,                                             -- KEK 包裹的 DEK 密文(destroy 后置 NULL,密钥销毁式删除)
  created_at     timestamptz   NOT NULL DEFAULT now(),
  destroyed_at   timestamptz                                        -- NULL=活;非 NULL=已销毁,不可逆
);

-- 销毁状态不变量:**destroyed_at NULL ↔ wrapped_dek 非 NULL**(销毁与未销毁是二元,不可"半销毁")。
-- 防外部 DML 制造不一致态(reviewer Slice34 B1);代码读取也只需查一列即可判定状态。
ALTER TABLE tenant_keys DROP CONSTRAINT IF EXISTS tenant_keys_destruction_chk;
ALTER TABLE tenant_keys ADD CONSTRAINT tenant_keys_destruction_chk
  CHECK ((destroyed_at IS NULL) = (wrapped_dek IS NOT NULL));
CREATE INDEX IF NOT EXISTS idx_tenant_keys_destroyed ON tenant_keys (destroyed_at) WHERE destroyed_at IS NOT NULL;

ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON tenant_keys;
CREATE POLICY tenant_isolation ON tenant_keys
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- 审计触发器(0012 通用 audit_row,source=data):密钥生命周期(create/destroy)经业务事务原子记审计——
-- DEK 销毁是 L1 3.16 密钥销毁式删除的工程载体,**高敏感事件须留痕**;detail 仅记 id=tenant_id,不落 wrapped。
DROP TRIGGER IF EXISTS audit_tr ON tenant_keys;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON tenant_keys
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

-- 授权:app_rw 写、app_ro 读;app_platform_ro 不授权(平台跨租户路径不应见 wrapped DEK)。
-- **wrapped_dek 安全性来自 KEK 与 wrapped 的分离**(KEK 仅在 secret 模块/KMS,不入库),wrapped 落 app_rw/app_ro
-- 可读不破安全(无 KEK 不可解);模块边界由代码内 internal/secret 唯一访问点保证。
GRANT SELECT, INSERT, UPDATE ON tenant_keys TO app_rw;
GRANT SELECT ON tenant_keys TO app_ro;
-- 注:app_rw 范围内仍靠 internal/secret 模块边界确保仅本模块访问(代码层);DB 层不再细分专用角色(避免引入第 4 个池)。
-- 安全模型说明:**信封加密的安全性来自 KEK 与 wrapped_dek 的分离**——KEK 仅在 secret 模块内存/KMS、不入库;
-- 即便 app_rw 任意模块读到 wrapped_dek,无 KEK 仍不可解,等效噪声。
