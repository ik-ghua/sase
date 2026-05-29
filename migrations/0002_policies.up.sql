-- 0002 policies:编写态策略 + 编译态 PolicyBundle(策略编译器 L2 3.1/3.7)。
-- 均租户作用域、RLS 强隔离;编译态保证「每租户至多一个激活版」(3.7 原子激活)。

-- 编写态策略(租户管理员编写;subject 保持选择器、不展开,编译器 L2 3.1)。
CREATE TABLE IF NOT EXISTS policies (
  id            uuid        PRIMARY KEY,
  tenant_id     uuid        NOT NULL,
  name          text        NOT NULL,
  priority      int         NOT NULL DEFAULT 100,  -- 小=高优先(3.2 优先级序内首次匹配)
  subject_kind  text        NOT NULL,              -- user / group / posture(选择器类型)
  subject_value text        NOT NULL,              -- 选择器值(如 group id、姿态谓词)
  resource      text        NOT NULL,              -- ZTNA 应用 id / FQDN
  action        text        NOT NULL,              -- connect / http-get ...
  effect        text        NOT NULL,              -- allow / deny / inspect(3.1)
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);

-- 编译态产物(L1 3.3 PolicyBundle 字段 + 本子 L2 新增 content_hash,编译器 L2 3.7)。
CREATE TABLE IF NOT EXISTS policy_bundles (
  id           uuid        PRIMARY KEY,
  tenant_id    uuid        NOT NULL,
  version      bigint      NOT NULL,               -- 每租户单调递增
  content_hash text        NOT NULL,               -- sha256(compiled),幂等(3.7)
  compiled     bytea       NOT NULL,               -- 编译产物(Slice 2:L7 规则 JSON;生产为自定义 xDS 资源)
  status       text        NOT NULL DEFAULT 'active', -- active / rolled_back(严格沿用 L1 3.3)
  created_at   timestamptz NOT NULL DEFAULT now()
);
-- 版本单调:每租户 version 唯一。
CREATE UNIQUE INDEX IF NOT EXISTS uq_bundle_tenant_version ON policy_bundles (tenant_id, version);
-- 原子激活:每租户至多一个 active(部分唯一索引,3.7)。插新激活版必须同事务降级旧版,否则违约。
CREATE UNIQUE INDEX IF NOT EXISTS uq_bundle_tenant_active ON policy_bundles (tenant_id) WHERE status = 'active';

-- RLS:ENABLE + FORCE + 租户隔离策略(同 0001 语义,fail-closed)。
ALTER TABLE policies       ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies       FORCE  ROW LEVEL SECURITY;
ALTER TABLE policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_bundles FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON policies;
CREATE POLICY tenant_isolation ON policies
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON policy_bundles;
CREATE POLICY tenant_isolation ON policy_bundles
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- 授权:app_rw 读写、app_ro 只读(xds-server 用 app_ro 按租户读编译产物,xDS server L2 3.3/3.9)。
GRANT SELECT, INSERT, UPDATE, DELETE ON policies, policy_bundles TO app_rw;
GRANT SELECT ON policies, policy_bundles TO app_ro;
