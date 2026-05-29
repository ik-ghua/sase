-- 0003 资源注册 + 撤销:apps/connectors(L1 3.3 Resource)+ revocations(秒级失效,ZTNA 硬化 L2 3.4)。
-- 均租户作用域、RLS 强隔离(同 0001/0002 语义,fail-closed)。

-- ZTNA 应用注册:app_key 是策略 resource 字段引用的逻辑键(编译器校验引用存在性,编译器 L2 3.3①)。
CREATE TABLE IF NOT EXISTS apps (
  id         uuid        PRIMARY KEY,
  tenant_id  uuid        NOT NULL,
  app_key    text        NOT NULL,            -- 策略引用键(如 "app1")
  name       text        NOT NULL,
  upstream   text        NOT NULL DEFAULT '', -- 上游地址(信息性;反向通道由连接器建立)
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_apps_tenant_key ON apps (tenant_id, app_key);

-- App Connector 定义(哪个连接器服务哪个 app;定义性注册,数据面反向通道仍由连接器拨入建立)。
CREATE TABLE IF NOT EXISTS connectors (
  id         uuid        PRIMARY KEY,
  tenant_id  uuid        NOT NULL,
  app_key    text        NOT NULL,
  name       text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors (tenant_id);

-- 撤销的会话凭证(by jti):PoP 验凭证后查吊销集,命中即拒(可达时秒级;短 TTL 为不可达兜底)。
CREATE TABLE IF NOT EXISTS revocations (
  tenant_id  uuid        NOT NULL,
  jti        text        NOT NULL,            -- 凭证唯一标识(cred.Claims.JTI)
  subject    text        NOT NULL DEFAULT '',
  reason     text        NOT NULL DEFAULT '',
  revoked_at timestamptz NOT NULL DEFAULT now(),
  expire_at  timestamptz NOT NULL,            -- = 凭证原 exp;过期后吊销项可 GC(凭证本就失效)
  PRIMARY KEY (tenant_id, jti)
);

-- RLS:ENABLE + FORCE + 租户隔离。
ALTER TABLE apps        ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps        FORCE  ROW LEVEL SECURITY;
ALTER TABLE connectors  ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors  FORCE  ROW LEVEL SECURITY;
ALTER TABLE revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE revocations FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON apps;
CREATE POLICY tenant_isolation ON apps
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON connectors;
CREATE POLICY tenant_isolation ON connectors
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON revocations;
CREATE POLICY tenant_isolation ON revocations
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- 授权:app_rw 读写、app_ro 只读(xds-server 用 app_ro 读吊销表下发)。
GRANT SELECT, INSERT, UPDATE, DELETE ON apps, connectors, revocations TO app_rw;
GRANT SELECT ON apps, connectors, revocations TO app_ro;
