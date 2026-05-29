-- 0019 PoP 节点注册 + 平台写池角色(Slice38a,PC-API-3 平台后端铺路)。
-- 设计:
--   ① PoP 节点 = **平台级共享基础设施**(非租户数据,无 tenant_id;租户/PoP 是 N:M 调度)
--      → pop_nodes **无 RLS**(没有租户维度可隔离);访问治理靠**专用平台写池角色**最小权限。
--   ② 新加 app_platform_rw 角色:与 app_platform_ro 形成对称(只读↔只写),
--      仅授 platform 表的 RW;**无任何 tenant 表 GRANT** → 误写租户表 → permission denied 兜底
--      (后续刀 38c/d:平台 RBAC、CA·KEK 双人控制等高敏感平台写复用此角色,避免堆到 app_rw)。
--   ③ DB 审计可按 PG role 区分「平台运维」vs「租户业务」(等保按主体维度分)。
--
-- ⚠️ 部署:`SASE_DB_PLATFORM_RW_DSN` 经此角色连接;开发期密码占位,生产经 secret 注入。

-- 平台写角色:NOBYPASSRLS(它会触及任何 RLS 表都被拒,纵深);仅授**平台白名单表**。
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_platform_rw') THEN
    CREATE ROLE app_platform_rw LOGIN PASSWORD 'app_platform_rw_dev' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END$$;

-- PoP 节点表:平台全局,无 RLS。字段最小子集(L1 3.7 PoP 单元、3.13 部署):
--   name      运营标识(机房代号/编号,unique 防重)
--   region    地域(用于调度/合规分区)
--   endpoint  PoP 入口公网地址(host:port 或 URL,供 Agent/CPE 端点发现)
--   max_users 容量上限(可空 = 未限,部署期填)
--   status    生命周期:active(在用)/ draining(下线中,新会话不调度)/ down(故障)
--   last_seen_at  PoP heartbeat 最近时间(Slice38a 不上报,留字段供后续刀填)
-- 不含:tenant_id(平台级)、密钥(走 PKI/secret 独立)、详细配置(走 xDS)。
CREATE TABLE IF NOT EXISTS pop_nodes (
  id            uuid        PRIMARY KEY,
  name          text        NOT NULL UNIQUE,
  region        text        NOT NULL,
  endpoint      text        NOT NULL,
  max_users     int                  CHECK (max_users IS NULL OR max_users >= 0),
  status        text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'draining', 'down')),
  last_seen_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pop_nodes_status ON pop_nodes (status);
CREATE INDEX IF NOT EXISTS idx_pop_nodes_region ON pop_nodes (region);

-- updated_at 自动维护(无须 audit_tr,平台级 audit 在另一张表,Slice38a 之后做)。
CREATE OR REPLACE FUNCTION pop_nodes_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END$$;
DROP TRIGGER IF EXISTS pop_nodes_touch ON pop_nodes;
CREATE TRIGGER pop_nodes_touch BEFORE UPDATE ON pop_nodes
  FOR EACH ROW EXECUTE FUNCTION pop_nodes_touch_updated_at();

-- 权限:
--   app_platform_rw:全 CRUD(平台运维)
--   app_platform_ro:只读(平台看板/列表;与 tenant_summary 同侧)
--   app_rw / app_ro:**不授**(租户路径不应见平台表;若误查 → permission denied 兜底)
GRANT SELECT, INSERT, UPDATE, DELETE ON pop_nodes TO app_platform_rw;
GRANT SELECT ON pop_nodes TO app_platform_ro;

COMMENT ON TABLE pop_nodes IS 'platform-global PoP registry (Slice38a, PC-API-3); no RLS; managed by app_platform_rw; read by app_platform_ro';

-- 部署自检(防沉默失败,对称 0013 视图 owner 自检):
-- app_platform_rw 是平台高敏感写池,Slice38c/d CA·KEK 双人控制会复用——若有人手工或后续 migration
-- 误给它 BYPASSRLS / superuser,会让"租户表 RLS 兜底"纵深 1 失效;此处把该隐患转为响亮迁移失败。
DO $$
DECLARE
  v_bypass bool;
  v_super  bool;
BEGIN
  SELECT rolbypassrls, rolsuper INTO v_bypass, v_super FROM pg_roles WHERE rolname = 'app_platform_rw';
  IF COALESCE(v_bypass, false) OR COALESCE(v_super, false) THEN
    RAISE EXCEPTION 'app_platform_rw 不应有 BYPASSRLS/SUPERUSER(否则误访租户表 RLS 兜底失效;数据访问层 L2 § app_platform_rw 设计)';
  END IF;
END$$;
