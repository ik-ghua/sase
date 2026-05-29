-- 0021 platform_audit_log:平台级操作审计(Slice38c CA·KEK 前置硬要求,Slice38a S3 TODO 锚)。
--
-- 与 audit_log(tenant-scoped)对称,但**无 tenant_id**(平台事件不属于任何租户)。
-- 适用范围:PoP CRUD(Slice38a)、未来平台 RBAC(Slice38c)、CA·KEK 双人控制(Slice38d)等。
-- target_tenant_id 可选(平台对某租户的操作时关联,如平台管理员代签 admin token——但当前 Slice33e
-- 已落 target tenant 的 audit_log,本字段为未来"平台 admin 操作 target=租户"扩展预留)。
--
-- 双层审计(与 audit_log 同模式,Slice29):
--   source=data  DB 触发器(挂 pop_nodes/未来平台白名单表)业务事务内原子写,result=0 哨兵
--   source=api   handler/middleware 显式写(含失败/2xx-零变更),result=HTTP 码

CREATE TABLE IF NOT EXISTS platform_audit_log (
  id               uuid        PRIMARY KEY,
  ts               timestamptz NOT NULL DEFAULT now(),
  actor_subject    text        NOT NULL,
  actor_role       text        NOT NULL,
  action           text        NOT NULL,
  result           int         NOT NULL,
  detail           text        NOT NULL DEFAULT '',
  source           text        NOT NULL CHECK (source IN ('api', 'data')),
  target_tenant_id uuid                                    -- 可选;平台对某租户操作时关联
);
CREATE INDEX IF NOT EXISTS idx_platform_audit_ts    ON platform_audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_platform_audit_actor ON platform_audit_log (actor_subject);

-- 权限:
--   app_platform_rw:INSERT(handler 显式写 + 触发器经事务写)+ SELECT(handler 查列表用 InPlatformTxRW 时也可)
--   app_platform_ro:SELECT(平台审计读端点经 InPlatformTx)
--   app_rw / app_ro:**不授权**(租户路径不应见平台审计;触发器只挂平台表,不会被租户写路径误触发)
GRANT INSERT, SELECT ON platform_audit_log TO app_platform_rw;
GRANT SELECT          ON platform_audit_log TO app_platform_ro;

COMMENT ON TABLE platform_audit_log IS 'platform-global audit log (Slice38a-S3 / Slice39); no RLS; written by app_platform_rw, read by app_platform_ro';

-- 通用平台审计触发器函数:
--   行级 AFTER INSERT/UPDATE/DELETE,从 per-tx GUC 取 actor(对齐 Slice29 audit_row 模式;
--   InPlatformTxRW 已设 app.current_actor / app.current_actor_role)。
CREATE OR REPLACE FUNCTION platform_audit_row() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  v_actor       text := current_setting('app.current_actor',      true);
  v_actor_role  text := current_setting('app.current_actor_role', true);
  v_action      text;
  v_row_id      text;
BEGIN
  IF v_actor      IS NULL OR v_actor      = '' THEN v_actor      := 'system'; END IF;
  IF v_actor_role IS NULL OR v_actor_role = '' THEN v_actor_role := 'system'; END IF;
  v_action := TG_OP || ' ' || TG_TABLE_NAME;
  -- 行 id 入 detail(挂在的平台表均 uuid PK 命名 id;便审计读端定位具体行)
  IF TG_OP = 'DELETE' THEN
    v_row_id := COALESCE((to_jsonb(OLD)->>'id'), '');
  ELSE
    v_row_id := COALESCE((to_jsonb(NEW)->>'id'), '');
  END IF;
  INSERT INTO platform_audit_log (id, actor_subject, actor_role, action, result, detail, source)
    VALUES (gen_random_uuid(), v_actor, v_actor_role, v_action, 0, 'id=' || v_row_id, 'data');
  RETURN COALESCE(NEW, OLD);
END$$;

-- 挂到 pop_nodes(Slice38a)。未来 Slice38c/d 新加平台表(ca_ops/platform_rbac/...)时同样挂。
DROP TRIGGER IF EXISTS platform_audit_tr ON pop_nodes;
CREATE TRIGGER platform_audit_tr
  AFTER INSERT OR UPDATE OR DELETE ON pop_nodes
  FOR EACH ROW EXECUTE FUNCTION platform_audit_row();

-- 自检(评审 B3):触发器 detail='id='+to_jsonb(NEW)->>'id' 依赖挂表 PK 列名为 'id'。
-- 后续刀新加平台表时若 PK 命名为 'ca_op_id'/'rbac_id' 等,detail 会沉默退化为 'id='(空)而非显式报错。
-- 此处把"挂 platform_audit_tr 的表必须有 id 列"做成响亮迁移失败(对称 0019 角色 BYPASSRLS 自检)。
DO $$
DECLARE
  v_table     name;
  v_has_id    bool;
BEGIN
  FOR v_table IN
    SELECT c.relname
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
    WHERE t.tgname = 'platform_audit_tr' AND NOT t.tgisinternal
  LOOP
    SELECT EXISTS (
      SELECT 1 FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
      WHERE c.relname = v_table AND a.attname = 'id' AND a.attnum > 0 AND NOT a.attisdropped
    ) INTO v_has_id;
    IF NOT v_has_id THEN
      RAISE EXCEPTION '挂 platform_audit_tr 的表 % 必须有 id 列(触发器 detail 依赖,见 platform_audit_row 注释)', v_table;
    END IF;
  END LOOP;
END$$;
