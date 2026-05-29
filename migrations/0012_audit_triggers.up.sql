-- 0012 审计事务化(方案 A:DB 触发器)。把「凡变更必留痕」做成数据库层不可绕过的不变量:
-- 受审计的租户业务表挂 AFTER INSERT/UPDATE/DELETE 行级触发器,在**触发它的业务事务内**原子写
-- audit_log(业务回滚则审计回滚)。actor/role 经 per-tx GUC(app.current_actor[_role])传入(data 层设)。
-- 见 docs/sase-l2-audit-transactional.md(方案 A,INVOKER 权限、两层分工、排除高频表)。

-- gen_random_uuid():PG13+ core 自带;为兼容更低版本/受限镜像显式兜底(本迁移以 DB owner/superuser 应用)。
-- 事务化把「审计写失败」放大为「业务变更失败」,故该函数可用性须做成硬前提(go-code-reviewer Slice29 建议)。
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── 两层审计分工:source 区分来源 ──────────────────────────────────────────────
--   'data' = 本触发器写(数据变更级、原子、权威;result=0 哨兵、action='TG_OP 表名')
--   'api'  = HTTP 中间件写(API 动作级、best-effort;含失败/无变更尝试,result=HTTP 码)
-- 既有行(中间件写)默认 'api'。source 同时消解「result=0 哨兵 vs 真实 HTTP 码」的同列混义。
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'api';
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_source_chk;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_source_chk CHECK (source IN ('api', 'data'));

-- ── 通用触发器函数(INVOKER:以 app_rw 身份在业务事务内写,受 audit_log RLS WITH CHECK 兜底)──
--   TG_ARGV[0] = 该表租户 id 所在列名(tenants='id',其余业务表='tenant_id')。
--   以 to_jsonb 按列名动态取值,使单一函数适配所有受审计表(无每表定制)。
CREATE OR REPLACE FUNCTION audit_row() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  rec  jsonb;
  tcol text := TG_ARGV[0];
  tid  text;
  rid  text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    rec := to_jsonb(OLD);
  ELSE
    rec := to_jsonb(NEW);
  END IF;
  tid := rec ->> tcol;          -- 租户 id(取自行,与 RLS WITH CHECK 同源)
  rid := rec ->> 'id';          -- 行标识(detail 只记 id,不落整行值,避免 PII 入审计)
  INSERT INTO audit_log (id, tenant_id, actor_subject, actor_role, action, result, detail, source)
  VALUES (
    gen_random_uuid(),
    tid::uuid,
    COALESCE(current_setting('app.current_actor', true), ''),                 -- 无 HTTP 主体→空
    COALESCE(NULLIF(current_setting('app.current_actor_role', true), ''), 'system'),
    TG_OP || ' ' || TG_TABLE_NAME,                                            -- 数据变更级动作
    0,                                                                        -- 数据变更类:result 不适用,置 0 哨兵
    COALESCE('id=' || rid, ''),
    'data'
  );
  RETURN NULL;  -- AFTER 触发器返回值被忽略
END;
$$;

-- ── 挂触发器:租户业务变更表 ──────────────────────────────────────────────────
-- tenants 的租户 id 是 id 列;其余业务表是 tenant_id 列。
DROP TRIGGER IF EXISTS audit_tr ON tenants;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON tenants
  FOR EACH ROW EXECUTE FUNCTION audit_row('id');

DROP TRIGGER IF EXISTS audit_tr ON users;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

DROP TRIGGER IF EXISTS audit_tr ON apps;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON apps
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

DROP TRIGGER IF EXISTS audit_tr ON connectors;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON connectors
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

DROP TRIGGER IF EXISTS audit_tr ON policies;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON policies
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

DROP TRIGGER IF EXISTS audit_tr ON sites;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON sites
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

DROP TRIGGER IF EXISTS audit_tr ON swg_rules;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON swg_rules
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

DROP TRIGGER IF EXISTS audit_tr ON fw_rules;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON fw_rules
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

DROP TRIGGER IF EXISTS audit_tr ON dlp_rules;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON dlp_rules
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

DROP TRIGGER IF EXISTS audit_tr ON device_enrollments;
CREATE TRIGGER audit_tr AFTER INSERT OR UPDATE OR DELETE ON device_enrollments
  FOR EACH ROW EXECUTE FUNCTION audit_row('tenant_id');

-- 显式排除(不挂触发器,见 L2 §4.3):
--   revocations  —— 机会式 GC 批量 DELETE 会致审计风暴;撤销审计另由应用语义记。
--   policy_bundles —— 编译产物高频 INSERT(非人工变更)。
--   audit_log    —— 自触发死循环。
