-- 0023 风险评分快照(Slice:risk RLS 持久化)。控制面信任/风险引擎(L1 3.8;L2 sase-l2-cp-trust-risk-engine.md)。
-- 现状:internal/risk 是内存评分(规则加权 + TTL 衰减),无持久化 → 运维/重启后看不到最新风险态。
-- 本表是**附加的快照层**:每 (tenant_id, subject) 一行最新快照(upsert),供只读查询端点暴露;
-- **不改内存评分逻辑**(权威评分仍在内存;本表 best-effort 旁路落盘,失败不阻断评分)。
-- 租户作用域、RLS(严格照搬 0005/0011:app_rw NOBYPASSRLS,纯靠 RLS 隔离)。

CREATE TABLE IF NOT EXISTS risk_scores (
  tenant_id  uuid        NOT NULL,
  subject    text        NOT NULL,            -- per-tenant 主体(用户/设备身份)
  score      int         NOT NULL,            -- 0–100
  level      text        NOT NULL,            -- low | medium | high | critical
  factors    jsonb,                            -- 可选:可解释因子(id/weight),供审计/排障
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject)            -- 每主体最新快照,upsert
);

ALTER TABLE risk_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_scores FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON risk_scores;
CREATE POLICY tenant_isolation ON risk_scores
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON risk_scores TO app_rw;
GRANT SELECT ON risk_scores TO app_ro;
