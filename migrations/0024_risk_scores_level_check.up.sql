-- 0024 risk_scores.level CHECK 约束(承接 0023 risk_scores 表 + internal/risk/store.go)。
-- 背景:0023 的 level 列仅注释标注 low|medium|high|critical(api/xdsv1 单一来源),DB 层无强约束 →
-- 应用 bug / 直插脏数据可写入非法 level,而 PEP riskRank 对未知 level 视作最低(low),静默 fail-open。
-- 本迁移在 DB 层补纵深防线:level 必落在合法枚举内(对照 tenants.status / pop_nodes.status 的 CHECK 惯例)。
-- 枚举来源:api/xdsv1/contract.go 的 RiskLow/RiskMedium/RiskHigh/RiskCritical = low/medium/high/critical。
-- 幂等:DROP CONSTRAINT IF EXISTS 再 ADD(对照 0010/0011 的 chk_ 前缀 CHECK 惯例),可重复应用。
ALTER TABLE risk_scores DROP CONSTRAINT IF EXISTS chk_risk_level;
ALTER TABLE risk_scores ADD CONSTRAINT chk_risk_level
  CHECK (level IN ('low', 'medium', 'high', 'critical'));
