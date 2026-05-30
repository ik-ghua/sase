-- 0024 down:删 level CHECK 约束。
ALTER TABLE risk_scores DROP CONSTRAINT IF EXISTS chk_risk_level;
