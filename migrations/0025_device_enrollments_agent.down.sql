-- 0025 down:回退 Agent 形态支持(去 user_id 列、kind CHECK 回 connector/cpe)。
-- ⚠️ 单向门警告:若已签发过 kind='agent' 的入网记录,回退 CHECK 会因现存 'agent' 行违反约束而失败;
-- 须先清理(或保留 'agent' 记录归档)。本 down 仅供未启用 Agent 入网前的回滚。
DROP INDEX IF EXISTS idx_enroll_user;
ALTER TABLE device_enrollments DROP COLUMN IF EXISTS user_id;
ALTER TABLE device_enrollments DROP CONSTRAINT IF EXISTS chk_enroll_kind;
ALTER TABLE device_enrollments ADD  CONSTRAINT chk_enroll_kind
  CHECK (kind IN ('connector','cpe'));
