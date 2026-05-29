-- 0014 租户注销宽限期(PC-API-2b,平台控制台 L2 LP-PC5:软删→宽限→硬删 DEK)。
-- 本迁移只加"宽限期调度标记"列;**硬删(销毁 DEK,不可逆,L1 3.16 密钥销毁式删除)是后续刀**——
-- 依赖尚未编码的 secret/KMS 模块 + 定时清扫作业(类比撤销表 GC,交 DB 维护作业按 decommission_at 触发)。
-- decommission_at:计划硬删时刻(now+宽限期);NULL=未注销。宽限期内可取消(回 active、清此列)。
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS decommission_at timestamptz;

-- 平台策展视图带上注销调度(平台运维看哪些租户在 offboarding 及何时硬删);CREATE OR REPLACE 保留 owner + 授权。
-- owner 仍为迁移期 superuser(绕 RLS,跨租户可见;0013 owner 自检结论不变,列仅追加)。
CREATE OR REPLACE VIEW tenant_summary AS
  SELECT id, name, status, plan, created_at, decommission_at
  FROM tenants;
