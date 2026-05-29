-- 0010 FWaaS 规则:安全能力 FWaaS(L3/L4 防火墙,P4)的每租户规则(安全栈 L2)。租户作用域、RLS。
-- 5 元组匹配 + 优先级首次匹配 + 默认拒绝;执行点为 PoP 数据面包路径(dptunnel Router),实现每租户网络分段。
-- L3/L4 起步用户态匹配,生产下沉 eBPF(规则模型不变);L7 防火墙复用 Envoy/SWG L7 检查点(后续)。

CREATE TABLE IF NOT EXISTS fw_rules (
  id            uuid        PRIMARY KEY,
  tenant_id     uuid        NOT NULL,
  priority      int         NOT NULL,            -- 越小越先匹配
  action        text        NOT NULL,            -- allow | deny
  protocol      text        NOT NULL DEFAULT 'any', -- any | tcp | udp | icmp
  src_cidr      text        NOT NULL DEFAULT '',    -- 空=any
  dst_cidr      text        NOT NULL DEFAULT '',    -- 空=any
  dst_port_min  int         NOT NULL DEFAULT 0,     -- 0,0 = any
  dst_port_max  int         NOT NULL DEFAULT 0,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_fw_action   CHECK (action   IN ('allow','deny')),
  CONSTRAINT chk_fw_protocol CHECK (protocol IN ('any','tcp','udp','icmp')),
  CONSTRAINT chk_fw_ports    CHECK (dst_port_min BETWEEN 0 AND 65535 AND dst_port_max BETWEEN 0 AND 65535)
);
CREATE INDEX IF NOT EXISTS idx_fw_rules_tenant ON fw_rules (tenant_id, priority);

ALTER TABLE fw_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE fw_rules FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON fw_rules;
CREATE POLICY tenant_isolation ON fw_rules
  USING      (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON fw_rules TO app_rw;
GRANT SELECT ON fw_rules TO app_ro;
