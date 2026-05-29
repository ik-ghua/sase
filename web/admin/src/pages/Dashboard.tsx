// Slice 63:控制台首页看板(点亮登录落地页)。聚合已有数据源(租户/PoP/平台审计)成运维总览。
// 纯前端、零后端依赖;每张卡片独立错误隔离(某查询失败不拖垮整页)。
import { useMemo } from 'react';
import { Card, Row, Col, Statistic, Tag, Space, Table, Typography, Spin, Button } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import type { ColumnsType } from 'antd/es/table';
import { client } from '@/api/client';
import type { components } from '@/api/types';
import { toApiError } from '@/lib/api-error';
import AppError from '@/components/AppError';

const { Title, Text } = Typography;

type TenantSummary = components['schemas']['TenantSummary'];
type PoP = components['schemas']['PoP'];
type AuditEntry = components['schemas']['PlatformAuditEntry'];

// 状态枚举(与各页/后端对齐)
const TENANT_STATUSES = ['active', 'suspended', 'offboarding', 'decommissioned'] as const;
const POP_STATUSES = ['active', 'draining', 'down'] as const;
const STATUS_COLORS: Record<string, string> = {
  active: 'success',
  suspended: 'warning',
  offboarding: 'processing',
  decommissioned: 'default',
  draining: 'warning',
  down: 'error',
};

const RECENT_AUDIT_LIMIT = 8;

async function fetchTenants(): Promise<TenantSummary[]> {
  const { data, error, response } = await client.GET('/api/v1/platform/tenants');
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}
async function fetchPops(): Promise<PoP[]> {
  const { data, error, response } = await client.GET('/api/v1/platform/pop-nodes');
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}
async function fetchRecentAudit(): Promise<AuditEntry[]> {
  const { data, error, response } = await client.GET('/api/v1/platform/audit', {
    params: { query: { limit: RECENT_AUDIT_LIMIT } },
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}

function countByStatus<T extends { status?: string }>(rows: T[], statuses: readonly string[]) {
  const known = statuses.reduce<Record<string, number>>((acc, s) => ((acc[s] = 0), acc), {});
  for (const r of rows) {
    const s = r.status ?? '';
    if (s in known) known[s] += 1;
  }
  return known;
}

// 状态分布标签条(0 计数也显示,便于一眼看清全貌)
function StatusBreakdown({ counts }: { counts: Record<string, number> }) {
  return (
    <Space size={[4, 4]} wrap style={{ marginTop: 8 }}>
      {Object.entries(counts).map(([s, n]) => (
        <Tag key={s} color={STATUS_COLORS[s] ?? 'default'}>
          {s}: {n}
        </Tag>
      ))}
    </Space>
  );
}

function formatDate(s?: string): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleString('zh-CN', { hour12: false });
  } catch {
    return s;
  }
}

const auditColumns: ColumnsType<AuditEntry> = [
  { title: '时间', dataIndex: 'ts', key: 'ts', width: 180, render: formatDate },
  { title: '主体', dataIndex: 'actor_subject', key: 'actor_subject', width: 120, ellipsis: true },
  { title: '动作', dataIndex: 'action', key: 'action', ellipsis: true },
  {
    title: '来源',
    dataIndex: 'source',
    key: 'source',
    width: 80,
    render: (s: string) => <Tag color={s === 'data' ? 'geekblue' : 'cyan'}>{s}</Tag>,
  },
];

export default function Dashboard() {
  const tenantsQ = useQuery({ queryKey: ['platform-tenants'], queryFn: fetchTenants });
  const popsQ = useQuery({ queryKey: ['platform-pops'], queryFn: fetchPops });
  const auditQ = useQuery({ queryKey: ['platform-audit-recent'], queryFn: fetchRecentAudit });

  const tenants = tenantsQ.data ?? [];
  const pops = popsQ.data ?? [];

  // useMemo 依赖 query.data 本身(引用稳定,仅数据变更时重算;避免每渲染新数组使依赖抖动)
  const tenantCounts = useMemo(() => countByStatus(tenantsQ.data ?? [], TENANT_STATUSES), [tenantsQ.data]);
  const popCounts = useMemo(() => countByStatus(popsQ.data ?? [], POP_STATUSES), [popsQ.data]);
  // PoP 容量配额合计(仅累加配了 max_users 的节点;null=不限不计入)
  const popQuota = useMemo(() => {
    let sum = 0;
    let unlimited = 0;
    for (const p of popsQ.data ?? []) {
      if (typeof p.max_users === 'number') sum += p.max_users;
      else unlimited += 1;
    }
    return { sum, unlimited };
  }, [popsQ.data]);

  const refreshAll = () => {
    tenantsQ.refetch();
    popsQ.refetch();
    auditQ.refetch();
  };

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Space style={{ justifyContent: 'space-between', width: '100%' }}>
        <Title level={3} style={{ margin: 0 }}>
          平台运维总览
        </Title>
        <Button icon={<ReloadOutlined />} onClick={refreshAll}>
          刷新
        </Button>
      </Space>

      <Row gutter={[16, 16]}>
        <Col xs={24} md={12} lg={8}>
          <Card title="租户">
            {tenantsQ.isError ? (
              <AppError error={tenantsQ.error} onRetry={() => tenantsQ.refetch()} />
            ) : (
              <Spin spinning={tenantsQ.isLoading}>
                <Statistic title="总数" value={tenants.length} />
                <StatusBreakdown counts={tenantCounts} />
              </Spin>
            )}
          </Card>
        </Col>

        <Col xs={24} md={12} lg={8}>
          <Card title="PoP 节点">
            {popsQ.isError ? (
              <AppError error={popsQ.error} onRetry={() => popsQ.refetch()} />
            ) : (
              <Spin spinning={popsQ.isLoading}>
                <Statistic title="总数" value={pops.length} />
                <StatusBreakdown counts={popCounts} />
                <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
                  容量配额合计 {popQuota.sum}
                  {popQuota.unlimited > 0 ? `(另有 ${popQuota.unlimited} 个不限)` : ''}
                </Text>
              </Spin>
            )}
          </Card>
        </Col>

        <Col xs={24} md={12} lg={8}>
          <Card title="最近活动">
            {auditQ.isError ? (
              <AppError error={auditQ.error} onRetry={() => auditQ.refetch()} />
            ) : (
              <Spin spinning={auditQ.isLoading}>
                <Statistic title={`最近 ${RECENT_AUDIT_LIMIT} 条审计`} value={auditQ.data?.length ?? 0} />
                <Text type="secondary" style={{ display: 'block', marginTop: 8 }}>
                  最新:{auditQ.data && auditQ.data.length > 0 ? formatDate(auditQ.data[0].ts) : '-'}
                </Text>
              </Spin>
            )}
          </Card>
        </Col>
      </Row>

      <Card title="最近平台审计">
        {auditQ.isError ? (
          <AppError error={auditQ.error} onRetry={() => auditQ.refetch()} />
        ) : (
          <Table
            rowKey={(r) => `${r.ts}-${r.actor_subject}-${r.action}`}
            columns={auditColumns}
            dataSource={auditQ.data ?? []}
            loading={auditQ.isFetching}
            pagination={false}
            size="small"
          />
        )}
      </Card>
    </Space>
  );
}
