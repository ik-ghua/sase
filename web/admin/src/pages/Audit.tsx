// Slice 47:平台审计页(只读)。GET /platform/audit?limit=N;双层审计 source=api(handler)/data(DB 触发器)。
import { useState } from 'react';
import { Card, Table, Tag, Button, Space, Typography, Tooltip, Select } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import type { ColumnsType } from 'antd/es/table';
import { client } from '@/api/client';
import type { components } from '@/api/types';
import { toApiError } from '@/lib/api-error';
import AppError from '@/components/AppError';

const { Title } = Typography;

type AuditEntry = components['schemas']['PlatformAuditEntry'];

const LIMIT_OPTIONS = [
  { value: 50, label: '最近 50 条' },
  { value: 100, label: '最近 100 条' },
  { value: 500, label: '最近 500 条' },
  { value: 1000, label: '最近 1000 条' },
];

async function fetchAudit(limit: number): Promise<AuditEntry[]> {
  const { data, error, response } = await client.GET('/api/v1/platform/audit', {
    params: { query: { limit } },
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}

function formatDate(s?: string): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleString('zh-CN', { hour12: false });
  } catch {
    return s;
  }
}

// result 渲染:source=data 的 result=0 是触发器哨兵(非 HTTP 码),特殊显示;source=api 是 HTTP 码。
function renderResult(result: number, source: string) {
  if (source === 'data' && result === 0) {
    return <Tag color="cyan">触发器</Tag>;
  }
  // HTTP 码:2xx 绿 / 4xx 橙 / 5xx 红
  let color = 'default';
  if (result >= 200 && result < 300) color = 'success';
  else if (result >= 400 && result < 500) color = 'warning';
  else if (result >= 500) color = 'error';
  return <Tag color={color}>{result}</Tag>;
}

const columns: ColumnsType<AuditEntry> = [
  {
    title: '时间',
    dataIndex: 'ts',
    key: 'ts',
    width: 180,
    render: formatDate,
    defaultSortOrder: 'descend',
    sorter: (a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime(),
  },
  {
    title: '来源',
    dataIndex: 'source',
    key: 'source',
    width: 90,
    filters: [
      { text: 'api(handler)', value: 'api' },
      { text: 'data(触发器)', value: 'data' },
    ],
    onFilter: (value, record) => record.source === value,
    render: (source: string) => (
      <Tag color={source === 'data' ? 'geekblue' : 'blue'}>{source}</Tag>
    ),
  },
  { title: '主体', dataIndex: 'actor_subject', key: 'actor_subject', width: 150, ellipsis: true },
  { title: '角色', dataIndex: 'actor_role', key: 'actor_role', width: 130, ellipsis: true },
  { title: '动作', dataIndex: 'action', key: 'action', ellipsis: true },
  {
    title: '结果',
    dataIndex: 'result',
    key: 'result',
    width: 90,
    render: (result: number, record) => renderResult(result, record.source),
  },
  {
    title: '详情',
    dataIndex: 'detail',
    key: 'detail',
    ellipsis: true,
    render: (detail?: string) =>
      detail ? (
        <Tooltip title={detail}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{detail}</span>
        </Tooltip>
      ) : (
        '-'
      ),
  },
  {
    title: '关联租户',
    dataIndex: 'target_tenant_id',
    key: 'target_tenant_id',
    width: 110,
    render: (tid?: string) =>
      tid ? (
        <Tooltip title={tid}>
          <span style={{ fontFamily: 'var(--font-mono)' }}>{tid.slice(0, 8)}</span>
        </Tooltip>
      ) : (
        '-'
      ),
  },
];

export default function Audit() {
  const [limit, setLimit] = useState(100);
  const query = useQuery({
    queryKey: ['platform-audit', limit],
    queryFn: () => fetchAudit(limit),
  });

  return (
    <Card>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>
          平台审计
        </Title>
        <Space>
          <Select
            value={limit}
            options={LIMIT_OPTIONS}
            onChange={setLimit}
            style={{ width: 150 }}
          />
          <Button icon={<ReloadOutlined />} onClick={() => query.refetch()} loading={query.isFetching}>
            刷新
          </Button>
        </Space>
      </div>

      <Typography.Paragraph type="secondary">
        双层审计:<Tag color="blue">api</Tag>= handler 显式写(含失败/零变更);
        <Tag color="geekblue">data</Tag>= DB 触发器原子写(同事务,result 显示「触发器」哨兵)。
      </Typography.Paragraph>

      {query.isError && <AppError error={query.error} onRetry={() => query.refetch()} />}

      <Table
        rowKey="id"
        columns={columns}
        dataSource={query.data ?? []}
        loading={query.isFetching}
        pagination={{ pageSize: 20, showSizeChanger: true, showTotal: (n) => `共 ${n} 条` }}
        scroll={{ x: 1200 }}
        size="middle"
      />
    </Card>
  );
}
