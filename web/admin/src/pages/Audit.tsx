// Slice 47:平台审计页(只读)。GET /platform/audit?limit=N;双层审计 source=api(handler)/data(DB 触发器)。
import { useMemo, useState } from 'react';
import { Card, Table, Tag, Button, Space, Typography, Tooltip, Select, Descriptions, Input } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import type { ColumnsType } from 'antd/es/table';
import { client } from '@/api/client';
import type { components } from '@/api/types';
import { toApiError } from '@/lib/api-error';
import AppError from '@/components/AppError';

const { Title } = Typography;

type AuditEntry = components['schemas']['PlatformAuditEntry'];

// result 筛选分桶:触发器哨兵(source=data 且 result=0)单列一桶,其余按 HTTP 码段。
// 哨兵的 result 数值 0 不是 HTTP 码,故不能并入「其它/0」HTTP 桶,须按 source 区分。
type ResultBucket = 'trigger' | '2xx' | '4xx' | '5xx' | 'other';

function resultBucket(record: AuditEntry): ResultBucket {
  if (record.source === 'data' && record.result === 0) return 'trigger';
  const r = record.result;
  if (r >= 200 && r < 300) return '2xx';
  if (r >= 400 && r < 500) return '4xx';
  if (r >= 500) return '5xx';
  return 'other';
}

const RESULT_FILTERS = [
  { text: '触发器(source=data)', value: 'trigger' },
  { text: '2xx 成功', value: '2xx' },
  { text: '4xx 客户端错误', value: '4xx' },
  { text: '5xx 服务端错误', value: '5xx' },
  { text: '其它', value: 'other' },
];

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
  {
    title: '主体',
    dataIndex: 'actor_subject',
    key: 'actor_subject',
    width: 150,
    ellipsis: true,
    render: (subject?: string) =>
      subject ? (
        <Tooltip title={subject}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{subject}</span>
        </Tooltip>
      ) : (
        '-'
      ),
  },
  { title: '角色', dataIndex: 'actor_role', key: 'actor_role', width: 130, ellipsis: true },
  { title: '动作', dataIndex: 'action', key: 'action', ellipsis: true },
  {
    title: '结果',
    dataIndex: 'result',
    key: 'result',
    width: 110,
    filters: RESULT_FILTERS,
    // 按 result 维度筛选:触发器哨兵(source=data+result=0)与 HTTP 码段分桶,正确区分双层语义。
    onFilter: (value, record) => resultBucket(record) === value,
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
  const [keyword, setKeyword] = useState('');
  const query = useQuery({
    queryKey: ['platform-audit', limit],
    queryFn: () => fetchAudit(limit),
  });

  // 客户端关键词过滤:大小写不敏感子串,匹配 actor_subject 或 action 任一即保留;空关键词=不过滤。
  // 与列级 filters(source/result)叠加——antd Table 在本 dataSource 之上再应用其内建列筛选。
  // 依赖 query.data 本身(引用稳定),`?? []` 在回调内取,避免每渲染新数组抖动 deps。
  const filteredRows = useMemo(() => {
    const rows = query.data ?? [];
    const kw = keyword.trim().toLowerCase();
    if (!kw) return rows;
    return rows.filter(
      (r) =>
        (r.actor_subject ?? '').toLowerCase().includes(kw) ||
        (r.action ?? '').toLowerCase().includes(kw),
    );
  }, [query.data, keyword]);

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

      <Input.Search
        placeholder="按主体 / 动作关键词筛选(客户端)"
        allowClear
        value={keyword}
        onChange={(e) => setKeyword(e.target.value)}
        style={{ width: 320, marginBottom: 16 }}
      />

      {query.isError && <AppError error={query.error} onRetry={() => query.refetch()} />}

      <Table
        rowKey="id"
        columns={columns}
        dataSource={filteredRows}
        loading={query.isFetching}
        pagination={{ pageSize: 20, showSizeChanger: true, showTotal: (n) => `共 ${n} 条` }}
        scroll={{ x: 1200 }}
        size="middle"
        expandable={{
          // 展开行显示完整 detail(详情列截断,展开看全)+ 主体/角色/动作/关联租户 概览。
          expandedRowRender: (record) => (
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label="主体">{record.actor_subject || '-'}</Descriptions.Item>
              <Descriptions.Item label="角色">{record.actor_role || '-'}</Descriptions.Item>
              <Descriptions.Item label="动作">{record.action || '-'}</Descriptions.Item>
              <Descriptions.Item label="关联租户">
                <span style={{ fontFamily: 'var(--font-mono)' }}>
                  {record.target_tenant_id || '-'}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label="完整详情">
                <span style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                  {record.detail || '-'}
                </span>
              </Descriptions.Item>
            </Descriptions>
          ),
        }}
      />
    </Card>
  );
}
