// Slice 45:PoP 注册页(首个含写操作的页 → 端到端验证 Slice40 CSRF + Slice42 Bearer 在 POST/PATCH 真联通)。
// 列表 GET /platform/pop-nodes;新建 POST;编辑 PATCH(仅 status/max_users,name/region/endpoint 不可改防 ID 漂移)。
import { useState, useMemo } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Space,
  Typography,
  Tooltip,
  Modal,
  Form,
  Input,
  InputNumber,
  Select,
  Row,
  Col,
  Statistic,
  App as AntdApp,
} from 'antd';
import { ReloadOutlined, PlusOutlined, EditOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { ColumnsType } from 'antd/es/table';
import { client } from '@/api/client';
import type { components } from '@/api/types';
import { toApiError, ApiError } from '@/lib/api-error';
import AppError from '@/components/AppError';

const { Title } = Typography;

type PoP = components['schemas']['PoP'];
type CreatePopRequest = components['schemas']['CreatePopRequest'];
type PopPatch = components['schemas']['PopPatch'];

const STATUS_COLORS: Record<string, string> = {
  active: 'success',
  draining: 'warning',
  down: 'error',
};
const STATUS_OPTIONS = [
  { value: 'active', label: 'active(在用)' },
  { value: 'draining', label: 'draining(下线中)' },
  { value: 'down', label: 'down(故障)' },
];

async function fetchPops(): Promise<PoP[]> {
  const { data, error, response } = await client.GET('/api/v1/platform/pop-nodes');
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}

async function createPop(body: CreatePopRequest): Promise<PoP> {
  const { data, error, response } = await client.POST('/api/v1/platform/pop-nodes', { body });
  if (error || !response.ok) throw toApiError(response, error);
  return data as PoP;
}

async function patchPop(pid: string, patch: PopPatch): Promise<PoP> {
  const { data, error, response } = await client.PATCH('/api/v1/platform/pop-nodes/{pid}', {
    params: { path: { pid } },
    body: patch,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as PoP;
}

function formatQuota(n?: number | null): string {
  if (n === null || n === undefined) return '不限';
  return n.toLocaleString('zh-CN');
}
function formatDate(s?: string | null): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleString('zh-CN', { hour12: false });
  } catch {
    return s;
  }
}

export default function Pops() {
  const { message } = AntdApp.useApp();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<PoP | null>(null);
  const [createForm] = Form.useForm<CreatePopRequest>();
  const [editForm] = Form.useForm<PopPatch>();

  const query = useQuery({ queryKey: ['platform-pops'], queryFn: fetchPops });

  const createMut = useMutation({
    mutationFn: createPop,
    onSuccess: (p) => {
      message.success(`PoP「${p.name}」已创建`);
      setCreateOpen(false);
      createForm.resetFields();
      qc.invalidateQueries({ queryKey: ['platform-pops'] });
    },
    onError: (err) => {
      // 409 name 冲突给可读提示;其它走通用
      if (err instanceof ApiError && err.status === 409) {
        message.error('PoP name 已存在,请换一个');
      } else {
        message.error(err instanceof Error ? err.message : '创建失败');
      }
    },
  });

  const patchMut = useMutation({
    mutationFn: ({ pid, patch }: { pid: string; patch: PopPatch }) => patchPop(pid, patch),
    onSuccess: (p) => {
      message.success(`PoP「${p.name}」已更新`);
      setEditTarget(null);
      editForm.resetFields();
      qc.invalidateQueries({ queryKey: ['platform-pops'] });
    },
    onError: (err) => {
      message.error(err instanceof Error ? err.message : '更新失败');
    },
  });

  // 仅设目标;预填经编辑 Form 的 initialValues + key(挂载时由 rc-field-form 初始化)。
  // ⚠️ 不要在此同步 setFieldsValue,也不要用 useEffect 回填:destroyOnHidden 下 Form 此刻未挂载,
  //   真浏览器里会丢失(Slice52 e2e 实证);initialValues 在挂载时初始化,jsdom/浏览器都对。
  const openEdit = (p: PoP) => {
    setEditTarget(p);
  };

  // Slice66:按地域容量概览(节点数 + active/draining/down 分布 + 容量配额合计)。
  const regionSummary = useMemo(() => {
    const agg: Record<
      string,
      { total: number; active: number; draining: number; down: number; capacity: number; unlimited: number }
    > = {};
    for (const p of query.data ?? []) {
      const region = p.region || '(未知)';
      const g = (agg[region] ??= { total: 0, active: 0, draining: 0, down: 0, capacity: 0, unlimited: 0 });
      g.total += 1;
      if (p.status === 'active') g.active += 1;
      else if (p.status === 'draining') g.draining += 1;
      else if (p.status === 'down') g.down += 1;
      if (typeof p.max_users === 'number') g.capacity += p.max_users;
      else g.unlimited += 1;
    }
    return Object.entries(agg).sort((a, b) => a[0].localeCompare(b[0]));
  }, [query.data]);

  const columns: ColumnsType<PoP> = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 110,
      render: (id: string) => (
        <Tooltip title={id}>
          <span style={{ fontFamily: 'var(--font-mono)' }}>{id.slice(0, 8)}</span>
        </Tooltip>
      ),
    },
    { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
    { title: '地域', dataIndex: 'region', key: 'region', width: 130 },
    { title: '入口地址', dataIndex: 'endpoint', key: 'endpoint', ellipsis: true },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 130,
      filters: STATUS_OPTIONS.map((s) => ({ text: s.value, value: s.value })),
      onFilter: (value, record) => record.status === value,
      render: (status: string) => <Tag color={STATUS_COLORS[status] ?? 'default'}>{status}</Tag>,
    },
    { title: '容量上限', dataIndex: 'max_users', key: 'max_users', width: 110, render: formatQuota },
    {
      title: '最近心跳',
      dataIndex: 'last_seen_at',
      key: 'last_seen_at',
      width: 180,
      render: formatDate,
    },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180, render: formatDate },
    {
      title: '操作',
      key: 'actions',
      width: 90,
      fixed: 'right',
      render: (_, record) => (
        <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(record)}>
          编辑
        </Button>
      ),
    },
  ];

  return (
    <Card>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>
          PoP 注册
        </Title>
        <Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建 PoP
          </Button>
          <Button icon={<ReloadOutlined />} onClick={() => query.refetch()} loading={query.isFetching}>
            刷新
          </Button>
        </Space>
      </div>

      {query.isError && <AppError error={query.error} onRetry={() => query.refetch()} />}

      {/* Slice66:按地域容量概览 */}
      {regionSummary.length > 0 && (
        <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
          {regionSummary.map(([region, g]) => (
            <Col key={region} xs={24} sm={12} md={8} lg={6}>
              <Card size="small" title={`地域 ${region}`}>
                <Statistic title="节点数" value={g.total} />
                <Space size={[4, 4]} wrap style={{ marginTop: 8 }}>
                  <Tag color="success">active {g.active}</Tag>
                  <Tag color="warning">draining {g.draining}</Tag>
                  <Tag color="error">down {g.down}</Tag>
                </Space>
                <div style={{ marginTop: 8, color: 'rgba(0,0,0,0.45)' }}>
                  容量配额 {g.capacity.toLocaleString('zh-CN')}
                  {g.unlimited > 0 ? `(${g.unlimited} 个不限)` : ''}
                </div>
              </Card>
            </Col>
          ))}
        </Row>
      )}

      <Table
        rowKey="id"
        columns={columns}
        dataSource={query.data ?? []}
        loading={query.isLoading}
        pagination={{ pageSize: 20, showSizeChanger: true, showTotal: (n) => `共 ${n} 条` }}
        scroll={{ x: 1280 }}
        size="middle"
      />

      {/* 新建 Modal */}
      <Modal
        title="新建 PoP 节点"
        open={createOpen}
        onCancel={() => {
          setCreateOpen(false);
          createForm.resetFields();
        }}
        onOk={() => createForm.submit()}
        confirmLoading={createMut.isPending}
        okText="创建"
        cancelText="取消"
        destroyOnHidden
      >
        <Form
          form={createForm}
          layout="vertical"
          onFinish={(values) => createMut.mutate(values)}
          preserve={false}
        >
          <Form.Item
            label="名称(name,唯一)"
            name="name"
            rules={[{ required: true, message: '必填' }]}
          >
            <Input placeholder="如 sh-pop-01" />
          </Form.Item>
          <Form.Item label="地域(region)" name="region" rules={[{ required: true, message: '必填' }]}>
            <Input placeholder="如 cn-east-1" />
          </Form.Item>
          <Form.Item
            label="入口地址(endpoint)"
            name="endpoint"
            rules={[{ required: true, message: '必填' }]}
          >
            <Input placeholder="如 pop-sh.example.com:443" />
          </Form.Item>
          <Form.Item
            label="容量上限(max_users,留空=不限)"
            name="max_users"
            tooltip="用户数上限;不填则不限"
          >
            <InputNumber min={0} style={{ width: '100%' }} placeholder="不限" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 编辑 Modal(仅 status/max_users;name/region/endpoint 不可改) */}
      <Modal
        title={editTarget ? `编辑 PoP「${editTarget.name}」` : '编辑 PoP'}
        open={editTarget !== null}
        onCancel={() => {
          setEditTarget(null);
          editForm.resetFields();
        }}
        onOk={() => editForm.submit()}
        confirmLoading={patchMut.isPending}
        okText="保存"
        cancelText="取消"
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          name / region / endpoint 不可改(防 ID 漂移);如需迁移请新建 + 旧节点置 draining → down。
        </Typography.Paragraph>
        <Form
          form={editForm}
          key={editTarget?.id}
          initialValues={
            editTarget ? { status: editTarget.status, max_users: editTarget.max_users } : undefined
          }
          layout="vertical"
          onFinish={(values) => {
            if (editTarget) patchMut.mutate({ pid: editTarget.id, patch: values });
          }}
          preserve={false}
        >
          <Form.Item label="状态(status)" name="status">
            <Select options={STATUS_OPTIONS} />
          </Form.Item>
          <Form.Item label="容量上限(max_users,留空=不限)" name="max_users">
            <InputNumber min={0} style={{ width: '100%' }} placeholder="不限" />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
