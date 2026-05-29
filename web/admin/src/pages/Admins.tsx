// Slice 46:平台管理员页(复用 Slice45 写操作模板:列表 + 新建 + 编辑 + 删除)。
// 后端 Slice38c:POST 新建 / PATCH(status/email,subject 不可改)/ DELETE(后端拦自删→400)。
// 注:前端不预判"是否自己"(auth store 暂无当前 subject);**直接展示后端 400 文案**(后端是权威,
// self-delete/self-disable 拦在后端 Slice38c)。
import { useState } from 'react';
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
  Select,
  Popconfirm,
  App as AntdApp,
} from 'antd';
import { ReloadOutlined, PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { ColumnsType } from 'antd/es/table';
import { client } from '@/api/client';
import type { components } from '@/api/types';
import { toApiError, ApiError } from '@/lib/api-error';
import AppError from '@/components/AppError';

const { Title } = Typography;

type PlatformAdmin = components['schemas']['PlatformAdmin'];
type CreateReq = components['schemas']['CreatePlatformAdminRequest'];
type AdminPatch = components['schemas']['PlatformAdminPatch'];

const STATUS_COLORS: Record<string, string> = { active: 'success', disabled: 'default' };
const STATUS_OPTIONS = [
  { value: 'active', label: 'active(启用)' },
  { value: 'disabled', label: 'disabled(停用)' },
];

async function fetchAdmins(): Promise<PlatformAdmin[]> {
  const { data, error, response } = await client.GET('/api/v1/platform/admins');
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}
async function createAdmin(body: CreateReq): Promise<PlatformAdmin> {
  const { data, error, response } = await client.POST('/api/v1/platform/admins', { body });
  if (error || !response.ok) throw toApiError(response, error);
  return data as PlatformAdmin;
}
async function patchAdmin(aid: string, patch: AdminPatch): Promise<PlatformAdmin> {
  const { data, error, response } = await client.PATCH('/api/v1/platform/admins/{aid}', {
    params: { path: { aid } },
    body: patch,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as PlatformAdmin;
}
async function deleteAdmin(aid: string): Promise<void> {
  const { error, response } = await client.DELETE('/api/v1/platform/admins/{aid}', {
    params: { path: { aid } },
  });
  if (error || !response.ok) throw toApiError(response, error);
}

function formatDate(s?: string | null): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleString('zh-CN', { hour12: false });
  } catch {
    return s;
  }
}

export default function Admins() {
  const { message } = AntdApp.useApp();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<PlatformAdmin | null>(null);
  const [createForm] = Form.useForm<CreateReq>();
  const [editForm] = Form.useForm<AdminPatch>();

  const query = useQuery({ queryKey: ['platform-admins'], queryFn: fetchAdmins });

  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform-admins'] });

  const createMut = useMutation({
    mutationFn: createAdmin,
    onSuccess: (a) => {
      message.success(`管理员「${a.subject}」已添加`);
      setCreateOpen(false);
      createForm.resetFields();
      invalidate();
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) {
        message.error('该 subject 已存在');
      } else {
        message.error(err instanceof Error ? err.message : '添加失败');
      }
    },
  });

  const patchMut = useMutation({
    mutationFn: ({ aid, patch }: { aid: string; patch: AdminPatch }) => patchAdmin(aid, patch),
    onSuccess: (a) => {
      message.success(`管理员「${a.subject}」已更新`);
      setEditTarget(null);
      editForm.resetFields();
      invalidate();
    },
    onError: (err) => {
      // 后端 Slice38c:disable 自己 → 400(防自助锁死),直接展示后端文案
      message.error(err instanceof Error ? err.message : '更新失败');
    },
  });

  const deleteMut = useMutation({
    mutationFn: deleteAdmin,
    onSuccess: () => {
      message.success('管理员已删除');
      invalidate();
    },
    onError: (err) => {
      // 后端 Slice38c:删自己 → 400(防锁死),直接展示后端文案
      message.error(err instanceof Error ? err.message : '删除失败');
    },
  });

  // 仅设目标;预填经编辑 Form 的 initialValues + key(挂载时由 rc-field-form 初始化)。
  // ⚠️ 不要在此同步 setFieldsValue/useEffect:destroyOnHidden 下 Form 未挂载,真浏览器会丢失(Slice52 e2e 实证)。
  const openEdit = (a: PlatformAdmin) => {
    setEditTarget(a);
  };

  const columns: ColumnsType<PlatformAdmin> = [
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
    { title: '主体(subject)', dataIndex: 'subject', key: 'subject', ellipsis: true },
    { title: '邮箱', dataIndex: 'email', key: 'email', ellipsis: true, render: (e?: string) => e || '-' },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      filters: STATUS_OPTIONS.map((s) => ({ text: s.value, value: s.value })),
      onFilter: (value, record) => record.status === value,
      render: (status: string) => <Tag color={STATUS_COLORS[status] ?? 'default'}>{status}</Tag>,
    },
    { title: '添加者', dataIndex: 'created_by', key: 'created_by', width: 140, render: (c?: string) => c || '-' },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180, render: formatDate },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(record)}>
            编辑
          </Button>
          <Popconfirm
            title="删除该管理员?"
            description="删自己会被后端拒(防锁死);删他人立即生效。"
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            onConfirm={() => deleteMut.mutate(record.id)}
          >
            <Button size="small" danger icon={<DeleteOutlined />}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <Card>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>
          平台管理员
        </Title>
        <Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            添加管理员
          </Button>
          <Button icon={<ReloadOutlined />} onClick={() => query.refetch()} loading={query.isFetching}>
            刷新
          </Button>
        </Space>
      </div>

      <Typography.Paragraph type="secondary">
        登记的 platform_admin 才能经 /platform/admin-tokens 签发平台令牌(bootstrap env 为应急例外)。
        删除/停用自己会被后端拒,防最后一枚管理员锁死。
      </Typography.Paragraph>

      {query.isError && <AppError error={query.error} onRetry={() => query.refetch()} />}

      <Table
        rowKey="id"
        columns={columns}
        dataSource={query.data ?? []}
        loading={query.isLoading}
        pagination={{ pageSize: 20, showSizeChanger: true, showTotal: (n) => `共 ${n} 条` }}
        scroll={{ x: 1100 }}
        size="middle"
      />

      {/* 新建 Modal */}
      <Modal
        title="添加平台管理员"
        open={createOpen}
        onCancel={() => {
          setCreateOpen(false);
          createForm.resetFields();
        }}
        onOk={() => createForm.submit()}
        confirmLoading={createMut.isPending}
        okText="添加"
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
            label="主体(subject,唯一)"
            name="subject"
            rules={[{ required: true, message: '必填' }]}
            tooltip="IdP sub / 运营 ID;签发 platform_admin token 时按此匹配"
          >
            <Input placeholder="如 ops-alice" />
          </Form.Item>
          <Form.Item label="邮箱(可选)" name="email">
            <Input placeholder="alice@example.com" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 编辑 Modal(status/email;subject 不可改) */}
      <Modal
        title={editTarget ? `编辑管理员「${editTarget.subject}」` : '编辑管理员'}
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
          subject 不可改(主键级;如需改名 = 删后重建)。停用自己会被后端拒。
        </Typography.Paragraph>
        <Form
          form={editForm}
          key={editTarget?.id}
          initialValues={
            editTarget ? { status: editTarget.status, email: editTarget.email } : undefined
          }
          layout="vertical"
          onFinish={(values) => {
            if (editTarget) patchMut.mutate({ aid: editTarget.id, patch: values });
          }}
          preserve={false}
        >
          <Form.Item label="状态(status)" name="status">
            <Select options={STATUS_OPTIONS} />
          </Form.Item>
          <Form.Item label="邮箱(email)" name="email">
            <Input placeholder="alice@example.com" />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
