// Slice 64:平台运维代租户管理 FWaaS 规则(Slice62 PUT/DELETE 契约的前端 payoff)。
// 自包含组件:list(GET)+ 新建(POST)+ 编辑(PUT 全量替换)+ 删除(DELETE)。
// 嵌入 Tenants 详情 Drawer;platform_admin 经 path-tid 对任意租户读写(authz 允许,Slice62 实证)。
// 编辑预填用 initialValues + key(Slice52:destroyOnHidden 下同步 setFieldsValue 真浏览器会丢)。
import { useState } from 'react';
import {
  Table,
  Tag,
  Button,
  Space,
  Modal,
  Form,
  Input,
  InputNumber,
  Select,
  Popconfirm,
  Typography,
  App as AntdApp,
} from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { ColumnsType } from 'antd/es/table';
import { client } from '@/api/client';
import type { components } from '@/api/types';
import { toApiError } from '@/lib/api-error';
import AppError from '@/components/AppError';

type FWRule = components['schemas']['FWRule'];

const ACTION_COLORS: Record<string, string> = { allow: 'green', deny: 'red' };
const ACTION_OPTIONS = [
  { value: 'allow', label: 'allow(放行)' },
  { value: 'deny', label: 'deny(拒绝)' },
];
const PROTO_OPTIONS = [
  { value: 'any', label: 'any' },
  { value: 'tcp', label: 'tcp' },
  { value: 'udp', label: 'udp' },
  { value: 'icmp', label: 'icmp' },
];

async function fetchRules(tid: string): Promise<FWRule[]> {
  const { data, error, response } = await client.GET('/api/v1/tenants/{tid}/fw/rules', {
    params: { path: { tid } },
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}
async function createRule(tid: string, body: FWRule): Promise<FWRule> {
  const { data, error, response } = await client.POST('/api/v1/tenants/{tid}/fw/rules', {
    params: { path: { tid } },
    body,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as FWRule;
}
async function updateRule(tid: string, id: string, body: FWRule): Promise<FWRule> {
  const { data, error, response } = await client.PUT('/api/v1/tenants/{tid}/fw/rules/{id}', {
    params: { path: { tid, id } },
    body,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as FWRule;
}
async function deleteRule(tid: string, id: string): Promise<void> {
  const { error, response } = await client.DELETE('/api/v1/tenants/{tid}/fw/rules/{id}', {
    params: { path: { tid, id } },
  });
  if (error || !response.ok) throw toApiError(response, error);
}

function portRange(r: FWRule): string {
  const lo = r.dst_port_min ?? 0;
  const hi = r.dst_port_max ?? 0;
  if (lo === 0 && hi === 0) return 'any';
  return lo === hi ? String(lo) : `${lo}-${hi}`;
}

// 表单默认值(新建)/ 编辑预填均经此整形,保证 PUT 全量替换字段齐全
const EMPTY_RULE: FWRule = {
  priority: 100,
  action: 'allow',
  protocol: 'any',
  src_cidr: '',
  dst_cidr: '',
  dst_port_min: 0,
  dst_port_max: 0,
};

export default function TenantFWRules({ tenantId }: { tenantId: string }) {
  const { message } = AntdApp.useApp();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<FWRule | null>(null);
  const [createForm] = Form.useForm<FWRule>();
  const [editForm] = Form.useForm<FWRule>();

  const qkey = ['tenant-fw-rules', tenantId];
  const query = useQuery({
    queryKey: qkey,
    queryFn: () => fetchRules(tenantId),
    enabled: tenantId !== '',
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: qkey });

  const createMut = useMutation({
    mutationFn: (body: FWRule) => createRule(tenantId, body),
    onSuccess: () => {
      message.success('防火墙规则已创建');
      setCreateOpen(false);
      createForm.resetFields();
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '创建失败'),
  });

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: FWRule }) => updateRule(tenantId, id, body),
    onSuccess: () => {
      message.success('防火墙规则已更新');
      setEditTarget(null);
      editForm.resetFields();
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '更新失败'),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteRule(tenantId, id),
    onSuccess: () => {
      message.success('防火墙规则已删除');
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '删除失败'),
  });

  const columns: ColumnsType<FWRule> = [
    { title: '优先级', dataIndex: 'priority', key: 'priority', width: 80, sorter: (a, b) => (a.priority ?? 0) - (b.priority ?? 0) },
    {
      title: '动作',
      dataIndex: 'action',
      key: 'action',
      width: 90,
      render: (a: string) => <Tag color={ACTION_COLORS[a] ?? 'default'}>{a}</Tag>,
    },
    { title: '协议', dataIndex: 'protocol', key: 'protocol', width: 80 },
    { title: '源 CIDR', dataIndex: 'src_cidr', key: 'src_cidr', render: (c: string) => c || 'any' },
    { title: '目的 CIDR', dataIndex: 'dst_cidr', key: 'dst_cidr', render: (c: string) => c || 'any' },
    { title: '目的端口', key: 'ports', width: 110, render: (_, r) => portRange(r) },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      render: (_, r) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => setEditTarget(r)}>
            编辑
          </Button>
          <Popconfirm
            title="删除该防火墙规则?"
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            onConfirm={() => r.id && deleteMut.mutate(r.id)}
          >
            <Button size="small" danger icon={<DeleteOutlined />}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  if (query.isError) {
    return <AppError error={query.error} onRetry={() => query.refetch()} />;
  }

  const ruleFormItems = (
    <>
      <Form.Item label="优先级(priority,越小越先匹配)" name="priority" rules={[{ required: true, message: '必填' }]}>
        <InputNumber min={0} style={{ width: '100%' }} />
      </Form.Item>
      <Form.Item label="动作(action)" name="action" rules={[{ required: true, message: '必填' }]}>
        <Select options={ACTION_OPTIONS} />
      </Form.Item>
      <Form.Item label="协议(protocol)" name="protocol" rules={[{ required: true, message: '必填' }]}>
        <Select options={PROTO_OPTIONS} />
      </Form.Item>
      <Form.Item label="源 CIDR(留空=any)" name="src_cidr" tooltip="如 10.0.0.0/24;留空匹配任意源">
        <Input placeholder="any" />
      </Form.Item>
      <Form.Item label="目的 CIDR(留空=any)" name="dst_cidr">
        <Input placeholder="any" />
      </Form.Item>
      <Space>
        <Form.Item label="目的端口下限(0,0=any)" name="dst_port_min">
          <InputNumber min={0} max={65535} />
        </Form.Item>
        <Form.Item label="上限" name="dst_port_max">
          <InputNumber min={0} max={65535} />
        </Form.Item>
      </Space>
    </>
  );

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <Typography.Text type="secondary">默认拒绝 + 优先级首次匹配;PUT 为全量替换</Typography.Text>
        <Button type="primary" size="small" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
          新建规则
        </Button>
      </div>
      <Table
        rowKey={(r) => r.id ?? `${r.priority}-${r.action}`}
        columns={columns}
        dataSource={query.data ?? []}
        loading={query.isFetching}
        pagination={false}
        size="small"
      />

      {/* 新建 Modal */}
      <Modal
        title="新建防火墙规则"
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
          initialValues={EMPTY_RULE}
          onFinish={(values) => createMut.mutate(values)}
          preserve={false}
        >
          {ruleFormItems}
        </Form>
      </Modal>

      {/* 编辑 Modal(PUT 全量替换);预填用 initialValues + key(Slice52) */}
      <Modal
        title="编辑防火墙规则"
        open={editTarget !== null}
        onCancel={() => {
          setEditTarget(null);
          editForm.resetFields();
        }}
        onOk={() => editForm.submit()}
        confirmLoading={updateMut.isPending}
        okText="保存"
        cancelText="取消"
        destroyOnHidden
      >
        <Form
          form={editForm}
          key={editTarget?.id}
          layout="vertical"
          initialValues={editTarget ? { ...EMPTY_RULE, ...editTarget } : EMPTY_RULE}
          onFinish={(values) =>
            editTarget?.id && updateMut.mutate({ id: editTarget.id, body: values })
          }
          preserve={false}
        >
          {ruleFormItems}
        </Form>
      </Modal>
    </>
  );
}
