// Slice 65:平台运维代租户管理 SWG 规则(URL 过滤)。套用 TenantFWRules(Slice64)模板。
// list(GET)+ 新建(POST)+ 编辑(PUT 全量替换)+ 删除(DELETE)。编辑预填 initialValues+key(Slice52)。
import { useState } from 'react';
import {
  Table,
  Tag,
  Button,
  Space,
  Modal,
  Form,
  Input,
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

type SWGRule = components['schemas']['SWGRule'];

const KIND_OPTIONS = [
  { value: 'host', label: 'host(域名)' },
  { value: 'path_prefix', label: 'path_prefix(路径前缀)' },
];
const ACTION_OPTIONS = [{ value: 'block', label: 'block(阻断)' }];
const EMPTY_RULE: SWGRule = { kind: 'host', pattern: '', action: 'block' };

async function fetchRules(tid: string): Promise<SWGRule[]> {
  const { data, error, response } = await client.GET('/api/v1/tenants/{tid}/swg/rules', {
    params: { path: { tid } },
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}
async function createRule(tid: string, body: SWGRule): Promise<SWGRule> {
  const { data, error, response } = await client.POST('/api/v1/tenants/{tid}/swg/rules', {
    params: { path: { tid } },
    body,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as SWGRule;
}
async function updateRule(tid: string, id: string, body: SWGRule): Promise<SWGRule> {
  const { data, error, response } = await client.PUT('/api/v1/tenants/{tid}/swg/rules/{id}', {
    params: { path: { tid, id } },
    body,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as SWGRule;
}
async function deleteRule(tid: string, id: string): Promise<void> {
  const { error, response } = await client.DELETE('/api/v1/tenants/{tid}/swg/rules/{id}', {
    params: { path: { tid, id } },
  });
  if (error || !response.ok) throw toApiError(response, error);
}

export default function TenantSWGRules({ tenantId }: { tenantId: string }) {
  const { message } = AntdApp.useApp();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<SWGRule | null>(null);
  const [createForm] = Form.useForm<SWGRule>();
  const [editForm] = Form.useForm<SWGRule>();

  const qkey = ['tenant-swg-rules', tenantId];
  const query = useQuery({ queryKey: qkey, queryFn: () => fetchRules(tenantId), enabled: tenantId !== '' });
  const invalidate = () => qc.invalidateQueries({ queryKey: qkey });

  const createMut = useMutation({
    mutationFn: (body: SWGRule) => createRule(tenantId, body),
    onSuccess: () => {
      message.success('SWG 规则已创建');
      setCreateOpen(false);
      createForm.resetFields();
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '创建失败'),
  });
  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: SWGRule }) => updateRule(tenantId, id, body),
    onSuccess: () => {
      message.success('SWG 规则已更新');
      setEditTarget(null);
      editForm.resetFields();
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '更新失败'),
  });
  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteRule(tenantId, id),
    onSuccess: () => {
      message.success('SWG 规则已删除');
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '删除失败'),
  });

  const columns: ColumnsType<SWGRule> = [
    { title: '类型', dataIndex: 'kind', key: 'kind', width: 120 },
    { title: '模式', dataIndex: 'pattern', key: 'pattern', ellipsis: true },
    {
      title: '动作',
      dataIndex: 'action',
      key: 'action',
      width: 90,
      render: (a: string) => <Tag color="red">{a}</Tag>,
    },
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
            title="删除该 SWG 规则?"
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

  const formItems = (
    <>
      <Form.Item label="类型(kind)" name="kind" rules={[{ required: true, message: '必填' }]}>
        <Select options={KIND_OPTIONS} />
      </Form.Item>
      <Form.Item label="模式(pattern,如 evil.com / /admin)" name="pattern" rules={[{ required: true, message: '必填' }]}>
        <Input placeholder="evil.com" />
      </Form.Item>
      <Form.Item label="动作(action)" name="action" rules={[{ required: true, message: '必填' }]}>
        <Select options={ACTION_OPTIONS} />
      </Form.Item>
    </>
  );

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <Typography.Text type="secondary">允许为默认;命中规则=阻断(PUT 为全量替换)</Typography.Text>
        <Button type="primary" size="small" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
          新建规则
        </Button>
      </div>
      <Table
        rowKey={(r) => r.id ?? `${r.kind}-${r.pattern}`}
        columns={columns}
        dataSource={query.data ?? []}
        loading={query.isFetching}
        pagination={false}
        size="small"
      />

      <Modal
        title="新建 SWG 规则"
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
        <Form form={createForm} layout="vertical" initialValues={EMPTY_RULE} onFinish={(v) => createMut.mutate(v)} preserve={false}>
          {formItems}
        </Form>
      </Modal>

      <Modal
        title="编辑 SWG 规则"
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
          onFinish={(v) => editTarget?.id && updateMut.mutate({ id: editTarget.id, body: v })}
          preserve={false}
        >
          {formItems}
        </Form>
      </Modal>
    </>
  );
}
