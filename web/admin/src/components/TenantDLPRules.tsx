// Slice 65:平台运维代租户管理 CASB-DLP 规则。套用 TenantFWRules(Slice64)模板。
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

type DLPRule = components['schemas']['DLPRule'];

const MATCH_OPTIONS = [
  { value: 'keyword', label: 'keyword(关键词)' },
  { value: 'regex', label: 'regex(正则)' },
];
const ACTION_OPTIONS = [
  { value: 'block', label: 'block(阻断)' },
  { value: 'alert', label: 'alert(告警)' },
];
const SEVERITY_OPTIONS = [
  { value: 'low', label: 'low' },
  { value: 'medium', label: 'medium' },
  { value: 'high', label: 'high' },
];
const ACTION_COLORS: Record<string, string> = { block: 'red', alert: 'orange' };
const EMPTY_RULE: DLPRule = { name: '', match_type: 'keyword', pattern: '', action: 'alert', severity: 'medium' };

async function fetchRules(tid: string): Promise<DLPRule[]> {
  const { data, error, response } = await client.GET('/api/v1/tenants/{tid}/dlp/rules', {
    params: { path: { tid } },
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}
async function createRule(tid: string, body: DLPRule): Promise<DLPRule> {
  const { data, error, response } = await client.POST('/api/v1/tenants/{tid}/dlp/rules', {
    params: { path: { tid } },
    body,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as DLPRule;
}
async function updateRule(tid: string, id: string, body: DLPRule): Promise<DLPRule> {
  const { data, error, response } = await client.PUT('/api/v1/tenants/{tid}/dlp/rules/{id}', {
    params: { path: { tid, id } },
    body,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as DLPRule;
}
async function deleteRule(tid: string, id: string): Promise<void> {
  const { error, response } = await client.DELETE('/api/v1/tenants/{tid}/dlp/rules/{id}', {
    params: { path: { tid, id } },
  });
  if (error || !response.ok) throw toApiError(response, error);
}

export default function TenantDLPRules({ tenantId }: { tenantId: string }) {
  const { message } = AntdApp.useApp();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<DLPRule | null>(null);
  const [createForm] = Form.useForm<DLPRule>();
  const [editForm] = Form.useForm<DLPRule>();

  const qkey = ['tenant-dlp-rules', tenantId];
  const query = useQuery({ queryKey: qkey, queryFn: () => fetchRules(tenantId), enabled: tenantId !== '' });
  const invalidate = () => qc.invalidateQueries({ queryKey: qkey });

  const createMut = useMutation({
    mutationFn: (body: DLPRule) => createRule(tenantId, body),
    onSuccess: () => {
      message.success('DLP 规则已创建');
      setCreateOpen(false);
      createForm.resetFields();
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '创建失败'),
  });
  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: DLPRule }) => updateRule(tenantId, id, body),
    onSuccess: () => {
      message.success('DLP 规则已更新');
      setEditTarget(null);
      editForm.resetFields();
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '更新失败'),
  });
  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteRule(tenantId, id),
    onSuccess: () => {
      message.success('DLP 规则已删除');
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '删除失败'),
  });

  const columns: ColumnsType<DLPRule> = [
    { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
    { title: '匹配', dataIndex: 'match_type', key: 'match_type', width: 90 },
    { title: '模式', dataIndex: 'pattern', key: 'pattern', ellipsis: true },
    {
      title: '动作',
      dataIndex: 'action',
      key: 'action',
      width: 90,
      render: (a: string) => <Tag color={ACTION_COLORS[a] ?? 'default'}>{a}</Tag>,
    },
    { title: '严重度', dataIndex: 'severity', key: 'severity', width: 90 },
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
            title="删除该 DLP 规则?"
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
      <Form.Item label="名称(name)" name="name" rules={[{ required: true, message: '必填' }]}>
        <Input placeholder="如 身份证号" />
      </Form.Item>
      <Form.Item label="匹配方式(match_type)" name="match_type" rules={[{ required: true, message: '必填' }]}>
        <Select options={MATCH_OPTIONS} />
      </Form.Item>
      <Form.Item label="模式(pattern,关键词或正则)" name="pattern" rules={[{ required: true, message: '必填' }]}>
        <Input placeholder="绝密 / \\d{17}[\\dXx]" />
      </Form.Item>
      <Form.Item label="动作(action)" name="action" rules={[{ required: true, message: '必填' }]}>
        <Select options={ACTION_OPTIONS} />
      </Form.Item>
      <Form.Item label="严重度(severity)" name="severity" rules={[{ required: true, message: '必填' }]}>
        <Select options={SEVERITY_OPTIONS} />
      </Form.Item>
    </>
  );

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <Typography.Text type="secondary">命中喂风险引擎;block 拒绝 / alert 告警(PUT 为全量替换)</Typography.Text>
        <Button type="primary" size="small" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
          新建规则
        </Button>
      </div>
      <Table
        rowKey={(r) => r.id ?? `${r.name}-${r.pattern}`}
        columns={columns}
        dataSource={query.data ?? []}
        loading={query.isFetching}
        pagination={false}
        size="small"
      />

      <Modal
        title="新建 DLP 规则"
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
        title="编辑 DLP 规则"
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
