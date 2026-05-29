// Slice 43:租户列表页(真接 GET /api/v1/platform/tenants)。
// Slice 50(g):加「详情」操作列 + Drawer —— 详情 Descriptions + PATCH 编辑 + 注销/取消注销生命周期。
//   - PATCH /api/v1/tenants/{tid}(platform_admin only):只发改动字段(buildPatch diff);
//     配额语义:留空=不改、0=限死、**暂不能改回「不限」(LP-PC1,后端 *int 无 clear-flag)**。
//   - 注销 POST /platform/tenants/{tid}/decommission(可选 grace_hours,缺省 30 天);
//     取消 POST .../decommission/cancel(409=不在宽限期)。
//   - Drawer 直接用列表行的 TenantSummary(已含全部可编辑字段),不额外 GET /tenants/{tid}。
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Space,
  Typography,
  Tooltip,
  Drawer,
  Descriptions,
  Divider,
  Alert,
  Modal,
  Form,
  Input,
  InputNumber,
  Select,
  Popconfirm,
  App as AntdApp,
} from 'antd';
import { ReloadOutlined, EditOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { ColumnsType } from 'antd/es/table';
import { client } from '@/api/client';
import type { components } from '@/api/types';
import { toApiError, ApiError } from '@/lib/api-error';
import AppError from '@/components/AppError';
import TenantFWRules from '@/components/TenantFWRules';
import TenantSWGRules from '@/components/TenantSWGRules';
import TenantDLPRules from '@/components/TenantDLPRules';

const { Title } = Typography;

type TenantSummary = components['schemas']['TenantSummary'];
type Tenant = components['schemas']['Tenant'];
type TenantPatch = components['schemas']['TenantPatch'];
type User = components['schemas']['User'];
type CompileResult = components['schemas']['CompileResult'];
type Policy = components['schemas']['Policy'];

// status → Tag 颜色映射(与后端枚举对齐:Slice 33b/c)
const STATUS_COLORS: Record<string, string> = {
  active: 'success',
  suspended: 'warning',
  offboarding: 'processing',
  decommissioned: 'default',
};

// 已知 status 集合(Slice 33b/c/35)— 提供 status 列筛选选项
const KNOWN_STATUSES = ['active', 'suspended', 'offboarding', 'decommissioned'];

// PATCH 表单 status 选项:仅 active/suspended(停用/恢复);offboarding 走专用注销/取消按钮
const PATCH_STATUS_OPTIONS = [
  { value: 'active', label: 'active(启用)' },
  { value: 'suspended', label: 'suspended(停用)' },
];

async function fetchTenants(): Promise<TenantSummary[]> {
  const { data, error, response } = await client.GET('/api/v1/platform/tenants');
  if (error || !response.ok) {
    throw toApiError(response, error);
  }
  return data ?? [];
}

async function patchTenant(tid: string, patch: TenantPatch): Promise<Tenant> {
  const { data, error, response } = await client.PATCH('/api/v1/tenants/{tid}', {
    params: { path: { tid } },
    body: patch,
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data as Tenant;
}

async function decommissionTenant(tid: string, graceHours?: number): Promise<Tenant> {
  // grace_hours 缺省/非正数 → 后端默认 30 天;留空时不发该字段
  const body = typeof graceHours === 'number' ? { grace_hours: graceHours } : {};
  const { data, error, response } = await client.POST(
    '/api/v1/platform/tenants/{tid}/decommission',
    { params: { path: { tid } }, body },
  );
  if (error || !response.ok) throw toApiError(response, error);
  return data as Tenant;
}

async function cancelDecommission(tid: string): Promise<Tenant> {
  const { data, error, response } = await client.POST(
    '/api/v1/platform/tenants/{tid}/decommission/cancel',
    { params: { path: { tid } } },
  );
  if (error || !response.ok) throw toApiError(response, error);
  return data as Tenant;
}

// Slice57:租户详情深化——platform_admin 读目标租户的用户/激活策略。
// 后端 handler 用 path tid 做 RLS 上下文(与 caller 角色无关),故 platform_admin 可读任意租户。
async function fetchTenantUsers(tid: string): Promise<User[]> {
  const { data, error, response } = await client.GET('/api/v1/tenants/{tid}/users', {
    params: { path: { tid } },
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}

// 激活策略只有 bundle 摘要可读(version/hash);无 GET 策略明细列表(待后端加)。
// 无激活 bundle 时后端 404 → 返 null(UI 显示「无激活策略」)。
async function fetchTenantBundle(tid: string): Promise<CompileResult | null> {
  const { data, error, response } = await client.GET('/api/v1/tenants/{tid}/policies/bundle', {
    params: { path: { tid } },
  });
  if (response.status === 404) return null;
  if (error || !response.ok) throw toApiError(response, error);
  return (data as CompileResult) ?? null;
}

// 编写态策略列表(Slice58 后端补 GET /policies)。
async function fetchTenantPolicies(tid: string): Promise<Policy[]> {
  const { data, error, response } = await client.GET('/api/v1/tenants/{tid}/policies', {
    params: { path: { tid } },
  });
  if (error || !response.ok) throw toApiError(response, error);
  return data ?? [];
}

function formatDate(s?: string | null): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleString('zh-CN', { hour12: false });
  } catch {
    return s;
  }
}

function formatQuota(n?: number | null): string {
  if (n === null || n === undefined) return '不限';
  return n.toLocaleString('zh-CN');
}

// 把 PATCH 返回的 Tenant 合并回行级 TenantSummary(保留 created_at;Tenant 不含该字段)。
function mergeTenant(prev: TenantSummary, t: Tenant): TenantSummary {
  return {
    ...prev,
    name: t.name ?? prev.name,
    status: t.status ?? prev.status,
    plan: t.plan ?? prev.plan,
    decommission_at: t.decommission_at ?? null,
    max_users: t.max_users ?? null,
    max_policies: t.max_policies ?? null,
    max_bandwidth_mbps: t.max_bandwidth_mbps ?? null,
  };
}

// 只挑「相对当前值有改动」的字段(PATCH 语义:不提供=不改)。
// 配额:仅当填了数字(含 0)且不同于当前才发;留空 → 跳过(无法改回 null,LP-PC1)。
function buildPatch(orig: TenantSummary, v: TenantPatch): TenantPatch {
  const p: TenantPatch = {};
  if (typeof v.name === 'string' && v.name.trim() && v.name.trim() !== orig.name) {
    p.name = v.name.trim();
  }
  if (v.status && v.status !== orig.status) p.status = v.status;
  if (typeof v.plan === 'string' && v.plan.trim() && v.plan.trim() !== orig.plan) {
    p.plan = v.plan.trim();
  }
  const quotaKeys = ['max_users', 'max_policies', 'max_bandwidth_mbps'] as const;
  for (const k of quotaKeys) {
    const nv = v[k];
    if (typeof nv === 'number' && nv !== orig[k]) p[k] = nv;
  }
  return p;
}

// 行展示列(纯函数,模块级);操作列在组件内拼接(需要 handler)。
const baseColumns: ColumnsType<TenantSummary> = [
  {
    title: 'ID',
    dataIndex: 'id',
    key: 'id',
    width: 110,
    render: (id?: string) =>
      id ? (
        <Tooltip title={id}>
          <span style={{ fontFamily: 'var(--font-mono)' }}>{id.slice(0, 8)}</span>
        </Tooltip>
      ) : (
        '-'
      ),
  },
  { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
  {
    title: '状态',
    dataIndex: 'status',
    key: 'status',
    width: 140,
    filters: KNOWN_STATUSES.map((s) => ({ text: s, value: s })),
    onFilter: (value, record) => record.status === value,
    render: (status?: string) => (
      <Tag color={STATUS_COLORS[status ?? ''] ?? 'default'}>{status ?? 'unknown'}</Tag>
    ),
  },
  { title: '套餐', dataIndex: 'plan', key: 'plan', width: 120 },
  { title: '用户上限', dataIndex: 'max_users', key: 'max_users', width: 110, render: formatQuota },
  {
    title: '策略上限',
    dataIndex: 'max_policies',
    key: 'max_policies',
    width: 110,
    render: formatQuota,
  },
  {
    title: '带宽上限 (Mbps)',
    dataIndex: 'max_bandwidth_mbps',
    key: 'max_bandwidth_mbps',
    width: 140,
    render: formatQuota,
  },
  {
    title: '创建时间',
    dataIndex: 'created_at',
    key: 'created_at',
    width: 180,
    render: formatDate,
    sorter: (a, b) => {
      const ta = a.created_at ? new Date(a.created_at).getTime() : 0;
      const tb = b.created_at ? new Date(b.created_at).getTime() : 0;
      return ta - tb;
    },
  },
  {
    title: '注销时间',
    dataIndex: 'decommission_at',
    key: 'decommission_at',
    width: 180,
    render: formatDate,
  },
];

export default function Tenants() {
  const { message } = AntdApp.useApp();
  const qc = useQueryClient();
  const [searchStatus] = useState<string | undefined>();
  const [detailTarget, setDetailTarget] = useState<TenantSummary | null>(null);
  const [decommissionOpen, setDecommissionOpen] = useState(false);
  const [editForm] = Form.useForm<TenantPatch>();
  const [graceForm] = Form.useForm<{ grace_hours?: number }>();

  const query = useQuery({
    queryKey: ['platform-tenants'],
    queryFn: fetchTenants,
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ['platform-tenants'] });

  // Slice57:Drawer 打开时懒加载目标租户的用户/激活策略(enabled 跟 detailTarget;关闭即停)。
  const detailTid = detailTarget?.id ?? '';
  const usersQuery = useQuery({
    queryKey: ['tenant-users', detailTid],
    queryFn: () => fetchTenantUsers(detailTid),
    enabled: detailTid !== '',
  });
  const bundleQuery = useQuery({
    queryKey: ['tenant-bundle', detailTid],
    queryFn: () => fetchTenantBundle(detailTid),
    enabled: detailTid !== '',
  });
  const policiesQuery = useQuery({
    queryKey: ['tenant-policies', detailTid],
    queryFn: () => fetchTenantPolicies(detailTid),
    enabled: detailTid !== '',
  });

  // 回填编辑表单(PATCH 基线):name/plan/quota 显示当前值,status 仅 active/suspended 可选。
  const fillForm = useCallback(
    (t: TenantSummary) => {
      editForm.setFieldsValue({
        name: t.name,
        status: t.status === 'active' || t.status === 'suspended' ? t.status : undefined,
        plan: t.plan,
        max_users: t.max_users ?? undefined,
        max_policies: t.max_policies ?? undefined,
        max_bandwidth_mbps: t.max_bandwidth_mbps ?? undefined,
      });
    },
    [editForm],
  );

  // 目标更新(PATCH/注销/取消后 merge)时回填;**初次打开由 Drawer afterOpenChange 兜底**
  // —— destroyOnClose 下 Form 实例在 effect 运行时可能尚未连接(antd "useForm not connected"),
  // afterOpenChange 在开场动画后触发,此时 Form 已连上,setFieldsValue 才生效(Slice51 真浏览器 e2e 揪出)。
  useEffect(() => {
    if (detailTarget) fillForm(detailTarget);
  }, [detailTarget, fillForm]);

  const patchMut = useMutation({
    mutationFn: ({ tid, patch }: { tid: string; patch: TenantPatch }) => patchTenant(tid, patch),
    onSuccess: (t) => {
      message.success('租户已更新');
      setDetailTarget((prev) => (prev ? mergeTenant(prev, t) : prev));
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '更新失败'),
  });

  const decommissionMut = useMutation({
    mutationFn: ({ tid, graceHours }: { tid: string; graceHours?: number }) =>
      decommissionTenant(tid, graceHours),
    onSuccess: (t) => {
      message.success('租户已进入注销宽限期');
      setDecommissionOpen(false);
      graceForm.resetFields();
      setDetailTarget((prev) => (prev ? mergeTenant(prev, t) : prev));
      invalidate();
    },
    onError: (err) => message.error(err instanceof Error ? err.message : '注销失败'),
  });

  const cancelMut = useMutation({
    mutationFn: (tid: string) => cancelDecommission(tid),
    onSuccess: (t) => {
      message.success('已取消注销,租户恢复 active');
      setDetailTarget((prev) => (prev ? mergeTenant(prev, t) : prev));
      invalidate();
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) {
        message.error('该租户不在注销宽限期,无法取消');
      } else {
        message.error(err instanceof Error ? err.message : '取消失败');
      }
    },
  });

  const onSavePatch = (values: TenantPatch) => {
    if (!detailTarget?.id) return;
    const patch = buildPatch(detailTarget, values);
    if (Object.keys(patch).length === 0) {
      message.info('无修改');
      return;
    }
    patchMut.mutate({ tid: detailTarget.id, patch });
  };

  // 客户端筛选(后端 Slice 32 List 端点暂无 query param 过滤;前端先做)
  const filtered = useMemo(() => {
    const list = query.data ?? [];
    if (!searchStatus) return list;
    return list.filter((t) => t.status === searchStatus);
  }, [query.data, searchStatus]);

  const columns: ColumnsType<TenantSummary> = [
    ...baseColumns,
    {
      title: '操作',
      key: 'actions',
      width: 90,
      fixed: 'right',
      render: (_, record) => (
        <Button size="small" icon={<EditOutlined />} onClick={() => setDetailTarget(record)}>
          详情
        </Button>
      ),
    },
  ];

  const status = detailTarget?.status;
  const statusEditable = status === 'active' || status === 'suspended';
  const isOffboarding = status === 'offboarding';
  const isDecommissioned = status === 'decommissioned';

  return (
    <Card>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={3} style={{ margin: 0 }}>
          租户管理
        </Title>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => query.refetch()}
            loading={query.isFetching}
          >
            刷新
          </Button>
        </Space>
      </div>

      {query.isError && <AppError error={query.error} onRetry={() => query.refetch()} />}

      <Table
        rowKey={(row) => row.id ?? ''}
        columns={columns}
        dataSource={filtered}
        loading={query.isLoading}
        pagination={{ pageSize: 20, showSizeChanger: true, showTotal: (n) => `共 ${n} 条` }}
        scroll={{ x: 1380 }}
        size="middle"
      />

      {/* 详情 / 编辑 / 生命周期 Drawer */}
      <Drawer
        title={detailTarget ? `租户「${detailTarget.name}」` : '租户详情'}
        open={detailTarget !== null}
        onClose={() => setDetailTarget(null)}
        width={540}
        destroyOnClose
        afterOpenChange={(open) => {
          if (open && detailTarget) fillForm(detailTarget);
        }}
      >
        {detailTarget && (
          <>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="ID">{detailTarget.id ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={STATUS_COLORS[detailTarget.status ?? ''] ?? 'default'}>
                  {detailTarget.status ?? 'unknown'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="套餐">{detailTarget.plan ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="用户上限">
                {formatQuota(detailTarget.max_users)}
              </Descriptions.Item>
              <Descriptions.Item label="策略上限">
                {formatQuota(detailTarget.max_policies)}
              </Descriptions.Item>
              <Descriptions.Item label="带宽上限 (Mbps)">
                {formatQuota(detailTarget.max_bandwidth_mbps)}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDate(detailTarget.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="注销时间">
                {formatDate(detailTarget.decommission_at)}
              </Descriptions.Item>
            </Descriptions>

            {isDecommissioned ? (
              <Alert
                style={{ marginTop: 16 }}
                type="info"
                showIcon
                message="该租户已注销(终态),不可操作。"
              />
            ) : (
              <>
                <Divider>编辑租户</Divider>
                <Form form={editForm} layout="vertical" onFinish={onSavePatch} preserve={false}>
                  <Form.Item label="名称(name)" name="name">
                    <Input placeholder="租户名称" />
                  </Form.Item>
                  {statusEditable && (
                    <Form.Item
                      label="状态(停用/恢复)"
                      name="status"
                      tooltip="注销 / 取消注销请用下方「生命周期」按钮(会同步设置宽限期)"
                    >
                      <Select options={PATCH_STATUS_OPTIONS} />
                    </Form.Item>
                  )}
                  <Form.Item label="套餐(plan)" name="plan">
                    <Input placeholder="如 standard / gm" />
                  </Form.Item>
                  <Form.Item
                    label="用户上限(max_users)"
                    name="max_users"
                    tooltip="留空=不改;0=限死;暂不能改回「不限」(LP-PC1)"
                  >
                    <InputNumber min={0} style={{ width: '100%' }} placeholder="不改" />
                  </Form.Item>
                  <Form.Item
                    label="策略上限(max_policies)"
                    name="max_policies"
                    tooltip="留空=不改;0=限死"
                  >
                    <InputNumber min={0} style={{ width: '100%' }} placeholder="不改" />
                  </Form.Item>
                  <Form.Item
                    label="带宽上限 Mbps(max_bandwidth_mbps)"
                    name="max_bandwidth_mbps"
                    tooltip="留空=不改;0=限死"
                  >
                    <InputNumber min={0} style={{ width: '100%' }} placeholder="不改" />
                  </Form.Item>
                  <Button type="primary" htmlType="submit" loading={patchMut.isPending}>
                    保存修改
                  </Button>
                </Form>

                <Divider>生命周期</Divider>
                {statusEditable && (
                  <Button danger onClick={() => setDecommissionOpen(true)}>
                    注销租户(进入宽限期)
                  </Button>
                )}
                {isOffboarding && (
                  <Space direction="vertical" style={{ width: '100%' }}>
                    <Typography.Text type="warning">
                      注销宽限期至 {formatDate(detailTarget.decommission_at)};宽限期内可取消恢复。
                    </Typography.Text>
                    <Popconfirm
                      title="取消注销?"
                      description="租户将恢复 active。"
                      okText="取消注销"
                      cancelText="返回"
                      onConfirm={() => detailTarget.id && cancelMut.mutate(detailTarget.id)}
                    >
                      <Button loading={cancelMut.isPending}>取消注销(恢复 active)</Button>
                    </Popconfirm>
                  </Space>
                )}
              </>
            )}

            {/* Slice57:用户 + 激活策略(只读;platform_admin 经 path-tid RLS 读目标租户;所有状态可见)*/}
            <Divider>用户</Divider>
            {usersQuery.isError ? (
              <Alert
                type="error"
                showIcon
                message="读取用户失败"
                description={usersQuery.error instanceof Error ? usersQuery.error.message : undefined}
              />
            ) : (
              <Table<User>
                rowKey={(u) => u.id ?? u.external_id ?? ''}
                size="small"
                loading={usersQuery.isFetching}
                dataSource={usersQuery.data ?? []}
                pagination={{ pageSize: 5, hideOnSinglePage: true, size: 'small' }}
                columns={[
                  {
                    title: '外部 ID',
                    dataIndex: 'external_id',
                    key: 'external_id',
                    ellipsis: true,
                    render: (v?: string) => v || '-',
                  },
                  {
                    title: '邮箱',
                    dataIndex: 'email',
                    key: 'email',
                    ellipsis: true,
                    render: (v?: string) => v || '-',
                  },
                  {
                    title: '状态',
                    dataIndex: 'status',
                    key: 'status',
                    width: 90,
                    render: (s?: string) => (
                      <Tag color={s === 'active' ? 'success' : 'default'}>{s ?? '-'}</Tag>
                    ),
                  },
                ]}
              />
            )}

            <Divider>策略</Divider>
            {/* 激活版本(编译产物摘要;404/未编译 → 无激活策略)*/}
            <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
              {bundleQuery.data && bundleQuery.data.version
                ? `激活版本 v${bundleQuery.data.version} · hash ${(bundleQuery.data.content_hash ?? '').slice(0, 12)}`
                : bundleQuery.isFetching
                  ? '激活版本加载中…'
                  : '无激活策略(未编译/未激活)'}
            </Typography.Paragraph>
            {/* 编写态策略列表(Slice58)*/}
            {policiesQuery.isError ? (
              <Alert
                type="error"
                showIcon
                message="读取策略失败"
                description={
                  policiesQuery.error instanceof Error ? policiesQuery.error.message : undefined
                }
              />
            ) : (
              <Table<Policy>
                rowKey={(p) => p.id ?? ''}
                size="small"
                loading={policiesQuery.isFetching}
                dataSource={policiesQuery.data ?? []}
                pagination={{ pageSize: 5, hideOnSinglePage: true, size: 'small' }}
                columns={[
                  { title: '优先级', dataIndex: 'priority', key: 'priority', width: 70 },
                  {
                    title: '主体',
                    key: 'subject',
                    ellipsis: true,
                    render: (_, p) => `${p.subject_kind ?? ''}${p.subject_value ? ':' + p.subject_value : ''}` || '-',
                  },
                  { title: '资源', dataIndex: 'resource', key: 'resource', ellipsis: true, render: (v?: string) => v || '-' },
                  { title: '动作', dataIndex: 'action', key: 'action', width: 80, render: (v?: string) => v || '-' },
                  {
                    title: '效果',
                    dataIndex: 'effect',
                    key: 'effect',
                    width: 90,
                    render: (e?: string) => (
                      <Tag color={e === 'allow' ? 'success' : e === 'deny' ? 'error' : 'warning'}>
                        {e ?? '-'}
                      </Tag>
                    ),
                  },
                ]}
              />
            )}

            {/* Slice64/65:平台运维代租户管理三项安全能力规则(可读写,Slice62 PUT/DELETE 契约)*/}
            <Divider>防火墙规则(FWaaS)</Divider>
            <TenantFWRules tenantId={detailTid} />
            <Divider>安全网关规则(SWG)</Divider>
            <TenantSWGRules tenantId={detailTid} />
            <Divider>数据防泄漏规则(CASB-DLP)</Divider>
            <TenantDLPRules tenantId={detailTid} />
          </>
        )}
      </Drawer>

      {/* 注销宽限期 Modal */}
      <Modal
        title={detailTarget ? `注销租户「${detailTarget.name}」` : '注销租户'}
        open={decommissionOpen}
        onCancel={() => {
          setDecommissionOpen(false);
          graceForm.resetFields();
        }}
        onOk={() => graceForm.submit()}
        confirmLoading={decommissionMut.isPending}
        okText="确认注销"
        okButtonProps={{ danger: true }}
        cancelText="取消"
        destroyOnHidden
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="注销进入宽限期(软删);宽限期末由清扫任务销毁租户密钥(不可逆)。宽限期内可取消。"
        />
        <Form
          form={graceForm}
          layout="vertical"
          preserve={false}
          onFinish={(v) => {
            if (detailTarget?.id) {
              decommissionMut.mutate({ tid: detailTarget.id, graceHours: v.grace_hours });
            }
          }}
        >
          <Form.Item
            label="宽限期(小时,留空=默认 30 天)"
            name="grace_hours"
            tooltip="范围 1–8760 小时(≤365 天);留空走后端默认 30 天(720 小时)"
          >
            <InputNumber min={1} max={8760} style={{ width: '100%' }} placeholder="默认 720(30 天)" />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
