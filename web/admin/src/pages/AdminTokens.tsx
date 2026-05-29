// Slice 48:管理员令牌签发页。POST /platform/admin-tokens 临时机制(IdP 登录到位前)。
// role: tenant_admin/auditor 必带 tenant_id;platform_admin 必空 tenant_id(且 subject 须在 platform_admins 表)。
// **token 只显示一次**(签发结果 Modal + 复制 + 不入审计/日志,后端已保证审计 detail 不含 token)。
import { useState } from 'react';
import {
  Card,
  Form,
  Input,
  InputNumber,
  Select,
  Button,
  Typography,
  Alert,
  Modal,
  Space,
  Descriptions,
  App as AntdApp,
} from 'antd';
import { KeyOutlined, CopyOutlined } from '@ant-design/icons';
import { useMutation } from '@tanstack/react-query';
import { client } from '@/api/client';
import type { components } from '@/api/types';
import { toApiError, ApiError } from '@/lib/api-error';

const { Title, Paragraph, Text } = Typography;

type IssueReq = components['schemas']['IssueAdminTokenRequest'];
type IssueResp = components['schemas']['IssueAdminTokenResponse'];

type Role = 'tenant_admin' | 'auditor' | 'platform_admin';
const ROLE_OPTIONS = [
  { value: 'tenant_admin', label: 'tenant_admin(租户管理员,需 tenant_id)' },
  { value: 'auditor', label: 'auditor(租户审计员,需 tenant_id)' },
  { value: 'platform_admin', label: 'platform_admin(平台管理员,无 tenant_id;须已登记)' },
];

async function issueToken(body: IssueReq): Promise<IssueResp> {
  const { data, error, response } = await client.POST('/api/v1/platform/admin-tokens', { body });
  if (error || !response.ok) throw toApiError(response, error);
  return data as IssueResp;
}

function formatDate(s?: string): string {
  if (!s) return '-';
  try {
    return new Date(s).toLocaleString('zh-CN', { hour12: false });
  } catch {
    return s;
  }
}

export default function AdminTokens() {
  const { message } = AntdApp.useApp();
  const [form] = Form.useForm<IssueReq>();
  const [role, setRole] = useState<Role>('tenant_admin');
  const [issued, setIssued] = useState<IssueResp | null>(null);

  const mut = useMutation({
    mutationFn: issueToken,
    onSuccess: (resp) => {
      setIssued(resp);
      form.resetFields();
      setRole('tenant_admin');
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          message.error('subject 不在 platform_admins 表或角色不符(403)');
          return;
        }
        if (err.status === 503) {
          message.error('平台 RBAC 未配置(503)');
          return;
        }
      }
      message.error(err instanceof Error ? err.message : '签发失败');
    },
  });

  const isPlatformAdmin = role === 'platform_admin';

  const handleCopy = async () => {
    if (issued?.token) {
      try {
        await navigator.clipboard.writeText(issued.token);
        message.success('已复制到剪贴板');
      } catch {
        message.warning('复制失败,请手动选择文本复制');
      }
    }
  };

  return (
    <Card>
      <Title level={3}>管理员令牌签发</Title>
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        message="临时机制"
        description="IdP-based 管理员登录到位前的应急签发(签名令牌 ≤12h TTL)。生产终态应走 IdP 登录换令牌。token 只显示一次,签发后请立即取用。"
      />

      <Form
        form={form}
        layout="vertical"
        style={{ maxWidth: 520 }}
        onFinish={(values) => mut.mutate(values)}
        initialValues={{ role: 'tenant_admin' }}
      >
        <Form.Item label="主体(subject)" name="subject" rules={[{ required: true, message: '必填' }]}>
          <Input placeholder="如 cust-admin / ops-alice" />
        </Form.Item>

        <Form.Item label="角色(role)" name="role" rules={[{ required: true }]}>
          <Select options={ROLE_OPTIONS} onChange={(v: Role) => setRole(v)} />
        </Form.Item>

        {!isPlatformAdmin && (
          <Form.Item
            label="租户 ID(tenant_id)"
            name="tenant_id"
            rules={[{ required: true, message: 'tenant_admin/auditor 必填 tenant_id' }]}
          >
            <Input placeholder="00000000-0000-0000-0000-000000000000" />
          </Form.Item>
        )}
        {isPlatformAdmin && (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message="platform_admin 无需 tenant_id"
            description="该 subject 必须已在「平台管理员」页登记且状态 active,否则后端拒(403)。"
          />
        )}

        <Form.Item
          label="有效期(秒,留空/0/超 12h → 钳至 12h)"
          name="ttl_seconds"
          tooltip="MaxAdminTTL = 12h"
        >
          <InputNumber min={0} style={{ width: '100%' }} placeholder="默认 12h" />
        </Form.Item>

        <Form.Item>
          <Button type="primary" htmlType="submit" icon={<KeyOutlined />} loading={mut.isPending}>
            签发令牌
          </Button>
        </Form.Item>
      </Form>

      {/* 签发结果 Modal:token 只显示一次 */}
      <Modal
        title="令牌已签发(只显示一次)"
        open={issued !== null}
        onCancel={() => setIssued(null)}
        footer={[
          <Button key="close" onClick={() => setIssued(null)}>
            关闭
          </Button>,
        ]}
        width={640}
        destroyOnHidden
      >
        <Alert
          type="success"
          showIcon
          style={{ marginBottom: 16 }}
          message="请立即复制保存"
          description="关闭后无法再查看此 token。token 不入审计/日志(后端已保证)。"
        />
        {issued && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="subject">{issued.subject}</Descriptions.Item>
            <Descriptions.Item label="role">{issued.role}</Descriptions.Item>
            <Descriptions.Item label="tenant_id">{issued.tenant_id || '(无,平台级)'}</Descriptions.Item>
            <Descriptions.Item label="过期时间">{formatDate(issued.expires_at)}</Descriptions.Item>
            <Descriptions.Item label="token">
              <Space direction="vertical" style={{ width: '100%' }}>
                <Input.TextArea
                  value={issued.token}
                  readOnly
                  rows={4}
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}
                />
                <Button icon={<CopyOutlined />} onClick={handleCopy}>
                  复制 token
                </Button>
              </Space>
            </Descriptions.Item>
          </Descriptions>
        )}
        <Paragraph type="secondary" style={{ marginTop: 16 }}>
          用法:把 token 粘到登录页「dev token」Tab,或客户端 <Text code>Authorization: Bearer &lt;token&gt;</Text>。
        </Paragraph>
      </Modal>
    </Card>
  );
}
