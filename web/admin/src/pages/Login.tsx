// Slice 42:登录页(dev token 模式 + OIDC 跳转模式)。
//
// dev 模式:粘 SASE_BOOTSTRAP_PLATFORM_ADMIN 启动期签发的 admin token → setDevToken → 探活 → 跳 /
// OIDC 模式:手输 tenant_id + idp_id → 跳 `/api/v1/idp/login?...&return_to=/`(浏览器经 Vite proxy 转后端 :8443)
//
// 注:dev 期无真 IdP sandbox,OIDC 端到端不能跑通(后端 OIDC discovery 会报错);**仅 UI 通**。
import { useEffect, useState } from 'react';
import { Card, Tabs, Input, Button, Form, Typography, Alert, Space } from 'antd';
import { LoginOutlined, KeyOutlined } from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '@/stores/auth';

const { Title, Paragraph, Text } = Typography;
const { TextArea } = Input;

interface LocationState {
  from?: string;
}

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const status = useAuthStore((s) => s.status);
  const detail = useAuthStore((s) => s.detail);
  const setDevToken = useAuthStore((s) => s.setDevToken);
  const probe = useAuthStore((s) => s.probe);

  const [token, setToken] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const from = (location.state as LocationState | null)?.from ?? '/';

  // 登录成功(status=authenticated)→ 跳目标页
  useEffect(() => {
    if (status === 'authenticated') {
      navigate(from, { replace: true });
    }
  }, [status, navigate, from]);

  const handleDevLogin = async () => {
    if (!token.trim()) return;
    setSubmitting(true);
    setDevToken(token.trim());
    await probe();
    setSubmitting(false);
  };

  const handleOIDCJump = (values: { tenant_id: string; idp_id: string }) => {
    const params = new URLSearchParams({
      tenant_id: values.tenant_id.trim(),
      idp_id: values.idp_id.trim(),
      return_to: from,
    });
    // 浏览器跳后端 OIDC 入口(经 Vite proxy 转 :8443);后端 set sase_session cookie 后 302 回 return_to
    window.location.href = `/api/v1/idp/login?${params.toString()}`;
  };

  return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f5f5f5' }}>
      <Card style={{ maxWidth: 560, width: '90%' }}>
        <Title level={3}>登录 SASE 平台运维控制台</Title>
        <Paragraph type="secondary">
          dev 期建议用 bootstrap admin token;真 IdP sandbox 到位后切到 OIDC 模式。
        </Paragraph>

        {status === 'forbidden' && (
          <Alert
            type="warning"
            message="探活已认证但非 platform_admin"
            description={detail}
            style={{ marginBottom: 16 }}
            showIcon
          />
        )}

        <Tabs
          defaultActiveKey="dev"
          items={[
            {
              key: 'dev',
              label: (
                <span>
                  <KeyOutlined /> dev token
                </span>
              ),
              children: (
                <Space direction="vertical" style={{ width: '100%' }}>
                  <Paragraph>
                    后端启动期设 <Text code>SASE_BOOTSTRAP_PLATFORM_ADMIN=&lt;subject&gt;</Text> 会打印一枚 15min platform_admin token,粘到下方:
                  </Paragraph>
                  <TextArea
                    rows={4}
                    placeholder="粘贴 admin token..."
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    style={{ fontFamily: 'var(--font-mono)' }}
                  />
                  <Button
                    type="primary"
                    icon={<LoginOutlined />}
                    onClick={handleDevLogin}
                    loading={submitting}
                    disabled={!token.trim()}
                    block
                  >
                    使用 dev token 登录
                  </Button>
                </Space>
              ),
            },
            {
              key: 'oidc',
              label: (
                <span>
                  <LoginOutlined /> OIDC 跳转
                </span>
              ),
              children: (
                <Form layout="vertical" onFinish={handleOIDCJump}>
                  <Alert
                    type="info"
                    message="dev 期无真 IdP sandbox"
                    description="本模式 UI 通;真跳转需后端配真 corpid/appid + 部署 dex 或对接真 IdP。"
                    style={{ marginBottom: 16 }}
                    showIcon
                  />
                  <Form.Item
                    label="租户 ID(tenant_id)"
                    name="tenant_id"
                    rules={[{ required: true, message: '必填' }]}
                  >
                    <Input placeholder="00000000-0000-0000-0000-000000000000" />
                  </Form.Item>
                  <Form.Item
                    label="IdP 配置 ID(idp_id)"
                    name="idp_id"
                    rules={[{ required: true, message: '必填' }]}
                  >
                    <Input placeholder="00000000-0000-0000-0000-000000000000" />
                  </Form.Item>
                  <Button type="primary" htmlType="submit" icon={<LoginOutlined />} block>
                    跳转 IdP 登录
                  </Button>
                </Form>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
}
