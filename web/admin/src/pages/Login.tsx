// Slice 42 + W2:登录页(令牌登录模式 + OIDC 跳转模式)。
//
// 令牌登录(W2):粘 admin 令牌(bootstrap / admin-tokens 签出)→ login() → POST /api/v1/login
//   → 后端验签后 Set-Cookie HttpOnly sase_session → 探活 → 跳 /。**令牌不落 localStorage**(只进 HttpOnly cookie,消除 XSS 面)。
// OIDC 模式:手输 tenant_id + idp_id → 跳 `/api/v1/idp/login?...&return_to=/`(浏览器经 Vite proxy 转后端 :8443)。
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
  const login = useAuthStore((s) => s.login);

  const [token, setToken] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const from = (location.state as LocationState | null)?.from ?? '/';

  // 登录成功(status=authenticated)→ 跳目标页
  useEffect(() => {
    if (status === 'authenticated') {
      navigate(from, { replace: true });
    }
  }, [status, navigate, from]);

  // 令牌登录(W2):POST /api/v1/login 种 HttpOnly cookie → 探活。令牌不落 localStorage。
  const handleTokenLogin = async () => {
    if (!token.trim()) return;
    setSubmitting(true);
    await login(token.trim());
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

        {status === 'unauthenticated' && detail && detail !== '主动登出' && (
          <Alert
            type="error"
            message="登录失败"
            description={detail}
            style={{ marginBottom: 16 }}
            showIcon
          />
        )}

        <Tabs
          defaultActiveKey="token"
          items={[
            {
              key: 'token',
              label: (
                <span>
                  <KeyOutlined /> 令牌登录
                </span>
              ),
              children: (
                <Space direction="vertical" style={{ width: '100%' }}>
                  <Paragraph>
                    后端启动期设 <Text code>SASE_BOOTSTRAP_PLATFORM_ADMIN=&lt;subject&gt;</Text> 会打印一枚 platform_admin
                    令牌(或经 admin-tokens 签发),粘到下方登录。令牌只换取 <Text code>HttpOnly</Text> 会话 cookie,
                    <Text strong>不存浏览器本地</Text>。
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
                    onClick={handleTokenLogin}
                    loading={submitting}
                    disabled={!token.trim()}
                    block
                  >
                    登录
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
