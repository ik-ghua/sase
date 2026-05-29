// Slice 41/42:平台运维控制台 Layout 骨架。
// Sider 5 菜单 + Header(标题 + 右上角认证状态 + 退出) + Content<Outlet/>
import { Layout, Menu, Tag, Typography, Button, Space } from 'antd';
import {
  TeamOutlined,
  CloudServerOutlined,
  UserSwitchOutlined,
  AuditOutlined,
  KeyOutlined,
  LogoutOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation, Outlet } from 'react-router-dom';
import { useAuthStore } from '@/stores/auth';

const { Header, Sider, Content } = Layout;
const { Title } = Typography;

const MENU_ITEMS = [
  { key: '/tenants', icon: <TeamOutlined />, label: '租户管理' },
  { key: '/pops', icon: <CloudServerOutlined />, label: 'PoP 注册' },
  { key: '/admins', icon: <UserSwitchOutlined />, label: '平台管理员' },
  { key: '/audit', icon: <AuditOutlined />, label: '平台审计' },
  { key: '/admin-tokens', icon: <KeyOutlined />, label: '管理员令牌' },
];

export default function AdminLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const status = useAuthStore((s) => s.status);
  const role = useAuthStore((s) => s.role);
  const logout = useAuthStore((s) => s.logout);

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  return (
    <Layout style={{ height: '100vh' }}>
      <Sider width={220} theme="dark">
        <div style={{ height: 64, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Title level={5} style={{ color: '#fff', margin: 0 }}>
            SASE 平台
          </Title>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={MENU_ITEMS}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            background: '#fff',
            padding: '0 24px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderBottom: '1px solid #f0f0f0',
          }}
        >
          <Title level={4} style={{ margin: 0 }}>
            SASE 平台运维控制台
          </Title>
          <Space>
            {status === 'authenticated' ? (
              <Tag color="success">已登录{role ? `(${role})` : ''}</Tag>
            ) : (
              <Tag color="default">未登录</Tag>
            )}
            <Button
              size="small"
              icon={<LogoutOutlined />}
              onClick={handleLogout}
              disabled={status !== 'authenticated'}
            >
              退出
            </Button>
          </Space>
        </Header>
        <Content style={{ padding: 24, overflow: 'auto', background: '#f5f5f5' }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
}
