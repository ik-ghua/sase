// Slice 42:鉴权 Guard 路由包裹。
// 启动时调 useAuthStore.probe() 一次,据 status 渲染:
//   probing → 全屏 Spin
//   unauthenticated → 跳 /login
//   forbidden(已认证但非 platform_admin)→ 提示页 + 重新登录按钮
//   authenticated → 渲染 children
import { useEffect } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { Spin, Result, Button } from 'antd';
import { useAuthStore } from '@/stores/auth';

export default function AuthGuard() {
  const status = useAuthStore((s) => s.status);
  const detail = useAuthStore((s) => s.detail);
  const probe = useAuthStore((s) => s.probe);
  const logout = useAuthStore((s) => s.logout);
  const location = useLocation();

  useEffect(() => {
    // 应用 mount 时探活一次;若已是 authenticated/forbidden 也再探一次(便重新登录后刷新)
    probe();
  }, [probe]);

  if (status === 'probing') {
    return (
      <div
        style={{
          height: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 16,
        }}
      >
        <Spin size="large" />
        <span style={{ color: '#666' }}>鉴权探活中...</span>
      </div>
    );
  }

  if (status === 'unauthenticated') {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  if (status === 'forbidden') {
    return (
      <Result
        status="403"
        title="无权访问平台运维控制台"
        subTitle={detail ?? '当前账号非 platform_admin 角色'}
        extra={
          <Button type="primary" onClick={logout}>
            退出并重新登录
          </Button>
        }
      />
    );
  }

  // status === 'authenticated'
  return <Outlet />;
}
