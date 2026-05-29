// Slice 41/42:路由配置。
// 公开:/login
// 鉴权受保护:除 /login 外全部包 AuthGuard(probe → unauthenticated 跳 /login;forbidden 提示)
import { createBrowserRouter, Navigate } from 'react-router-dom';
import AuthGuard from '@/components/AuthGuard';
import AdminLayout from '@/layouts/AdminLayout';
import Dashboard from '@/pages/Dashboard';
import Tenants from '@/pages/Tenants';
import Pops from '@/pages/Pops';
import Admins from '@/pages/Admins';
import Audit from '@/pages/Audit';
import AdminTokens from '@/pages/AdminTokens';
import Login from '@/pages/Login';
import NotFound from '@/pages/NotFound';

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <Login />,
  },
  {
    // 顶层 AuthGuard:probe + 状态分发(authenticated 渲染 children;unauthenticated 跳 /login;forbidden 提示)
    element: <AuthGuard />,
    children: [
      {
        path: '/',
        element: <AdminLayout />,
        children: [
          { index: true, element: <Navigate to="/dashboard" replace /> },
          { path: 'dashboard', element: <Dashboard /> },
          { path: 'tenants', element: <Tenants /> },
          { path: 'pops', element: <Pops /> },
          { path: 'admins', element: <Admins /> },
          { path: 'audit', element: <Audit /> },
          { path: 'admin-tokens', element: <AdminTokens /> },
          { path: '*', element: <NotFound /> },
        ],
      },
    ],
  },
]);
