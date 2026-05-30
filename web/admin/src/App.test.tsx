// Slice 41/42 smoke 测试:
//  ① Login 页渲染(无 mock 鉴权时)
//  ② AdminLayout 渲染(mock authenticated)
//  ③ AuthGuard probing → Spin
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import AdminLayout from './layouts/AdminLayout';
import Dashboard from './pages/Dashboard';
import Login from './pages/Login';
import AuthGuard from './components/AuthGuard';
import { useAuthStore } from './stores/auth';

// Dashboard(Slice 63)用 useQuery 拉数据;smoke 测试只验布局,mock client 返空避免真 fetch。
vi.mock('@/api/client', () => ({
  client: { GET: vi.fn().mockResolvedValue({ data: [], response: { ok: true, status: 200 } }) },
}));

function renderWith(ui: React.ReactElement, initialEntries: string[] = ['/']) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>
      </QueryClientProvider>
    </ConfigProvider>,
  );
}

describe('Slice 41/42 smoke', () => {
  beforeEach(() => {
    // 重置 zustand auth state(每个测试独立);probe/login 用 mock 跳过真 fetch
    useAuthStore.setState({
      status: 'unauthenticated',
      role: undefined,
      detail: undefined,
      probe: vi.fn().mockResolvedValue(undefined),
      login: vi.fn().mockResolvedValue(undefined),
      logout: useAuthStore.getState().logout,
    });
  });

  it('AdminLayout 渲染 "SASE 平台运维控制台" header', () => {
    renderWith(
      <Routes>
        <Route path="/" element={<AdminLayout />}>
          <Route index element={<Dashboard />} />
        </Route>
      </Routes>,
    );
    expect(screen.getByText('SASE 平台运维控制台')).toBeInTheDocument();
  });

  it('Login 页渲染 令牌登录 + OIDC 两个 Tab', () => {
    renderWith(<Login />, ['/login']);
    expect(screen.getByText('登录 SASE 平台运维控制台')).toBeInTheDocument();
    expect(screen.getByText('令牌登录')).toBeInTheDocument();
    expect(screen.getByText('OIDC 跳转')).toBeInTheDocument();
  });

  it('AuthGuard 在 probing 状态显示 Spin', () => {
    // 设 status=probing
    useAuthStore.setState({ status: 'probing' });
    renderWith(
      <Routes>
        <Route element={<AuthGuard />}>
          <Route path="/" element={<div>受保护页</div>} />
        </Route>
      </Routes>,
    );
    expect(screen.getByText('鉴权探活中...')).toBeInTheDocument();
  });

  it('AuthGuard 在 authenticated 状态渲染 children', async () => {
    useAuthStore.setState({ status: 'authenticated', role: 'platform_admin' });
    renderWith(
      <Routes>
        <Route element={<AuthGuard />}>
          <Route path="/" element={<div>受保护页内容</div>} />
        </Route>
      </Routes>,
    );
    await waitFor(() => {
      expect(screen.getByText('受保护页内容')).toBeInTheDocument();
    });
  });

  it('AuthGuard 在 forbidden 状态显示 403 提示', () => {
    useAuthStore.setState({ status: 'forbidden', detail: '角色非 platform_admin' });
    renderWith(
      <Routes>
        <Route element={<AuthGuard />}>
          <Route path="/" element={<div>不应渲染</div>} />
        </Route>
      </Routes>,
    );
    expect(screen.getByText('无权访问平台运维控制台')).toBeInTheDocument();
    expect(screen.queryByText('不应渲染')).not.toBeInTheDocument();
  });
});
