// W2 登录页测试:令牌登录走 POST /api/v1/login(种 HttpOnly cookie)→ 探活;失败显错。
//   ① 粘令牌点登录 → 调 client.POST('/api/v1/login', {body:{token}}) → 探活 → authenticated。
//   ② 登录失败(后端 401)→ status=unauthenticated + 显示「登录失败」Alert(detail)。
//   ③ OIDC tab 跳转(window.location.href)保留。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { MemoryRouter } from 'react-router-dom';
import Login from './Login';
import { useAuthStore } from '@/stores/auth';

// mock api client(POST /login + 探活 GET);mock auth-probe 由 store.login 真调,故 mock client。
const { post, get } = vi.hoisted(() => ({ post: vi.fn(), get: vi.fn() }));
vi.mock('@/api/client', () => ({
  client: { POST: post, GET: get },
  setUnauthorizedHandler: vi.fn(),
}));

function renderLogin() {
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntdApp>
        <MemoryRouter initialEntries={['/login']}>
          <Login />
        </MemoryRouter>
      </AntdApp>
    </ConfigProvider>,
  );
}

describe('W2 Login 令牌登录', () => {
  beforeEach(() => {
    post.mockReset();
    get.mockReset();
    // 重置真实 store(login 用真实实现,经 mock client 走 POST /login + 探活 GET)
    useAuthStore.setState({
      status: 'unauthenticated',
      role: undefined,
      detail: undefined,
    });
  });

  it('粘令牌点登录 → POST /api/v1/login 携 token + 探活成功 → authenticated', async () => {
    // login 成功:POST /login → 200;探活两步 GET(trust/pubkey + platform/tenants)→ 200
    post.mockResolvedValue({ response: { ok: true, status: 200 }, data: { role: 'platform_admin' } });
    get.mockResolvedValue({ response: { ok: true, status: 200 }, data: [] });

    renderLogin();
    fireEvent.change(screen.getByPlaceholderText('粘贴 admin token...'), {
      target: { value: 'fake.admin.token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /登\s*录/ }));

    await waitFor(() => {
      expect(post).toHaveBeenCalledWith('/api/v1/login', { body: { token: 'fake.admin.token' } });
    });
    await waitFor(() => {
      expect(useAuthStore.getState().status).toBe('authenticated');
    });
  });

  it('登录失败(后端 401)→ unauthenticated + 显示「登录失败」', async () => {
    post.mockResolvedValue({ response: { ok: false, status: 401 }, error: 'unauthorized' });

    renderLogin();
    fireEvent.change(screen.getByPlaceholderText('粘贴 admin token...'), {
      target: { value: 'bad.token' },
    });
    fireEvent.click(screen.getByRole('button', { name: /登\s*录/ }));

    await waitFor(() => {
      expect(screen.getByText('登录失败')).toBeInTheDocument();
    });
    expect(useAuthStore.getState().status).toBe('unauthenticated');
    // 探活 GET 不应被调(login 在 POST 失败时早返,不进探活)
    expect(get).not.toHaveBeenCalled();
  });
});
