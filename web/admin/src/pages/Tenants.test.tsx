// Slice 43 Tenants 页测试:mock openapi-fetch client,验三态(loading/success/error)+ 渲染。
// Slice 50(g):加 Drawer 详情 + PATCH(只发改动字段)+ 注销/取消生命周期测试。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import Tenants from './Tenants';

// mock client.GET/PATCH/POST(避免真 fetch);用 vi.hoisted 保证 mock 在 import 前生效
const { mockGET, mockPATCH, mockPOST } = vi.hoisted(() => ({
  mockGET: vi.fn(),
  mockPATCH: vi.fn(),
  mockPOST: vi.fn(),
}));
vi.mock('@/api/client', () => ({
  client: { GET: mockGET, PATCH: mockPATCH, POST: mockPOST },
}));

function renderWith(): ReturnType<typeof render> {
  // 每个测试独立 QueryClient(避免缓存串扰);关 retry 让 error 直接显示
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntdApp>
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <Tenants />
          </MemoryRouter>
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

const activeTenant = {
  id: 'aaaaaaaa-1111-2222-3333-444444444444',
  name: 'TenantA',
  status: 'active',
  plan: 'standard',
  created_at: '2026-01-01T08:00:00Z',
  max_users: 1000,
  max_policies: null,
  max_bandwidth_mbps: 500,
  decommission_at: null,
};

describe('Tenants 页', () => {
  beforeEach(() => {
    mockGET.mockReset();
    mockPATCH.mockReset();
    mockPOST.mockReset();
    // Slice57:Drawer 打开会触发 users/bundle GET;默认兜底返空 ok(各测试的 mockResolvedValueOnce
    // 仍优先用于首个 GET=fetchTenants)。tenants 路径默认空(测试用 once 覆盖)。
    mockGET.mockImplementation((path: string) => {
      if (path === '/api/v1/tenants/{tid}/users') {
        return Promise.resolve({ data: [], response: { ok: true, status: 200 } });
      }
      if (path === '/api/v1/tenants/{tid}/policies/bundle') {
        return Promise.resolve({ data: null, response: { ok: true, status: 200 } });
      }
      if (path === '/api/v1/tenants/{tid}/policies') {
        return Promise.resolve({ data: [], response: { ok: true, status: 200 } });
      }
      // 风险快照默认 404(无快照)— 各测试用 mockImplementation 覆盖具体行为
      if (path === '/api/v1/tenants/{tid}/risk/{subject}') {
        return Promise.resolve({ data: undefined, response: { ok: false, status: 404 } });
      }
      return Promise.resolve({ data: [], response: { ok: true, status: 200 } });
    });
  });

  it('成功路径:渲染租户行', async () => {
    mockGET.mockResolvedValueOnce({ data: [activeTenant], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => {
      expect(screen.getByText('TenantA')).toBeInTheDocument();
    });
    expect(screen.getByText('active')).toBeInTheDocument();
    expect(screen.getByText('standard')).toBeInTheDocument();
  });

  it('空列表:Table 显示无数据(empty)', async () => {
    mockGET.mockResolvedValueOnce({ data: [], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => {
      expect(screen.getAllByText('暂无数据').length).toBeGreaterThan(0);
    });
  });

  it('error 路径:HTTP 500 显示 AppError Result(服务端错误)', async () => {
    mockGET.mockResolvedValueOnce({
      data: undefined,
      error: 'internal error',
      response: { ok: false, status: 500 },
    });
    renderWith();
    await waitFor(() => {
      expect(screen.getByText('服务端错误')).toBeInTheDocument();
    });
    expect(screen.getByText(/HTTP 500/)).toBeInTheDocument();
  });

  it('error 路径:HTTP 401 显示 AppError Alert(未登录)', async () => {
    mockGET.mockResolvedValueOnce({
      data: undefined,
      error: 'unauthorized',
      response: { ok: false, status: 401 },
    });
    renderWith();
    await waitFor(() => {
      expect(screen.getByText('未登录或会话过期')).toBeInTheDocument();
    });
  });

  it('标题与刷新按钮存在', async () => {
    mockGET.mockResolvedValueOnce({ data: [], response: { ok: true, status: 200 } });
    renderWith();
    expect(screen.getByText('租户管理')).toBeInTheDocument();
    expect(screen.getByText('刷新')).toBeInTheDocument();
  });

  // ---- Slice 50(g) 新增 ----

  it('点「详情」打开 Drawer:显示详情 + 编辑表单 + 生命周期按钮', async () => {
    mockGET.mockResolvedValueOnce({ data: [activeTenant], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    await waitFor(() => expect(screen.getByText('租户「TenantA」')).toBeInTheDocument());
    expect(screen.getByText('编辑租户')).toBeInTheDocument();
    expect(screen.getByText('生命周期')).toBeInTheDocument();
    // active 租户可注销
    expect(screen.getByRole('button', { name: /注销租户/ })).toBeInTheDocument();
  });

  it('PATCH 只发改动字段:改名 → body 仅含 name', async () => {
    mockGET.mockResolvedValueOnce({ data: [activeTenant], response: { ok: true, status: 200 } });
    mockPATCH.mockResolvedValueOnce({
      data: { ...activeTenant, name: 'TenantB' },
      response: { ok: true, status: 200 },
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    await waitFor(() => expect(screen.getByText('编辑租户')).toBeInTheDocument());
    // name 预填 TenantA → 改为 TenantB;其余不动
    fireEvent.change(screen.getByPlaceholderText('租户名称'), { target: { value: 'TenantB' } });
    fireEvent.click(screen.getByRole('button', { name: /保存修改/ }));
    await waitFor(() => expect(mockPATCH).toHaveBeenCalledOnce());
    expect(mockPATCH).toHaveBeenCalledWith('/api/v1/tenants/{tid}', {
      params: { path: { tid: activeTenant.id } },
      body: { name: 'TenantB' },
    });
  });

  it('无修改:不调用 PATCH', async () => {
    mockGET.mockResolvedValueOnce({ data: [activeTenant], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    await waitFor(() => expect(screen.getByText('编辑租户')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /保存修改/ }));
    // 等一拍,确认未发起 PATCH
    await waitFor(() => expect(screen.getByText('无修改')).toBeInTheDocument());
    expect(mockPATCH).not.toHaveBeenCalled();
  });

  it('注销:确认 → POST decommission(留空 grace → body 空)', async () => {
    mockGET.mockResolvedValueOnce({ data: [activeTenant], response: { ok: true, status: 200 } });
    mockPOST.mockResolvedValueOnce({
      data: { ...activeTenant, status: 'offboarding', decommission_at: '2026-06-28T08:00:00Z' },
      response: { ok: true, status: 200 },
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    await waitFor(() => expect(screen.getByRole('button', { name: /注销租户/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /注销租户/ }));
    // 注销 Modal 弹出 → 唯一的「确认注销」按钮(grace 留空)
    const confirmBtn = await screen.findByRole('button', { name: /确认注销/ });
    fireEvent.click(confirmBtn);
    await waitFor(() => expect(mockPOST).toHaveBeenCalledOnce());
    expect(mockPOST).toHaveBeenCalledWith('/api/v1/platform/tenants/{tid}/decommission', {
      params: { path: { tid: activeTenant.id } },
      body: {},
    });
  });

  it('offboarding 租户:Drawer 显示「取消注销」按钮', async () => {
    const offboarding = {
      ...activeTenant,
      status: 'offboarding',
      decommission_at: '2026-06-28T08:00:00Z',
    };
    mockGET.mockResolvedValueOnce({ data: [offboarding], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    await waitFor(() => expect(screen.getByText('生命周期')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /取消注销/ })).toBeInTheDocument();
    // offboarding 不显示「注销租户」按钮
    expect(screen.queryByRole('button', { name: /^注销租户/ })).not.toBeInTheDocument();
  });

  it('decommissioned 租户:终态 Alert,无编辑表单', async () => {
    const dead = { ...activeTenant, status: 'decommissioned' };
    mockGET.mockResolvedValueOnce({ data: [dead], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    await waitFor(() =>
      expect(screen.getByText('该租户已注销(终态),不可操作。')).toBeInTheDocument(),
    );
    expect(screen.queryByText('编辑租户')).not.toBeInTheDocument();
  });

  it('Drawer 显示用户列表 + 激活策略版本 + 策略列表(Slice57/58)', async () => {
    mockGET.mockImplementation((path: string) => {
      if (path === '/api/v1/tenants/{tid}/users') {
        return Promise.resolve({
          data: [{ id: 'u1', external_id: 'ext-1', email: 'alice@t.io', status: 'active' }],
          response: { ok: true, status: 200 },
        });
      }
      if (path === '/api/v1/tenants/{tid}/policies/bundle') {
        return Promise.resolve({
          data: { version: 7, content_hash: 'abcdef0123456789', changed: false },
          response: { ok: true, status: 200 },
        });
      }
      if (path === '/api/v1/tenants/{tid}/policies') {
        return Promise.resolve({
          data: [
            {
              id: 'p1',
              name: 'deny-risk',
              priority: 10,
              subject_kind: 'risk_gte',
              subject_value: 'critical',
              resource: 'app-x',
              action: 'access',
              effect: 'deny',
            },
          ],
          response: { ok: true, status: 200 },
        });
      }
      return Promise.resolve({ data: [activeTenant], response: { ok: true, status: 200 } });
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    // 用户区:渲染用户行
    await waitFor(() => expect(screen.getByText('alice@t.io')).toBeInTheDocument());
    expect(screen.getByText('ext-1')).toBeInTheDocument();
    // 策略区:激活版本(在 Paragraph 中,用正则子串匹配)
    expect(screen.getByText(/激活版本 v7/)).toBeInTheDocument();
    // 策略列表:渲染策略行(主体 risk_gte:critical + 效果 deny)
    expect(screen.getByText('risk_gte:critical')).toBeInTheDocument();
    expect(screen.getByText('app-x')).toBeInTheDocument();
  });

  // ---- Slice68 风险列(懒查)----

  // 通用:渲染含一个用户的 Drawer,path-aware mock,risk 行为由 riskResp 决定
  function mockWithRisk(riskResp: { data?: unknown; response: { ok: boolean; status: number } }) {
    mockGET.mockImplementation((path: string) => {
      if (path === '/api/v1/tenants/{tid}/users') {
        return Promise.resolve({
          data: [{ id: 'u1', external_id: 'ext-1', email: 'alice@t.io', status: 'active' }],
          response: { ok: true, status: 200 },
        });
      }
      if (path === '/api/v1/tenants/{tid}/policies/bundle') {
        return Promise.resolve({ data: null, response: { ok: true, status: 200 } });
      }
      if (path === '/api/v1/tenants/{tid}/policies') {
        return Promise.resolve({ data: [], response: { ok: true, status: 200 } });
      }
      if (path === '/api/v1/tenants/{tid}/risk/{subject}') {
        return Promise.resolve(riskResp);
      }
      return Promise.resolve({ data: [activeTenant], response: { ok: true, status: 200 } });
    });
  }

  it('风险列:点「查看风险」→ 懒查 → 显 level Tag + score', async () => {
    mockWithRisk({
      data: { subject: 'ext-1', score: 88, level: 'critical' },
      response: { ok: true, status: 200 },
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    // 用户行渲染后,风险列默认显示「查看风险」懒查按钮(此时尚未发起 risk 查询)
    await waitFor(() => expect(screen.getByText('alice@t.io')).toBeInTheDocument());
    const viewBtn = screen.getByRole('button', { name: /查看风险/ });
    expect(viewBtn).toBeInTheDocument();
    // 懒查前没发起 risk 请求
    expect(mockGET).not.toHaveBeenCalledWith(
      '/api/v1/tenants/{tid}/risk/{subject}',
      expect.anything(),
    );
    fireEvent.click(viewBtn);
    // 点击后发起查询,经 path tid + subject=external_id 寻址
    await waitFor(() =>
      expect(mockGET).toHaveBeenCalledWith('/api/v1/tenants/{tid}/risk/{subject}', {
        params: { path: { tid: activeTenant.id, subject: 'ext-1' } },
      }),
    );
    // 成功 → 显 level Tag + score
    await waitFor(() => expect(screen.getByText('critical')).toBeInTheDocument());
    expect(screen.getByText('88')).toBeInTheDocument();
  });

  it('风险列:404(无快照)→ 显「未评估」', async () => {
    mockWithRisk({ data: undefined, response: { ok: false, status: 404 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('TenantA')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /详情/ }));
    await waitFor(() => expect(screen.getByText('alice@t.io')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /查看风险/ }));
    await waitFor(() => expect(screen.getByText('未评估')).toBeInTheDocument());
  });
});
