// Slice 63 控制台首页看板测试:path-aware mock 三数据源(租户/PoP/审计),验聚合计数 +
// 状态分布 + 最近审计行 + 单卡片错误隔离(租户查询 403 不拖垮 PoP/审计卡)。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from './Dashboard';

const { mockGET } = vi.hoisted(() => ({ mockGET: vi.fn() }));
vi.mock('@/api/client', () => ({ client: { GET: mockGET } }));

function renderWith() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntdApp>
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <Dashboard />
          </MemoryRouter>
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

const tenants = [
  { id: 't1', name: 'A', status: 'active' },
  { id: 't2', name: 'B', status: 'active' },
  { id: 't3', name: 'C', status: 'suspended' },
];
const pops = [
  { id: 'p1', name: 'sh-1', region: 'sh', status: 'active', max_users: 1000 },
  { id: 'p2', name: 'bj-1', region: 'bj', status: 'down', max_users: null },
];
const audit = [
  {
    id: 'a1',
    ts: '2026-05-29T08:00:00Z',
    actor_subject: 'ops',
    actor_role: 'platform_admin',
    action: 'POST /api/v1/platform/pop-nodes',
    result: 201,
    detail: '',
    source: 'api',
  },
];

// path-aware mock(Dashboard 三 GET 并发,顺序不定)
function mockOK() {
  mockGET.mockImplementation((path: string) => {
    if (path === '/api/v1/platform/tenants')
      return Promise.resolve({ data: tenants, response: { ok: true, status: 200 } });
    if (path === '/api/v1/platform/pop-nodes')
      return Promise.resolve({ data: pops, response: { ok: true, status: 200 } });
    if (path === '/api/v1/platform/audit')
      return Promise.resolve({ data: audit, response: { ok: true, status: 200 } });
    return Promise.resolve({ data: [], response: { ok: true, status: 200 } });
  });
}

describe('Dashboard 首页看板', () => {
  beforeEach(() => mockGET.mockReset());

  it('聚合计数 + 状态分布 + 最近审计行', async () => {
    mockOK();
    renderWith();
    // 标题
    expect(screen.getByText('平台运维总览')).toBeInTheDocument();
    // 租户状态分布:active 2 / suspended 1
    await waitFor(() => expect(screen.getByText('active: 2')).toBeInTheDocument());
    expect(screen.getByText('suspended: 1')).toBeInTheDocument();
    // PoP 状态分布:active 1 / down 1
    expect(screen.getByText('active: 1')).toBeInTheDocument();
    expect(screen.getByText('down: 1')).toBeInTheDocument();
    // PoP 容量配额合计 1000 + 1 个不限
    expect(screen.getByText(/容量配额合计 1000/)).toBeInTheDocument();
    // 最近审计表渲染该动作行
    expect(screen.getByText('POST /api/v1/platform/pop-nodes')).toBeInTheDocument();
  });

  it('audit 默认 limit=8', async () => {
    mockOK();
    renderWith();
    await waitFor(() => expect(mockGET).toHaveBeenCalledWith('/api/v1/platform/audit', { params: { query: { limit: 8 } } }));
  });

  it('单卡片错误隔离:租户 403 不拖垮 PoP/审计卡', async () => {
    mockGET.mockImplementation((path: string) => {
      if (path === '/api/v1/platform/tenants')
        return Promise.resolve({ data: undefined, error: 'forbidden', response: { ok: false, status: 403 } });
      if (path === '/api/v1/platform/pop-nodes')
        return Promise.resolve({ data: pops, response: { ok: true, status: 200 } });
      if (path === '/api/v1/platform/audit')
        return Promise.resolve({ data: audit, response: { ok: true, status: 200 } });
      return Promise.resolve({ data: [], response: { ok: true, status: 200 } });
    });
    renderWith();
    // 租户卡显示 AppError(403 → 无权访问)
    await waitFor(() => expect(screen.getByText('无权访问')).toBeInTheDocument());
    // PoP 卡仍正常渲染(down: 1)+ 审计行仍在
    expect(screen.getByText('down: 1')).toBeInTheDocument();
    expect(screen.getByText('POST /api/v1/platform/pop-nodes')).toBeInTheDocument();
  });
});
