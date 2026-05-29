// Slice 47 平台审计页测试:mock client.GET,验列表渲染 + source/result 区分 + limit 切换。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import Audit from './Audit';

const { mockGET } = vi.hoisted(() => ({ mockGET: vi.fn() }));
vi.mock('@/api/client', () => ({ client: { GET: mockGET } }));

function renderWith() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntdApp>
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <Audit />
          </MemoryRouter>
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

const apiEntry = {
  id: 'e1111111-0000-0000-0000-000000000001',
  ts: '2026-05-29T08:00:00Z',
  actor_subject: 'ops-alice',
  actor_role: 'platform_admin',
  action: 'POST /api/v1/platform/pop-nodes',
  result: 201,
  detail: 'name=sh-pop-01',
  source: 'api',
};
const dataEntry = {
  id: 'e2222222-0000-0000-0000-000000000002',
  ts: '2026-05-29T08:00:01Z',
  actor_subject: 'ops-alice',
  actor_role: 'platform_admin',
  action: 'INSERT pop_nodes',
  result: 0,
  detail: 'id=pppppppp',
  source: 'data',
};

describe('Audit 页', () => {
  beforeEach(() => mockGET.mockReset());

  it('渲染双层审计行(api + data)', async () => {
    mockGET.mockResolvedValueOnce({ data: [apiEntry, dataEntry], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() =>
      expect(screen.getByText('POST /api/v1/platform/pop-nodes')).toBeInTheDocument(),
    );
    expect(screen.getByText('INSERT pop_nodes')).toBeInTheDocument();
    // source data 的 result=0 显示「触发器」哨兵
    expect(screen.getByText('触发器')).toBeInTheDocument();
    // api 的 result=201
    expect(screen.getByText('201')).toBeInTheDocument();
  });

  it('标题 + 刷新 + limit 选择器', async () => {
    mockGET.mockResolvedValueOnce({ data: [], response: { ok: true, status: 200 } });
    renderWith();
    expect(screen.getByText('平台审计')).toBeInTheDocument();
    expect(screen.getByText('刷新')).toBeInTheDocument();
    // 默认 limit=100
    expect(screen.getByText('最近 100 条')).toBeInTheDocument();
  });

  it('默认 limit=100 调用 GET', async () => {
    mockGET.mockResolvedValueOnce({ data: [], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(mockGET).toHaveBeenCalled());
    expect(mockGET).toHaveBeenCalledWith('/api/v1/platform/audit', {
      params: { query: { limit: 100 } },
    });
  });

  it('error 路径:HTTP 403 显示 AppError', async () => {
    mockGET.mockResolvedValueOnce({
      data: undefined,
      error: 'forbidden',
      response: { ok: false, status: 403 },
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('无权访问')).toBeInTheDocument());
  });
});
