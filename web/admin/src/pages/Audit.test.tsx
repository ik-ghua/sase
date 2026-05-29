// Slice 47 平台审计页测试:mock client.GET,验列表渲染 + source/result 区分 + limit 切换。
// 深化:target_tenant_id 列 + result 筛选(区分触发器哨兵)+ detail 展开。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, within, fireEvent } from '@testing-library/react';
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
  detail: 'name=sh-pop-01 region=cn-east endpoint=1.2.3.4:443 max_users=1000 extra-very-long-detail-payload-to-exercise-expand',
  source: 'api',
  target_tenant_id: 'aaaaaaaa-1111-2222-3333-444444444444',
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
const errEntry = {
  id: 'e3333333-0000-0000-0000-000000000003',
  ts: '2026-05-29T08:00:02Z',
  actor_subject: 'ops-alice',
  actor_role: 'platform_admin',
  action: 'PATCH /api/v1/tenants/{tid}',
  result: 409,
  detail: 'conflict',
  source: 'api',
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

  it('target_tenant_id 列:有值显截断、空值显 -', async () => {
    mockGET.mockResolvedValueOnce({
      data: [apiEntry, dataEntry],
      response: { ok: true, status: 200 },
    });
    renderWith();
    await waitFor(() =>
      expect(screen.getByText('POST /api/v1/platform/pop-nodes')).toBeInTheDocument(),
    );
    // apiEntry 的 target_tenant_id 截断为前 8 位
    expect(screen.getByText('aaaaaaaa')).toBeInTheDocument();
    // dataEntry 无 target_tenant_id → 显示 '-'(关联租户列内)
    const dataRow = screen.getByText('INSERT pop_nodes').closest('tr')!;
    expect(within(dataRow).getByText('-')).toBeInTheDocument();
  });

  it('result 筛选:触发器哨兵桶只保留 source=data + result=0,不混入 HTTP 码', async () => {
    // 三条:201(2xx api)、0(触发器 data)、409(4xx api)
    mockGET.mockResolvedValueOnce({
      data: [apiEntry, dataEntry, errEntry],
      response: { ok: true, status: 200 },
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('INSERT pop_nodes')).toBeInTheDocument());

    // 打开「结果」列筛选下拉(antd scroll 表头可能渲染多份「结果」,取其中带筛选按钮的 th)
    const resultHeader = screen
      .getAllByText('结果')
      .map((el) => el.closest('th'))
      .find((th): th is HTMLTableCellElement => !!th?.querySelector('.ant-table-filter-trigger'))!;
    fireEvent.click(resultHeader.querySelector('.ant-table-filter-trigger')!);
    // 勾选「触发器(source=data)」
    await waitFor(() => expect(screen.getByText('触发器(source=data)')).toBeInTheDocument());
    fireEvent.click(screen.getByText('触发器(source=data)'));
    // 确定
    fireEvent.click(screen.getByRole('button', { name: /OK|确\s*定/ }));

    // 仅触发器行保留;两条 HTTP 行(POST/PATCH 动作)被筛掉
    await waitFor(() =>
      expect(screen.queryByText('POST /api/v1/platform/pop-nodes')).not.toBeInTheDocument(),
    );
    expect(screen.queryByText('PATCH /api/v1/tenants/{tid}')).not.toBeInTheDocument();
    expect(screen.getByText('INSERT pop_nodes')).toBeInTheDocument();
  });

  it('detail 展开:展开行显示完整 detail + 概览 Descriptions', async () => {
    mockGET.mockResolvedValueOnce({
      data: [apiEntry],
      response: { ok: true, status: 200 },
    });
    renderWith();
    await waitFor(() =>
      expect(screen.getByText('POST /api/v1/platform/pop-nodes')).toBeInTheDocument(),
    );
    // 点击展开图标(antd 行展开按钮)
    fireEvent.click(screen.getByRole('button', { name: /展开行|Expand row/ }));
    // 展开后出现 Descriptions 概览标签 + 完整 detail(含截断列里看不全的长尾)
    await waitFor(() => expect(screen.getByText('完整详情')).toBeInTheDocument());
    // 「关联租户」既是列头又是 Descriptions 标签,至少出现一次即可
    expect(screen.getAllByText('关联租户').length).toBeGreaterThan(0);
    // 长 detail 在截断列与展开 Descriptions 各渲染一次(列用 CSS ellipsis 仍含全文),≥1 即覆盖
    expect(
      screen.getAllByText(/extra-very-long-detail-payload-to-exercise-expand/).length,
    ).toBeGreaterThan(0);
    // 展开行内显示完整 target_tenant_id(非截断,列里只显前 8 位)
    expect(
      screen.getByText('aaaaaaaa-1111-2222-3333-444444444444'),
    ).toBeInTheDocument();
  });
});
