// Slice 65 TenantSWGRules 测试:mock GET/POST/PUT/DELETE,验列表 + 新建(填必填 pattern → POST)+
// 编辑预填(getByDisplayValue)+ PUT + 删除(Popconfirm → DELETE)。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import TenantSWGRules from './TenantSWGRules';

const { mockGET, mockPOST, mockPUT, mockDELETE } = vi.hoisted(() => ({
  mockGET: vi.fn(),
  mockPOST: vi.fn(),
  mockPUT: vi.fn(),
  mockDELETE: vi.fn(),
}));
vi.mock('@/api/client', () => ({
  client: { GET: mockGET, POST: mockPOST, PUT: mockPUT, DELETE: mockDELETE },
}));

function renderWith(tenantId = 'tid-1') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntdApp>
        <QueryClientProvider client={qc}>
          <TenantSWGRules tenantId={tenantId} />
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

const rule = { id: 'sssssss-1', kind: 'host', pattern: 'evil.com', action: 'block' };

describe('TenantSWGRules', () => {
  beforeEach(() => {
    mockGET.mockReset();
    mockPOST.mockReset();
    mockPUT.mockReset();
    mockDELETE.mockReset();
  });

  it('列表渲染规则(kind/pattern/action)', async () => {
    mockGET.mockResolvedValue({ data: [rule], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('evil.com')).toBeInTheDocument());
    expect(screen.getByText('host')).toBeInTheDocument();
    expect(mockGET).toHaveBeenCalledWith('/api/v1/tenants/{tid}/swg/rules', {
      params: { path: { tid: 'tid-1' } },
    });
  });

  it('新建规则:填 pattern → POST 经 path tid', async () => {
    mockGET.mockResolvedValue({ data: [], response: { ok: true, status: 200 } });
    mockPOST.mockResolvedValueOnce({ data: rule, response: { ok: true, status: 201 } });
    renderWith();
    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }));
    await waitFor(() => expect(screen.getByText('新建 SWG 规则')).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText('evil.com'), { target: { value: 'bad.com' } });
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
    await waitFor(() => expect(mockPOST).toHaveBeenCalledOnce());
    expect(mockPOST).toHaveBeenCalledWith('/api/v1/tenants/{tid}/swg/rules', {
      params: { path: { tid: 'tid-1' } },
      body: expect.objectContaining({ kind: 'host', pattern: 'bad.com', action: 'block' }),
    });
  });

  it('编辑规则:Modal 预填(pattern)+ PUT 经 path {tid,id}', async () => {
    mockGET.mockResolvedValue({ data: [rule], response: { ok: true, status: 200 } });
    mockPUT.mockResolvedValueOnce({ data: rule, response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('evil.com')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }));
    await waitFor(() => expect(screen.getByText('编辑 SWG 规则')).toBeInTheDocument());
    expect(screen.getByDisplayValue('evil.com')).toBeInTheDocument(); // 预填
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(mockPUT).toHaveBeenCalledOnce());
    expect(mockPUT).toHaveBeenCalledWith('/api/v1/tenants/{tid}/swg/rules/{id}', {
      params: { path: { tid: 'tid-1', id: rule.id } },
      body: expect.objectContaining({ kind: 'host', pattern: 'evil.com', action: 'block' }),
    });
  });

  it('删除规则:Popconfirm → DELETE 经 path {tid,id}', async () => {
    mockGET.mockResolvedValue({ data: [rule], response: { ok: true, status: 200 } });
    mockDELETE.mockResolvedValueOnce({ response: { ok: true, status: 204 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('evil.com')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /删\s*除/ }));
    await waitFor(() => expect(screen.getByText('删除该 SWG 规则?')).toBeInTheDocument());
    const dels = screen.getAllByRole('button', { name: /删\s*除/ });
    fireEvent.click(dels[dels.length - 1]);
    await waitFor(() => expect(mockDELETE).toHaveBeenCalledOnce());
    expect(mockDELETE).toHaveBeenCalledWith('/api/v1/tenants/{tid}/swg/rules/{id}', {
      params: { path: { tid: 'tid-1', id: rule.id } },
    });
  });
});
