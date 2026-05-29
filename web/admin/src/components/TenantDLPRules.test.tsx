// Slice 65 TenantDLPRules 测试:mock GET/POST/PUT/DELETE,验列表 + 新建(填必填 name/pattern → POST)+
// 编辑预填 + PUT + 删除(Popconfirm → DELETE)。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import TenantDLPRules from './TenantDLPRules';

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
          <TenantDLPRules tenantId={tenantId} />
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

const rule = {
  id: 'ddddddd-1',
  name: '身份证',
  match_type: 'regex',
  pattern: '\\d{17}[\\dXx]',
  action: 'block',
  severity: 'high',
};

describe('TenantDLPRules', () => {
  beforeEach(() => {
    mockGET.mockReset();
    mockPOST.mockReset();
    mockPUT.mockReset();
    mockDELETE.mockReset();
  });

  it('列表渲染规则(name/match/action/severity)', async () => {
    mockGET.mockResolvedValue({ data: [rule], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('身份证')).toBeInTheDocument());
    expect(screen.getByText('regex')).toBeInTheDocument();
    expect(screen.getByText('block')).toBeInTheDocument();
    expect(screen.getByText('high')).toBeInTheDocument();
    expect(mockGET).toHaveBeenCalledWith('/api/v1/tenants/{tid}/dlp/rules', {
      params: { path: { tid: 'tid-1' } },
    });
  });

  it('新建规则:填 name+pattern → POST 经 path tid', async () => {
    mockGET.mockResolvedValue({ data: [], response: { ok: true, status: 200 } });
    mockPOST.mockResolvedValueOnce({ data: rule, response: { ok: true, status: 201 } });
    renderWith();
    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }));
    await waitFor(() => expect(screen.getByText('新建 DLP 规则')).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText('如 身份证号'), { target: { value: '机密' } });
    fireEvent.change(screen.getByPlaceholderText(/绝密/), { target: { value: '绝密' } });
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
    await waitFor(() => expect(mockPOST).toHaveBeenCalledOnce());
    expect(mockPOST).toHaveBeenCalledWith('/api/v1/tenants/{tid}/dlp/rules', {
      params: { path: { tid: 'tid-1' } },
      body: expect.objectContaining({ name: '机密', pattern: '绝密', match_type: 'keyword', action: 'alert', severity: 'medium' }),
    });
  });

  it('编辑规则:Modal 预填(name)+ PUT 经 path {tid,id}', async () => {
    mockGET.mockResolvedValue({ data: [rule], response: { ok: true, status: 200 } });
    mockPUT.mockResolvedValueOnce({ data: rule, response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('身份证')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }));
    await waitFor(() => expect(screen.getByText('编辑 DLP 规则')).toBeInTheDocument());
    expect(screen.getByDisplayValue('身份证')).toBeInTheDocument(); // 预填
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(mockPUT).toHaveBeenCalledOnce());
    expect(mockPUT).toHaveBeenCalledWith('/api/v1/tenants/{tid}/dlp/rules/{id}', {
      params: { path: { tid: 'tid-1', id: rule.id } },
      body: expect.objectContaining({ name: '身份证', action: 'block', severity: 'high' }),
    });
  });

  it('删除规则:Popconfirm → DELETE 经 path {tid,id}', async () => {
    mockGET.mockResolvedValue({ data: [rule], response: { ok: true, status: 200 } });
    mockDELETE.mockResolvedValueOnce({ response: { ok: true, status: 204 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('身份证')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /删\s*除/ }));
    await waitFor(() => expect(screen.getByText('删除该 DLP 规则?')).toBeInTheDocument());
    const dels = screen.getAllByRole('button', { name: /删\s*除/ });
    fireEvent.click(dels[dels.length - 1]);
    await waitFor(() => expect(mockDELETE).toHaveBeenCalledOnce());
    expect(mockDELETE).toHaveBeenCalledWith('/api/v1/tenants/{tid}/dlp/rules/{id}', {
      params: { path: { tid: 'tid-1', id: rule.id } },
    });
  });
});
