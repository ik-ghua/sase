// Slice 64 TenantFWRules 测试:mock client GET/POST/PUT/DELETE,验列表 + 新建(POST)+
// 编辑预填(initialValues,Slice52 模式)+ PUT + 删除(Popconfirm → DELETE)。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import TenantFWRules from './TenantFWRules';

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
          <TenantFWRules tenantId={tenantId} />
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

const denyRule = {
  id: 'rrrrrrrr-1111-2222-3333-444444444444',
  priority: 5,
  action: 'deny',
  protocol: 'tcp',
  src_cidr: '',
  dst_cidr: '10.0.0.0/24',
  dst_port_min: 22,
  dst_port_max: 22,
};
const allowRule = {
  id: 'rrrrrrrr-5555-6666-7777-888888888888',
  priority: 100,
  action: 'allow',
  protocol: 'any',
  src_cidr: '',
  dst_cidr: '',
  dst_port_min: 0,
  dst_port_max: 0,
};

describe('TenantFWRules', () => {
  beforeEach(() => {
    mockGET.mockReset();
    mockPOST.mockReset();
    mockPUT.mockReset();
    mockDELETE.mockReset();
  });

  it('列表渲染规则(allow/deny + 端口区间)', async () => {
    mockGET.mockResolvedValue({ data: [denyRule, allowRule], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('deny')).toBeInTheDocument());
    expect(screen.getByText('allow')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument();
    // GET 经 path tid
    expect(mockGET).toHaveBeenCalledWith('/api/v1/tenants/{tid}/fw/rules', {
      params: { path: { tid: 'tid-1' } },
    });
  });

  it('新建规则:POST 经 path tid + 默认值 body', async () => {
    mockGET.mockResolvedValue({ data: [], response: { ok: true, status: 200 } });
    mockPOST.mockResolvedValueOnce({ data: allowRule, response: { ok: true, status: 201 } });
    renderWith();
    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }));
    await waitFor(() => expect(screen.getByText('新建防火墙规则')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
    await waitFor(() => expect(mockPOST).toHaveBeenCalledOnce());
    expect(mockPOST).toHaveBeenCalledWith('/api/v1/tenants/{tid}/fw/rules', {
      params: { path: { tid: 'tid-1' } },
      body: expect.objectContaining({ priority: 100, action: 'allow', protocol: 'any' }),
    });
  });

  it('编辑规则:Modal 预填当前值(initialValues)+ PUT 经 path {tid,id}', async () => {
    mockGET.mockResolvedValue({ data: [denyRule], response: { ok: true, status: 200 } });
    mockPUT.mockResolvedValueOnce({ data: denyRule, response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('deny')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }));
    await waitFor(() => expect(screen.getByText('编辑防火墙规则')).toBeInTheDocument());
    // 预填:priority=5 的 InputNumber 应显示 5(initialValues 挂载初始化,jsdom+浏览器皆对)
    expect(screen.getByDisplayValue('5')).toBeInTheDocument();
    // 保存 → PUT(全量替换,body 含预填的 deny/tcp)
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(mockPUT).toHaveBeenCalledOnce());
    expect(mockPUT).toHaveBeenCalledWith('/api/v1/tenants/{tid}/fw/rules/{id}', {
      params: { path: { tid: 'tid-1', id: denyRule.id } },
      body: expect.objectContaining({ action: 'deny', protocol: 'tcp', priority: 5 }),
    });
  });

  it('删除规则:Popconfirm 确认 → DELETE 经 path {tid,id}', async () => {
    mockGET.mockResolvedValue({ data: [denyRule], response: { ok: true, status: 200 } });
    mockDELETE.mockResolvedValueOnce({ response: { ok: true, status: 204 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('deny')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /删\s*除/ }));
    // Popconfirm 确认按钮(气泡里的「删除」danger 按钮 = 最后一个)
    await waitFor(() => expect(screen.getByText('删除该防火墙规则?')).toBeInTheDocument());
    const delButtons = screen.getAllByRole('button', { name: /删\s*除/ });
    fireEvent.click(delButtons[delButtons.length - 1]);
    await waitFor(() => expect(mockDELETE).toHaveBeenCalledOnce());
    expect(mockDELETE).toHaveBeenCalledWith('/api/v1/tenants/{tid}/fw/rules/{id}', {
      params: { path: { tid: 'tid-1', id: denyRule.id } },
    });
  });
});
