// Slice 45 PoP 注册页测试:mock client.GET/POST/PATCH,验列表渲染 + 新建 + 编辑 + 409 冲突提示。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import Pops from './Pops';

const { mockGET, mockPOST, mockPATCH } = vi.hoisted(() => ({
  mockGET: vi.fn(),
  mockPOST: vi.fn(),
  mockPATCH: vi.fn(),
}));
vi.mock('@/api/client', () => ({
  client: { GET: mockGET, POST: mockPOST, PATCH: mockPATCH },
}));

function renderWith() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntdApp>
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <Pops />
          </MemoryRouter>
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

const samplePop = {
  id: 'pppppppp-1111-2222-3333-444444444444',
  name: 'sh-pop-01',
  region: 'cn-east-1',
  endpoint: 'pop-sh.example.com:443',
  status: 'active',
  max_users: 1000,
  last_seen_at: null,
  created_at: '2026-01-01T08:00:00Z',
  updated_at: '2026-01-01T08:00:00Z',
};

describe('Pops 页', () => {
  beforeEach(() => {
    mockGET.mockReset();
    mockPOST.mockReset();
    mockPATCH.mockReset();
  });

  it('列表渲染 PoP 行', async () => {
    mockGET.mockResolvedValueOnce({ data: [samplePop], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('sh-pop-01')).toBeInTheDocument());
    expect(screen.getByText('cn-east-1')).toBeInTheDocument();
    expect(screen.getByText('active')).toBeInTheDocument();
  });

  it('标题 + 新建/刷新按钮存在', async () => {
    mockGET.mockResolvedValueOnce({ data: [], response: { ok: true, status: 200 } });
    renderWith();
    expect(screen.getByText('PoP 注册')).toBeInTheDocument();
    expect(screen.getByText('新建 PoP')).toBeInTheDocument();
    expect(screen.getByText('刷新')).toBeInTheDocument();
  });

  it('新建 PoP:POST 成功后刷新列表', async () => {
    mockGET
      .mockResolvedValueOnce({ data: [], response: { ok: true, status: 200 } }) // 初始空
      .mockResolvedValueOnce({ data: [samplePop], response: { ok: true, status: 200 } }); // 创建后刷新
    mockPOST.mockResolvedValueOnce({ data: samplePop, response: { ok: true, status: 201 } });

    renderWith();
    // 打开新建 Modal
    fireEvent.click(screen.getByText('新建 PoP'));
    await waitFor(() => expect(screen.getByText('新建 PoP 节点')).toBeInTheDocument());
    // 填表单(antd Form 用 placeholder 定位 input)
    fireEvent.change(screen.getByPlaceholderText('如 sh-pop-01'), { target: { value: 'sh-pop-01' } });
    fireEvent.change(screen.getByPlaceholderText('如 cn-east-1'), { target: { value: 'cn-east-1' } });
    fireEvent.change(screen.getByPlaceholderText('如 pop-sh.example.com:443'), {
      target: { value: 'pop-sh.example.com:443' },
    });
    // 点创建(antd 两字按钮可能插空格,用 role + 正则)
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
    await waitFor(() => expect(mockPOST).toHaveBeenCalledOnce());
    expect(mockPOST).toHaveBeenCalledWith('/api/v1/platform/pop-nodes', {
      body: { name: 'sh-pop-01', region: 'cn-east-1', endpoint: 'pop-sh.example.com:443' },
    });
  });

  it('新建 PoP:409 冲突显示错误提示', async () => {
    mockGET.mockResolvedValue({ data: [], response: { ok: true, status: 200 } });
    mockPOST.mockResolvedValueOnce({
      data: undefined,
      error: 'name exists',
      response: { ok: false, status: 409 },
    });
    renderWith();
    fireEvent.click(screen.getByText('新建 PoP'));
    await waitFor(() => expect(screen.getByText('新建 PoP 节点')).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText('如 sh-pop-01'), { target: { value: 'dup' } });
    fireEvent.change(screen.getByPlaceholderText('如 cn-east-1'), { target: { value: 'r' } });
    fireEvent.change(screen.getByPlaceholderText('如 pop-sh.example.com:443'), {
      target: { value: 'e' },
    });
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }));
    await waitFor(() => expect(screen.getByText('PoP name 已存在,请换一个')).toBeInTheDocument());
  });

  it('编辑 PoP:打开 Modal 预填 + PATCH', async () => {
    mockGET.mockResolvedValue({ data: [samplePop], response: { ok: true, status: 200 } });
    mockPATCH.mockResolvedValueOnce({
      data: { ...samplePop, status: 'draining' },
      response: { ok: true, status: 200 },
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('sh-pop-01')).toBeInTheDocument());
    fireEvent.click(screen.getByText('编辑'));
    await waitFor(() => expect(screen.getByText(/编辑 PoP「sh-pop-01」/)).toBeInTheDocument());
    // 保存(不改值也能 PATCH 提交当前 status/max_users)
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(mockPATCH).toHaveBeenCalledOnce());
    expect(mockPATCH).toHaveBeenCalledWith('/api/v1/platform/pop-nodes/{pid}', {
      params: { path: { pid: samplePop.id } },
      body: { status: 'active', max_users: 1000 },
    });
  });
});
