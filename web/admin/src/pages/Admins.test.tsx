// Slice 46 平台管理员页测试:mock client.GET/POST/PATCH/DELETE,验列表 + 新建 + 编辑 + 删除 + 409/400 提示。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import Admins from './Admins';

const { mockGET, mockPOST, mockPATCH, mockDELETE } = vi.hoisted(() => ({
  mockGET: vi.fn(),
  mockPOST: vi.fn(),
  mockPATCH: vi.fn(),
  mockDELETE: vi.fn(),
}));
vi.mock('@/api/client', () => ({
  client: { GET: mockGET, POST: mockPOST, PATCH: mockPATCH, DELETE: mockDELETE },
}));

function renderWith() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntdApp>
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <Admins />
          </MemoryRouter>
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

const sampleAdmin = {
  id: 'aaaaaaaa-1111-2222-3333-444444444444',
  subject: 'ops-alice',
  email: 'alice@example.com',
  status: 'active',
  created_by: 'ops-root',
  created_at: '2026-01-01T08:00:00Z',
  updated_at: '2026-01-01T08:00:00Z',
};

describe('Admins 页', () => {
  beforeEach(() => {
    mockGET.mockReset();
    mockPOST.mockReset();
    mockPATCH.mockReset();
    mockDELETE.mockReset();
  });

  it('列表渲染管理员行', async () => {
    mockGET.mockResolvedValueOnce({ data: [sampleAdmin], response: { ok: true, status: 200 } });
    renderWith();
    await waitFor(() => expect(screen.getByText('ops-alice')).toBeInTheDocument());
    expect(screen.getByText('alice@example.com')).toBeInTheDocument();
    expect(screen.getByText('active')).toBeInTheDocument();
  });

  it('标题 + 添加/刷新按钮', async () => {
    mockGET.mockResolvedValueOnce({ data: [], response: { ok: true, status: 200 } });
    renderWith();
    expect(screen.getByText('平台管理员')).toBeInTheDocument();
    expect(screen.getByText('添加管理员')).toBeInTheDocument();
    expect(screen.getByText('刷新')).toBeInTheDocument();
  });

  it('新建管理员:POST 参数对账', async () => {
    mockGET.mockResolvedValue({ data: [], response: { ok: true, status: 200 } });
    mockPOST.mockResolvedValueOnce({ data: sampleAdmin, response: { ok: true, status: 201 } });
    renderWith();
    fireEvent.click(screen.getByText('添加管理员'));
    await waitFor(() => expect(screen.getByText('添加平台管理员')).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText('如 ops-alice'), { target: { value: 'ops-bob' } });
    fireEvent.change(screen.getByPlaceholderText('alice@example.com'), {
      target: { value: 'bob@x.com' },
    });
    // Modal OK 按钮"添加"(两字插空格用正则)
    fireEvent.click(screen.getByRole('button', { name: /添\s*加$/ }));
    await waitFor(() => expect(mockPOST).toHaveBeenCalledOnce());
    expect(mockPOST).toHaveBeenCalledWith('/api/v1/platform/admins', {
      body: { subject: 'ops-bob', email: 'bob@x.com' },
    });
  });

  it('新建:409 subject 冲突提示', async () => {
    mockGET.mockResolvedValue({ data: [], response: { ok: true, status: 200 } });
    mockPOST.mockResolvedValueOnce({
      data: undefined,
      error: 'exists',
      response: { ok: false, status: 409 },
    });
    renderWith();
    fireEvent.click(screen.getByText('添加管理员'));
    await waitFor(() => expect(screen.getByText('添加平台管理员')).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText('如 ops-alice'), { target: { value: 'dup' } });
    fireEvent.click(screen.getByRole('button', { name: /添\s*加$/ }));
    await waitFor(() => expect(screen.getByText('该 subject 已存在')).toBeInTheDocument());
  });

  it('编辑管理员:PATCH 预填 + 对账', async () => {
    mockGET.mockResolvedValue({ data: [sampleAdmin], response: { ok: true, status: 200 } });
    mockPATCH.mockResolvedValueOnce({
      data: { ...sampleAdmin, status: 'disabled' },
      response: { ok: true, status: 200 },
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('ops-alice')).toBeInTheDocument());
    fireEvent.click(screen.getByText('编辑'));
    await waitFor(() => expect(screen.getByText(/编辑管理员「ops-alice」/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(mockPATCH).toHaveBeenCalledOnce());
    expect(mockPATCH).toHaveBeenCalledWith('/api/v1/platform/admins/{aid}', {
      params: { path: { aid: sampleAdmin.id } },
      body: { status: 'active', email: 'alice@example.com' },
    });
  });

  it('删除管理员:Popconfirm 确认 → DELETE;400 自删拒展示后端文案', async () => {
    mockGET.mockResolvedValue({ data: [sampleAdmin], response: { ok: true, status: 200 } });
    mockDELETE.mockResolvedValueOnce({
      error: 'cannot delete self',
      response: { ok: false, status: 400 },
    });
    renderWith();
    await waitFor(() => expect(screen.getByText('ops-alice')).toBeInTheDocument());
    fireEvent.click(screen.getByText('删除'));
    // Popconfirm 弹出确认("删除"确认按钮)
    await waitFor(() => expect(screen.getByText('删除该管理员?')).toBeInTheDocument());
    // 点 Popconfirm 的"删除"确认(danger 按钮)
    const confirmBtns = screen.getAllByRole('button', { name: /删\s*除/ });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);
    await waitFor(() => expect(mockDELETE).toHaveBeenCalledOnce());
    // 400 后端文案"cannot delete self"经 toApiError → message
    await waitFor(() =>
      expect(screen.getByText(/cannot delete self/)).toBeInTheDocument(),
    );
  });
});
