// Slice 48 管理员令牌页测试:mock client.POST,验表单 + 条件 tenant_id + 签发成功 Modal + 403/503 提示。
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import AdminTokens from './AdminTokens';

const { mockPOST } = vi.hoisted(() => ({ mockPOST: vi.fn() }));
vi.mock('@/api/client', () => ({ client: { POST: mockPOST } }));

function renderWith() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntdApp>
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <AdminTokens />
          </MemoryRouter>
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>,
  );
}

describe('AdminTokens 页', () => {
  beforeEach(() => mockPOST.mockReset());

  it('标题 + 临时机制提示 + 默认 tenant_admin 显示 tenant_id 字段', () => {
    renderWith();
    expect(screen.getByText('管理员令牌签发')).toBeInTheDocument();
    expect(screen.getByText('临时机制')).toBeInTheDocument();
    // 默认 role=tenant_admin → 显示 tenant_id 输入
    expect(screen.getByPlaceholderText('00000000-0000-0000-0000-000000000000')).toBeInTheDocument();
  });

  it('签发 tenant_admin 令牌:POST 对账 + 成功 Modal 显示 token', async () => {
    mockPOST.mockResolvedValueOnce({
      data: {
        token: 'eyJhbGci.SAMPLE.TOKEN',
        subject: 'cust-admin',
        role: 'tenant_admin',
        tenant_id: 'tttttttt-0000-0000-0000-000000000000',
        expires_at: '2026-05-29T20:00:00Z',
      },
      response: { ok: true, status: 200 },
    });
    renderWith();
    fireEvent.change(screen.getByPlaceholderText('如 cust-admin / ops-alice'), {
      target: { value: 'cust-admin' },
    });
    fireEvent.change(screen.getByPlaceholderText('00000000-0000-0000-0000-000000000000'), {
      target: { value: 'tttttttt-0000-0000-0000-000000000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: /签发令牌/ }));
    await waitFor(() => expect(mockPOST).toHaveBeenCalledOnce());
    expect(mockPOST).toHaveBeenCalledWith('/api/v1/platform/admin-tokens', {
      body: {
        subject: 'cust-admin',
        role: 'tenant_admin',
        tenant_id: 'tttttttt-0000-0000-0000-000000000000',
      },
    });
    // 成功 Modal 显示 token(只显示一次)
    await waitFor(() => expect(screen.getByText('令牌已签发(只显示一次)')).toBeInTheDocument());
    expect(screen.getByDisplayValue('eyJhbGci.SAMPLE.TOKEN')).toBeInTheDocument();
  });

  it('403 subject 不在表:错误提示', async () => {
    mockPOST.mockResolvedValueOnce({
      data: undefined,
      error: 'not in table',
      response: { ok: false, status: 403 },
    });
    renderWith();
    fireEvent.change(screen.getByPlaceholderText('如 cust-admin / ops-alice'), {
      target: { value: 'x' },
    });
    fireEvent.change(screen.getByPlaceholderText('00000000-0000-0000-0000-000000000000'), {
      target: { value: 't' },
    });
    fireEvent.click(screen.getByRole('button', { name: /签发令牌/ }));
    await waitFor(() =>
      expect(screen.getByText(/subject 不在 platform_admins 表或角色不符/)).toBeInTheDocument(),
    );
  });
});
