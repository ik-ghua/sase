// Slice 44:AppError + ErrorBoundary 测试。
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import AppError from './AppError';
import ErrorBoundary from './ErrorBoundary';
import { ApiError } from '@/lib/api-error';

function w(ui: React.ReactElement) {
  return render(
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      {ui}
    </ConfigProvider>,
  );
}

describe('AppError', () => {
  it('403 → Result 无权访问', () => {
    w(<AppError error={new ApiError(403, 'forbidden')} />);
    expect(screen.getByText('无权访问')).toBeInTheDocument();
  });

  it('500 → Result 服务端错误 + 重试按钮', () => {
    const onRetry = vi.fn();
    w(<AppError error={new ApiError(500, 'boom')} onRetry={onRetry} />);
    expect(screen.getByText('服务端错误')).toBeInTheDocument();
    // antd Button 两字中间可能插空格,用 role + name 正则匹配
    fireEvent.click(screen.getByRole('button', { name: /重\s*试/ }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('401 → Alert 未登录', () => {
    w(<AppError error={new ApiError(401, 'unauthorized')} />);
    expect(screen.getByText('未登录或会话过期')).toBeInTheDocument();
  });

  it('非 ApiError(普通 Error)→ 兜底标题"错误"', () => {
    w(<AppError error={new Error('网络断了')} />);
    expect(screen.getByText('错误')).toBeInTheDocument();
    expect(screen.getByText('网络断了')).toBeInTheDocument();
  });
});

describe('ErrorBoundary', () => {
  it('子组件抛错 → 渲染 500 Result', () => {
    const Boom = (): React.ReactElement => {
      throw new Error('render crash');
    };
    // 抑制 React error console 噪音
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    w(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    expect(screen.getByText('页面渲染出错')).toBeInTheDocument();
    expect(screen.getByText('render crash')).toBeInTheDocument();
    spy.mockRestore();
  });

  it('子组件正常 → 渲染 children', () => {
    w(
      <ErrorBoundary>
        <div>正常内容</div>
      </ErrorBoundary>,
    );
    expect(screen.getByText('正常内容')).toBeInTheDocument();
  });
});
