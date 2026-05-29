// Slice 44:React 渲染期异常边界(捕组件抛错,防白屏)。
// 注:只捕**渲染期**同步异常;异步(fetch)错由 TanStack Query onError + 页内 AppError 处理。
import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Result, Button } from 'antd';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // 生产可上报监控;dev 期 console 即可
    console.error('[ErrorBoundary]', error, info.componentStack);
  }

  handleReload = (): void => {
    // 渲染期异常通常需整页重载恢复
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <Result
          status="500"
          title="页面渲染出错"
          subTitle={this.state.error?.message ?? '未知错误'}
          extra={
            <Button type="primary" onClick={this.handleReload}>
              重新加载
            </Button>
          }
        />
      );
    }
    return this.props.children;
  }
}
