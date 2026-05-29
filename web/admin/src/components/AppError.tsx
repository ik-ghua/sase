// Slice 44:受控 API 错误展示组件(供页面 useQuery isError 复用)。
// 据 ApiError.status 渲染对应 antd Result/Alert;403/404/5xx 用 Result,其它用 Alert。
import { Result, Alert, Button } from 'antd';
import { ApiError, statusTitle } from '@/lib/api-error';

interface Props {
  error: unknown;
  /** 重试回调(如 query.refetch) */
  onRetry?: () => void;
}

export default function AppError({ error, onRetry }: Props) {
  const status = error instanceof ApiError ? error.status : 0;
  const message = error instanceof Error ? error.message : String(error);
  const title = statusTitle(status);

  // 403 / 404 / 5xx → 整块 Result(页面级失败);其它(网络错/400 等)→ 行内 Alert
  if (status === 403 || status === 404 || status >= 500) {
    return (
      <Result
        status={status === 403 ? '403' : status === 404 ? '404' : '500'}
        title={title}
        subTitle={message}
        extra={
          onRetry ? (
            <Button type="primary" onClick={onRetry}>
              重试
            </Button>
          ) : undefined
        }
      />
    );
  }

  return (
    <Alert
      type="error"
      message={title}
      description={message}
      showIcon
      closable
      action={
        onRetry ? (
          <Button size="small" onClick={onRetry}>
            重试
          </Button>
        ) : undefined
      }
      style={{ marginBottom: 16 }}
    />
  );
}
