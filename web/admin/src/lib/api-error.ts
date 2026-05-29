// Slice 44:统一 API 错误类型 + 解析 helper。
// 各页面 useQuery/useMutation 的 queryFn 抛 ApiError;全局 onError + 页内 AppError 组件统一展示。

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// 把 openapi-fetch 返回的 { error, response } 转成 ApiError(供 queryFn throw)。
// error body 可能是 plaintext string(后端多数 4xx)或 JSON {error:"..."};尽量提取可读信息。
export function toApiError(
  response: { ok: boolean; status: number },
  errBody?: unknown,
): ApiError {
  let msg = `HTTP ${response.status}`;
  if (typeof errBody === 'string' && errBody.trim()) {
    msg = `${msg}: ${errBody.trim()}`;
  } else if (errBody && typeof errBody === 'object' && 'error' in errBody) {
    const e = (errBody as { error?: unknown }).error;
    if (typeof e === 'string') msg = `${msg}: ${e}`;
  }
  return new ApiError(response.status, msg);
}

// 人类可读的状态描述(给 AppError 组件标题用)。
export function statusTitle(status: number): string {
  switch (status) {
    case 401:
      return '未登录或会话过期';
    case 403:
      return '无权访问';
    case 404:
      return '资源不存在';
    case 409:
      return '操作冲突';
    case 503:
      return '服务暂不可用';
    default:
      if (status >= 500) return '服务端错误';
      if (status >= 400) return '请求错误';
      return '错误';
  }
}
