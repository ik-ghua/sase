// Slice 41/42/44:openapi-fetch 客户端 + CSRF + dev Bearer + 401 集中登出 middleware。
// baseUrl 走 Vite proxy `/api`(转后端 :8443);credentials:'include' 让浏览器自动带 sase_session cookie。
import createClient, { type Middleware } from 'openapi-fetch';
import type { paths } from './types';
import { getCsrfTokenFromCookie } from '@/lib/csrf';
import { getDevToken } from '@/stores/auth';

const CSRF_HEADER = 'X-CSRF-Token';
const WRITE_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

// CSRF middleware:写方法自动从 cookie 复制到 header(Slice40 后端 double-submit 校验)。
const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    if (WRITE_METHODS.has(request.method.toUpperCase())) {
      const token = getCsrfTokenFromCookie();
      if (token) {
        request.headers.set(CSRF_HEADER, token);
      }
    }
    return request;
  },
};

// Slice 42 Authorization middleware:dev 模式注入 Bearer admin token(从 Zustand store 同步读)。
// 生产模式 dev token 为空 → 不注入,浏览器自动带 sase_session cookie(credentials:'include')。
const authMiddleware: Middleware = {
  onRequest({ request }) {
    const devToken = getDevToken();
    if (devToken) {
      request.headers.set('Authorization', `Bearer ${devToken}`);
    }
    return request;
  },
};

// Slice 44 401 集中登出:任何请求返 401 → 触发全局未认证处理(清 dev token + 跳 /login)。
// 用回调注入(避免 client.ts → auth store → client.ts 循环 import 风险;由 main.tsx 注册)。
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

const authExpiryMiddleware: Middleware = {
  onResponse({ response }) {
    // 探活端点(auth-probe)自己处理 401,不触发全局跳转——靠 url 豁免 platform/tenants 探活?
    // 简化:401 一律触发全局登出;探活在未登录态本就期望跳 /login,语义一致。
    if (response.status === 401 && onUnauthorized) {
      onUnauthorized();
    }
    return response;
  },
};

// 创建 openapi-fetch 客户端。**baseUrl 留空**:types.ts 的 path key 已含完整 `/api/v1/...` 前缀
// (OpenAPI spec 单一来源),故请求 URL = path 本身(相对当前 origin → 经 Vite proxy `/api` 转后端)。
// ⚠️ 历史坑(Slice51 真浏览器 e2e 揪出):曾设 `baseUrl:'/api/v1'` → 与 path 自带前缀拼成
// `/api/v1/api/v1/...` 双前缀;此前单测 mock client、Slice49 用 curl 绕过 client,均未触发。
export const client = createClient<paths>({
  credentials: 'include',
});

client.use(authMiddleware);
client.use(csrfMiddleware);
client.use(authExpiryMiddleware);
