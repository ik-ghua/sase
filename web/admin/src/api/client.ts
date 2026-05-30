// Slice 41/42/44 + W2:openapi-fetch 客户端 + CSRF + HttpOnly 会话 cookie + 401 集中登出 middleware。
// baseUrl 走 Vite proxy `/api`(转后端 :8443);credentials:'include' 让浏览器自动带 HttpOnly sase_session cookie。
//
// W2 变更:**去掉 localStorage Bearer 注入**(消除 XSS 面)。登录态统一走 HttpOnly `sase_session` cookie
// (POST /api/v1/login 种、authz 中间件读;cookie 与 Bearer 在后端二选一,前端浏览器只用 cookie)。
// CSRF double-submit 仍生效(写方法把非 HttpOnly 的 csrf_token cookie 复制到 X-CSRF-Token header)。
import createClient, { type Middleware } from 'openapi-fetch';
import type { paths } from './types';
import { getCsrfTokenFromCookie } from '@/lib/csrf';

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

// Slice 44 401 集中登出:任何请求返 401 → 触发全局未认证处理(清 dev token + 跳 /login)。
// 用回调注入(避免 client.ts → auth store → client.ts 循环 import 风险;由 main.tsx 注册)。
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

// 自处理 401 的端点(不触发全局登出回调):
//   - /api/v1/login:登录失败的 401 由 auth store login() 自行置 detail(且无 cookie 可清,触发 logout 多余);
//   - /api/v1/logout:登出本身,409/401 也无意义触发再次登出。
const SELF_HANDLED_401 = ['/api/v1/login', '/api/v1/logout'];

const authExpiryMiddleware: Middleware = {
  onResponse({ request, response }) {
    // 401 集中登出:任何受保护请求返 401(会话过期/cookie 失效)→ 触发全局未认证处理 → AuthGuard 跳 /login。
    // 登录/登出端点自处理,豁免(否则失败登录会触发一次多余的 logout POST + 覆盖 detail)。
    const selfHandled = SELF_HANDLED_401.some((p) => request.url.includes(p));
    if (response.status === 401 && onUnauthorized && !selfHandled) {
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

client.use(csrfMiddleware);
client.use(authExpiryMiddleware);
