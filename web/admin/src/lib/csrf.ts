// Slice 41 + 后端 Slice 40 CSRF 中间件协同:
// 后端首次 GET 任意非白名单 API 颁发 csrf_token cookie(非 HttpOnly,JS 可读);
// 写方法(POST/PATCH/PUT/DELETE)必须复制 cookie 值到 X-CSRF-Token header,
// 且 Origin/Referer 同源(由浏览器自动发)。

/**
 * 从 document.cookie 读 csrf_token 值。
 * @returns cookie 值,未颁发时返空串。
 */
export function getCsrfTokenFromCookie(): string {
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}
