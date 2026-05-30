// Slice 42 + W2:Zustand auth store(HttpOnly 会话 cookie + 探活)。
//
// 模式(W2 起统一为 HttpOnly cookie,**不再用 localStorage Bearer**,消除 XSS 面):
//   1) **令牌登录**:粘 admin 令牌(bootstrap / admin-tokens 签出)→ POST /api/v1/login
//      → 后端验签后 Set-Cookie HttpOnly `sase_session` → 探活。令牌**不落 localStorage**(只进 HttpOnly cookie)。
//   2) **OIDC**:浏览器跳 IdP → 回调 set HttpOnly sase_session cookie → 探活(同一 cookie,authz 中间件 W2 起也认)。
//
// state:
//   probing  — 启动后异步探活中(显示 Spin)
//   authenticated — 200 OK,role=platform_admin
//   unauthenticated — 401 / 网络错(默认值)
//   forbidden — 已认证但角色不对(403,如 tenant_admin/auditor)
//
// 登录态全在 HttpOnly `sase_session` cookie(JS 不可读),故无本地持久化 token——刷新页面靠探活恢复。
import { create } from 'zustand';
import { probeAuth, type ProbeStatus } from '@/lib/auth-probe';
import { client } from '@/api/client';
import { toApiError } from '@/lib/api-error';

export interface AuthState {
  status: ProbeStatus | 'probing';
  role?: 'platform_admin';
  /** 探活失败/未登录/登录失败时的可读原因 */
  detail?: string;
  /** 异步探活;App 启动后调用 */
  probe: () => Promise<void>;
  /** 令牌登录:POST /api/v1/login 种 HttpOnly cookie 后探活。失败置 detail。 */
  login: (token: string) => Promise<void>;
  /** 登出:POST /api/v1/logout 清 cookie(best-effort)+ 置 unauthenticated。 */
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  status: 'probing',

  probe: async () => {
    set({ status: 'probing' });
    const result = await probeAuth();
    set({ status: result.status, role: result.role, detail: result.detail });
  },

  login: async (token: string) => {
    set({ status: 'probing', detail: undefined });
    try {
      const { response, error } = await client.POST('/api/v1/login', {
        body: { token },
      });
      if (!response.ok) {
        const apiErr = toApiError(response, error);
        set({ status: 'unauthenticated', detail: apiErr.message });
        return;
      }
    } catch (err) {
      set({ status: 'unauthenticated', detail: `登录请求失败:${String(err)}` });
      return;
    }
    // cookie 已种(HttpOnly,JS 不可读)→ 探活确认角色
    const result = await probeAuth();
    set({ status: result.status, role: result.role, detail: result.detail });
  },

  logout: () => {
    // best-effort 通知后端清 cookie(不阻塞 UI;失败也照常本地置未登录)
    void client.POST('/api/v1/logout', {}).catch(() => {
      /* 登出尽力而为:网络错也照常本地登出 */
    });
    set({ status: 'unauthenticated', role: undefined, detail: '主动登出' });
  },
}));
