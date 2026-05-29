// Slice 42:Zustand auth store(真鉴权探活 + dev token 兜底)。
//
// 模式:
//   1) **dev 模式**:粘 bootstrap admin token → 存 localStorage → client.ts middleware 注入 Authorization header → 探活
//   2) **生产 OIDC**:浏览器跳 IdP → 回调 set HttpOnly sase_session cookie → 探活
//
// state:
//   probing  — 启动后异步探活中(显示 Spin)
//   authenticated — 200 OK,role=platform_admin
//   unauthenticated — 401 / 网络错(默认值)
//   forbidden — 已认证但角色不对(403,如 tenant_admin/auditor)
//
// **⚠️ dev token 持久化到 localStorage 有 XSS 风险,仅 dev 期可接受;生产期应走 HttpOnly cookie**。
import { create } from 'zustand';
import { probeAuth, type ProbeStatus } from '@/lib/auth-probe';

const DEV_TOKEN_KEY = 'sase_dev_token';

export interface AuthState {
  status: ProbeStatus | 'probing';
  role?: 'platform_admin';
  /** dev 期粘的 bootstrap admin token(localStorage 持久化) */
  devToken: string;
  /** 探活失败/未登录时的可读原因 */
  detail?: string;
  /** 异步探活;App 启动 + setDevToken 后调用 */
  probe: () => Promise<void>;
  setDevToken: (token: string) => void;
  logout: () => void;
}

function loadDevToken(): string {
  try {
    return localStorage.getItem(DEV_TOKEN_KEY) ?? '';
  } catch {
    return '';
  }
}

function saveDevToken(token: string): void {
  try {
    if (token) {
      localStorage.setItem(DEV_TOKEN_KEY, token);
    } else {
      localStorage.removeItem(DEV_TOKEN_KEY);
    }
  } catch {
    // 隐私模式 localStorage 不可用,静默
  }
}

export const useAuthStore = create<AuthState>((set) => ({
  status: 'probing',
  devToken: loadDevToken(),

  probe: async () => {
    set({ status: 'probing' });
    const result = await probeAuth();
    set({ status: result.status, role: result.role, detail: result.detail });
  },

  setDevToken: (token: string) => {
    saveDevToken(token);
    set({ devToken: token });
  },

  logout: () => {
    saveDevToken('');
    set({ status: 'unauthenticated', role: undefined, devToken: '', detail: '主动登出' });
  },
}));

/** 给 client.ts middleware 同步读 token(避免 react hook 依赖) */
export function getDevToken(): string {
  return useAuthStore.getState().devToken;
}
