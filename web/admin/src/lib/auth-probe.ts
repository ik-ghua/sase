// Slice 42:启动鉴权探活(Slice45 活体联调修正 CSRF cookie 来源)。
// 1) 调 GET /api/v1/trust/pubkey(公开端点)预热连接;
// 2) 调 GET /api/v1/platform/tenants(需 platform_admin)判断鉴权状态:
//    200 → authenticated + role=platform_admin
//    401 → unauthenticated
//    403 → forbidden(已认证但角色不对,如 tenant_admin/auditor)
//    其它 → 兜底 unauthenticated(网络错/后端未起均可重试)
//
// **CSRF cookie 来源(活体验证)**:`/trust/pubkey` 在后端 Slice40 CSRF Skip 白名单内,**不颁发** csrf_token cookie;
// 真正颁发 csrf_token 的是**第 2 步非白名单 GET `/platform/tenants`**(经 CSRF middleware GET 分支 Set-Cookie)。
// 故探活结束(走完第 2 步)后 csrf_token cookie 已就位,后续写方法(POST/PATCH/DELETE)才能带上 X-CSRF-Token。
//
// 注:**sase_session 是 HttpOnly cookie**(W2:登录态唯一载体,JS 不能直接读),只能靠"调需要认证的 API"判断;
// 请求经 credentials:'include' 自动带 cookie(无 localStorage Bearer)。
import { client } from '@/api/client';

export type ProbeStatus = 'authenticated' | 'unauthenticated' | 'forbidden';

export interface ProbeResult {
  status: ProbeStatus;
  /** 仅 authenticated 时有意义 — 当前角色(目前仅识别 platform_admin) */
  role?: 'platform_admin';
  /** 仅 unauthenticated/forbidden 时填,debug 用 */
  detail?: string;
}

export async function probeAuth(): Promise<ProbeResult> {
  // Step 1:GET 公开端点预热(注:此端点在 CSRF 白名单,**不**颁发 csrf cookie;cookie 由 Step 2 颁发)
  try {
    await client.GET('/api/v1/trust/pubkey');
  } catch {
    // 公开端点失败不致命(可能后端没起),不阻塞后续探活
  }

  // Step 2:探活鉴权端点
  try {
    const { response } = await client.GET('/api/v1/platform/tenants');
    if (response.ok) {
      return { status: 'authenticated', role: 'platform_admin' };
    }
    if (response.status === 401) {
      return { status: 'unauthenticated', detail: '未登录(401)' };
    }
    if (response.status === 403) {
      return { status: 'forbidden', detail: '已登录但角色非 platform_admin(403)' };
    }
    return { status: 'unauthenticated', detail: `探活返码 ${response.status}` };
  } catch (err) {
    return { status: 'unauthenticated', detail: `网络错或后端未起:${String(err)}` };
  }
}
