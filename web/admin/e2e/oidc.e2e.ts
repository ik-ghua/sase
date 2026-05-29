import { test, expect } from '@playwright/test';

// Slice 54:真 OIDC 端到端(自托管 dex)。浏览器 → /idp/login → dex 真登录 → callback →
// 后端真 discovery/PKCE/id_token 验签(dex JWKS)/userinfo → EnsureUser → 签发会话 → 种 sase_session cookie。
//
// ⚠️ 诚实口径:admin API authz 只认 Bearer,不读 sase_session cookie(handler 种了但无消费者)。
// 故本测验的是 OIDC **机制**跑通(cookie 种下 + 重定向链 + 真 IdP 验签),非"登进平台控制台"。
// 服务端全链路成功由 audit_log 的 OIDC_LOGIN 旁证(测试外用 curl/psql 查)。
const TID = process.env.OIDC_TID ?? '';
const IDP = process.env.OIDC_IDP ?? '';

test('OIDC:浏览器 → dex 登录 → callback 种 sase_session cookie', async ({ page, context }) => {
  expect(TID, '需 OIDC_TID').not.toBe('');
  expect(IDP, '需 OIDC_IDP').not.toBe('');

  // 1) 登录页 → OIDC 跳转 tab
  await page.goto('/login');
  await expect(page.getByText('登录 SASE 平台运维控制台')).toBeVisible();
  await page.getByRole('tab', { name: /OIDC 跳转/ }).click();

  // tenant_id / idp_id 两个输入框 placeholder 相同,按顺序填
  const idInputs = page.getByPlaceholder('00000000-0000-0000-0000-000000000000');
  await idInputs.nth(0).fill(TID);
  await idInputs.nth(1).fill(IDP);
  await page.screenshot({ path: 'e2e/shot-oidc-1-form.png' });
  await page.getByRole('button', { name: /跳转 IdP 登录/ }).click();

  // 2) 跳到 dex 登录页(VM 192.168.11.66:5556)
  await page.waitForURL(/192\.168\.11\.66:5556/, { timeout: 15_000 });
  await page.screenshot({ path: 'e2e/shot-oidc-2-dex.png' });

  // 3) 填 dex 本地口令登录表单(staticPasswords)
  await page.fill('input[name="login"]', 'alice@oidc-test.local');
  await page.fill('input[name="password"]', 'password');
  await page.click('button[type="submit"]');

  // 4) callback 处理完 → 重定向回 app(localhost:5173;因 cookie 不被 admin authz 认,最终落 /login)
  await page.waitForURL((u) => u.hostname === 'localhost' && u.port === '5173', { timeout: 15_000 });
  await page.screenshot({ path: 'e2e/shot-oidc-3-back.png' });

  // 5) 断言:callback 已种 sase_session cookie(HttpOnly,Playwright context 可读)
  const cookies = await context.cookies();
  const sess = cookies.find((c) => c.name === 'sase_session');
  expect(sess, 'callback 应种 sase_session cookie(OIDC 机制跑通)').toBeTruthy();
  expect(sess?.httpOnly, 'sase_session 应为 HttpOnly').toBe(true);
  console.log(`[oidc] sase_session 已种:httpOnly=${sess?.httpOnly} sameSite=${sess?.sameSite} path=${sess?.path}`);
});
