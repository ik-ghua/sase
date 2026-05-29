import { test, expect } from '@playwright/test';

// Slice 51:真 Chromium 端到端 —— dev-token 登录 → 租户页(真数据)→ 详情 Drawer(Slice50 UI)→ PoP 浏览器真写。
// SASE_DEV_TOKEN = 后端 bootstrap platform_admin token(由外层脚本启动后端取日志注入)。
const TOKEN = process.env.SASE_DEV_TOKEN ?? '';

test('登录 → 租户页 → 详情 Drawer → PoP 写操作(浏览器真跑)', async ({ page }) => {
  expect(TOKEN, '需设 SASE_DEV_TOKEN(bootstrap admin token)').not.toBe('');

  const consoleErrors: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error') consoleErrors.push(m.text());
  });
  page.on('pageerror', (e) => consoleErrors.push(String(e)));
  // /api 响应状态(诊断 URL 拼接/鉴权用)
  page.on('response', (r) => {
    const u = r.url();
    if (u.includes('/api/v1')) console.log(`[net] ${r.status()} ${r.request().method()} ${new URL(u).pathname}`);
  });

  // 1) 登录页
  await page.goto('/login');
  await expect(page.getByText('登录 SASE 平台运维控制台')).toBeVisible();
  await page.screenshot({ path: 'e2e/shot-01-login.png' });

  // 2) dev token 登录(真填表单 + 点按钮)
  await page.getByPlaceholder('粘贴 admin token...').fill(TOKEN);
  await page.getByRole('button', { name: /使用 dev token 登录/ }).click();

  // 3) 鉴权探活通过 → '/' 重定向到 /dashboard
  await page.waitForURL(/\/dashboard/, { timeout: 15_000 });
  await page.screenshot({ path: 'e2e/shot-02-after-login.png' });

  // 4) 租户页:VM PG 真数据(TenantA)
  await page.goto('/tenants');
  await expect(page.getByRole('heading', { name: '租户管理' })).toBeVisible();
  await expect(page.getByText('TenantA').first()).toBeVisible({ timeout: 10_000 });
  await page.screenshot({ path: 'e2e/shot-03-tenants.png' });

  // 5) 首行「详情」→ Drawer(Slice50:编辑表单 + 生命周期)
  await page.getByRole('button', { name: /详情/ }).first().click();
  await expect(page.getByText('编辑租户')).toBeVisible();
  await expect(page.getByText('生命周期')).toBeVisible();
  // 编辑表单应预填当前值(afterOpenChange 回填;首行=TenantA)
  await expect(page.getByPlaceholder('租户名称')).toHaveValue('TenantA');
  // Slice57:用户/策略区(platform_admin 经 path-tid RLS 读目标租户);TenantA 有用户 ua@a.com
  await expect(page.getByText('用户', { exact: true })).toBeVisible();
  await expect(page.getByText('ua@a.com')).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText('策略', { exact: true })).toBeVisible();
  await expect(page.getByText('读取用户失败')).toHaveCount(0); // users 读成功
  await expect(page.getByText('读取策略失败')).toHaveCount(0); // policies 读成功(platform_admin RLS)
  await page.waitForTimeout(400); // 待 Drawer 滑入动画定格,截图更清晰
  await page.screenshot({ path: 'e2e/shot-04-tenant-drawer.png' });
  await page.keyboard.press('Escape');

  // 6) PoP 页:浏览器真写(CSRF cookie→X-CSRF-Token + Bearer 全由 client.ts JS 完成)
  await page.goto('/pops');
  await expect(page.getByRole('heading', { name: 'PoP 注册' })).toBeVisible();
  await page.getByRole('button', { name: /新建 PoP/ }).click();
  const popName = `e2e-pop-${Date.now()}`;
  await page.getByPlaceholder('如 sh-pop-01').fill(popName);
  await page.getByPlaceholder('如 cn-east-1').fill('cn-e2e');
  await page.getByPlaceholder('如 pop-sh.example.com:443').fill('e2e:443');
  await page.getByRole('button', { name: /创\s*建/ }).click();

  // 成功 toast 证明写请求 201 通过(CSRF + Bearer 全链路在真浏览器跑通)
  await expect(page.getByText(new RegExp(`PoP「${popName}」已创建`))).toBeVisible({ timeout: 10_000 });
  await page.screenshot({ path: 'e2e/shot-05-pop-created.png' });

  const harmful = consoleErrors.filter((e) => !/favicon|ResizeObserver loop/i.test(e));
  console.log(`[e2e] 浏览器控制台 error(过滤后)=${harmful.length}`, harmful);
});
