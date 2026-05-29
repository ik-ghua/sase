import { test, expect } from '@playwright/test';
import { login, TOKEN } from './helpers';

// Slice 52:真浏览器验证编辑表单预填(destroyOnHidden Modal / destroyOnClose Drawer)。
// 背景:Slice51 在 Tenants Drawer 实证 useEffect 回填在真浏览器失败(字段空白),afterOpenChange 修好。
// workflow 复核 agent 推断 Pops/Admins 的「openEdit 同步 setFieldsValue」无此问题——本 spec 用真浏览器证伪/证实。
test.describe('编辑表单预填(真浏览器)', () => {
  test.beforeEach(async ({ page }) => {
    expect(TOKEN, '需设 SASE_DEV_TOKEN').not.toBe('');
    await login(page);
  });

  test('Pops 编辑 Modal:status Select 预填当前值(首行)', async ({ page }) => {
    await page.goto('/pops');
    await expect(page.getByRole('heading', { name: 'PoP 注册' })).toBeVisible();
    await expect(page.getByRole('button', { name: /编辑/ }).first()).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: /编辑/ }).first().click();
    await expect(page.getByText(/编辑 PoP/)).toBeVisible();
    // status Select 应预填:选中项非空,显示 active/draining/down 之一(每个 PoP 都有非空 status)
    const sel = page.locator('.ant-modal .ant-select-selection-item').first();
    await expect(sel).toBeVisible({ timeout: 5_000 });
    await expect(sel).toHaveText(/active|draining|down/);
    await page.screenshot({ path: 'e2e/shot-pops-edit.png' });
  });

  test('Admins 编辑 Modal:email + status 预填(创建已知值再编辑)', async ({ page }) => {
    await page.goto('/admins');
    await expect(page.getByRole('heading', { name: '平台管理员' })).toBeVisible();

    // 创建一个带已知 email 的管理员(确保有可编辑行 + 已知预期值)
    const subj = `pf-admin-${Date.now()}`;
    await page.getByRole('button', { name: /添加管理员/ }).click();
    await page.getByPlaceholder('如 ops-alice').fill(subj);
    await page.locator('.ant-modal').getByPlaceholder('alice@example.com').fill('pf@example.com');
    // OK 按钮限定在 Modal 内(避开页面「添加管理员」按钮的 strict 冲突)
    await page.locator('.ant-modal-footer').getByRole('button', { name: /添\s*加/ }).click();
    await expect(page.getByText(new RegExp(`管理员「${subj}」已添加`))).toBeVisible({ timeout: 10_000 });

    // 编辑该行
    await page
      .getByRole('row', { name: new RegExp(subj) })
      .getByRole('button', { name: /编辑/ })
      .click();
    await expect(page.getByText(/编辑管理员/)).toBeVisible();
    // email 预填
    await expect(page.locator('.ant-modal').getByPlaceholder('alice@example.com')).toHaveValue(
      'pf@example.com',
    );
    // status Select 预填(active)
    const sel = page.locator('.ant-modal .ant-select-selection-item').first();
    await expect(sel).toBeVisible({ timeout: 5_000 });
    await expect(sel).toHaveText(/active|disabled/);
    await page.screenshot({ path: 'e2e/shot-admins-edit.png' });
  });
});
