import { test, expect } from '@playwright/test';
import { login } from './helpers';

// Slice 65:SWG + DLP 规则管理真 Chromium 端到端(create→edit 预填→delete),验两个新组件。
// Drawer 三段(FW/SWG/DLP)各有「新建规则」按钮 → 用 nth 索引(固定序);Modal/行用标题/可识别值区分。
// 末尾删除自清理。
const SWG_PATTERN = 'evil-test-65.example';
const DLP_NAME = 'DLP-TEST-65';

test('SWG + DLP 规则 CRUD(真浏览器验编辑预填)', async ({ page }) => {
  await login(page);
  await page.goto('/tenants');
  await expect(page.getByRole('button', { name: /详情/ }).first()).toBeVisible({ timeout: 10_000 });
  await page.getByRole('button', { name: /详情/ }).first().click();
  await expect(page.getByText('安全网关规则(SWG)')).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText('数据防泄漏规则(CASB-DLP)')).toBeVisible();

  const newButtons = page.getByRole('button', { name: /新建规则/ }); // [0]=FW [1]=SWG [2]=DLP

  // ── SWG:create → edit(prefill)→ delete ──
  await newButtons.nth(1).click();
  const swgCreate = page.getByRole('dialog').filter({ hasText: '新建 SWG 规则' });
  await expect(swgCreate).toBeVisible();
  await swgCreate.getByLabel(/模式/).fill(SWG_PATTERN);
  await swgCreate.getByRole('button', { name: /创\s*建/ }).click();
  await expect(page.getByText('新建 SWG 规则')).toHaveCount(0, { timeout: 10_000 });

  const swgRow = page.getByRole('row').filter({ hasText: SWG_PATTERN }).first();
  await expect(swgRow).toBeVisible({ timeout: 10_000 });
  await swgRow.getByRole('button', { name: /编\s*辑/ }).click();
  const swgEdit = page.getByRole('dialog').filter({ hasText: '编辑 SWG 规则' });
  await expect(swgEdit.getByLabel(/模式/)).toHaveValue(SWG_PATTERN); // 预填(关键)
  await swgEdit.getByRole('button', { name: /保\s*存/ }).click();
  await expect(page.getByText('编辑 SWG 规则')).toHaveCount(0, { timeout: 10_000 });
  await swgRow.getByRole('button', { name: /删\s*除/ }).click();
  await page.getByRole('button', { name: /删\s*除/ }).last().click();
  await expect(page.getByRole('row').filter({ hasText: SWG_PATTERN })).toHaveCount(0, { timeout: 10_000 });

  // ── DLP:create → edit(prefill)→ delete ──
  await newButtons.nth(2).click();
  const dlpCreate = page.getByRole('dialog').filter({ hasText: '新建 DLP 规则' });
  await expect(dlpCreate).toBeVisible();
  // 用 placeholder 定位(antd 标签关联对部分字段不稳;placeholder 可靠,jsdom 测试同法)
  await dlpCreate.getByPlaceholder('如 身份证号').fill(DLP_NAME);
  await dlpCreate.getByPlaceholder(/绝密/).fill('topsecret');
  await dlpCreate.getByRole('button', { name: /创\s*建/ }).click();
  await expect(page.getByText('新建 DLP 规则')).toHaveCount(0, { timeout: 10_000 });

  const dlpRow = page.getByRole('row').filter({ hasText: DLP_NAME }).first();
  await expect(dlpRow).toBeVisible({ timeout: 10_000 });
  await dlpRow.getByRole('button', { name: /编\s*辑/ }).click();
  const dlpEdit = page.getByRole('dialog').filter({ hasText: '编辑 DLP 规则' });
  await expect(dlpEdit.getByPlaceholder('如 身份证号')).toHaveValue(DLP_NAME); // 预填(关键)
  await dlpEdit.getByRole('button', { name: /保\s*存/ }).click();
  await expect(page.getByText('编辑 DLP 规则')).toHaveCount(0, { timeout: 10_000 });
  await dlpRow.getByRole('button', { name: /删\s*除/ }).click();
  await page.getByRole('button', { name: /删\s*除/ }).last().click();
  await expect(page.getByRole('row').filter({ hasText: DLP_NAME })).toHaveCount(0, { timeout: 10_000 });
});
