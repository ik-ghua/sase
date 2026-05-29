import { test, expect } from '@playwright/test';
import { login } from './helpers';

// Slice 64:平台运维代租户管理 FWaaS 规则,真 Chromium 端到端(create→edit→delete)。
// 重点验**编辑 Modal 预填**(initialValues+key,Slice52 教训的 antd 时序高危点,jsdom 掩盖、须真浏览器)。
// 用可识别的 TEST-NET-3 CIDR 精确定位行 + 末尾删除自清理(不留 VM PG 残留)。
const CIDR = '203.0.113.0/24';

test('FWaaS 规则 CRUD(平台运维代租户,真浏览器验编辑预填)', async ({ page }) => {
  await login(page);
  await page.goto('/tenants');
  // 开首行任意租户的详情 Drawer(FW 规则按租户隔离,末尾删除自清理,与具体租户无关)
  await expect(page.getByRole('button', { name: /详情/ }).first()).toBeVisible({ timeout: 10_000 });
  await page.getByRole('button', { name: /详情/ }).first().click();
  await expect(page.getByText('防火墙规则(FWaaS)')).toBeVisible({ timeout: 10_000 });

  // 新建规则(set 目的 CIDR 为可识别值;priority/action 用默认 100/allow)
  // Drawer 三段(FW/SWG/DLP)各有「新建规则」,FW 是首个(Slice65 后)
  await page.getByRole('button', { name: /新建规则/ }).first().click();
  // 限定在新建 Modal(dialog)内操作——避开租户 Drawer 编辑表单的同名按钮/字段(strict 多匹配)
  const createModal = page.getByRole('dialog').filter({ hasText: '新建防火墙规则' });
  await expect(createModal).toBeVisible();
  await createModal.getByLabel(/目的 CIDR/).fill(CIDR);
  await createModal.getByRole('button', { name: /创\s*建/ }).click();
  await expect(page.getByText('新建防火墙规则')).toHaveCount(0, { timeout: 10_000 }); // POST 成功 Modal 关

  const row = page.getByRole('row').filter({ hasText: CIDR }).first();
  await expect(row).toBeVisible({ timeout: 10_000 });

  // 编辑:打开 → **断言预填**(真浏览器验 initialValues+key)→ 保存
  await row.getByRole('button', { name: /编\s*辑/ }).click();
  const editModal = page.getByRole('dialog').filter({ hasText: '编辑防火墙规则' });
  await expect(editModal).toBeVisible();
  await expect(editModal.getByLabel(/目的 CIDR/)).toHaveValue(CIDR); // 预填成功(关键断言:真浏览器验 initialValues+key)
  await editModal.getByRole('button', { name: /保\s*存/ }).click();
  await expect(page.getByText('编辑防火墙规则')).toHaveCount(0, { timeout: 10_000 }); // PUT 成功 Modal 关

  // 删除:Popconfirm → 确认(末尾「删除」= portal 里的确认按钮)
  await row.getByRole('button', { name: /删\s*除/ }).click();
  await expect(page.getByText('删除该防火墙规则?')).toBeVisible();
  const delButtons = page.getByRole('button', { name: /删\s*除/ });
  await delButtons.last().click();
  await expect(page.getByRole('row').filter({ hasText: CIDR })).toHaveCount(0, { timeout: 10_000 });
});
