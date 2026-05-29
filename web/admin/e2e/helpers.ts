import type { Page } from '@playwright/test';

// Slice 51/52 e2e 共享:dev-token 登录(SASE_DEV_TOKEN 由外层脚本注入)。
export const TOKEN = process.env.SASE_DEV_TOKEN ?? '';

export async function login(page: Page): Promise<void> {
  await page.goto('/login');
  await page.getByPlaceholder('粘贴 admin token...').fill(TOKEN);
  await page.getByRole('button', { name: /使用 dev token 登录/ }).click();
  await page.waitForURL(/\/dashboard/, { timeout: 15_000 });
}
