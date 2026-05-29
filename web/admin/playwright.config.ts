import { defineConfig } from '@playwright/test';

// Slice 51:E2E — 真 Chromium 驱动平台控制台。
// 测试文件用 *.e2e.ts(与 vitest 的 *.test.ts 分流,vitest 默认只匹配 test/spec,不会误跑这里)。
// 前置:起后端(:8443,带 SASE_CSRF_ALLOWED_ORIGINS=http://localhost:5173)+ vite(:5173)+ 设 SASE_DEV_TOKEN。
export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.ts',
  timeout: 30_000,
  fullyParallel: false,
  reporter: [['list']],
  use: {
    // 默认 dev server(5173);设 E2E_BASE_URL=http://localhost:4173 可对生产构建预览(vite preview)跑同一套 e2e。
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:5173',
    headless: true,
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
  },
});
