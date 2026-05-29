/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);
// 后端 admin TLS 端口 8443(HTTPS 自签,secure:false 跳过校验;target 经 VITE_API_TARGET 可配,
// 远程后端如 VM 时设 https://192.168.x.x:8443)。dev server 与 preview(生产构建预览)共用,
// 便于对生产构建也跑 e2e。
var apiProxy = {
    '/api': {
        target: process.env.VITE_API_TARGET || 'https://localhost:8443',
        changeOrigin: true,
        secure: false,
    },
};
// Slice 41/52:Vite 配置——dev server + 后端 /api proxy + 别名 @ → src + 生产 manualChunks 分包。
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
    server: {
        port: 5173,
        proxy: apiProxy,
    },
    preview: {
        port: 4173,
        proxy: apiProxy,
    },
    build: {
        // antd 单包 ~1.1MB(gzip ~340KB)是该 UI 库固有体量,已隔离为独立 vendor chunk 长期缓存;
        // 阈值提到 1200KB 消除「预期内」噪声,真超出(如误引大依赖)才再告警。
        chunkSizeWarningLimit: 1200,
        rollupOptions: {
            output: {
                // 分包(Slice52 e):把大块第三方库(尤 antd ~1MB)从 app 代码拆出,改善浏览器缓存——
                // app 代码改动不再使整包失效,vendor chunk 可长期缓存。antd 的传递依赖(rc-*/dayjs)
                // 仅被 antd 引用,自然落入 antd-vendor。
                manualChunks: {
                    'react-vendor': ['react', 'react-dom', 'react-router-dom'],
                    'antd-vendor': ['antd', '@ant-design/icons'],
                    'query-vendor': ['@tanstack/react-query'],
                },
            },
        },
    },
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: ['./src/test-setup.ts'],
    },
});
