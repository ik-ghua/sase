import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider, App as AntdApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import ErrorBoundary from '@/components/ErrorBoundary';
import { setUnauthorizedHandler } from '@/api/client';
import { useAuthStore } from '@/stores/auth';
import { ApiError } from '@/lib/api-error';
import './styles/global.css';

// Slice 44:401 集中处理 —— 任何请求 401 → logout(状态变更);
// AuthGuard 响应式观测 status='unauthenticated' → Navigate /login(避免 hard reload)。
setUnauthorizedHandler(() => {
  useAuthStore.getState().logout();
});

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000,
      // 401/403 不重试(鉴权错重试无意义);其它错重试 1 次
      retry: (failureCount, error) => {
        if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
          return false;
        }
        return failureCount < 1;
      },
    },
  },
});

const themeToken = {
  colorPrimary: '#1677ff',
  fontFamily: 'var(--font-system)',
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN} theme={{ token: themeToken }}>
      <AntdApp>
        <ErrorBoundary>
          <QueryClientProvider client={queryClient}>
            <App />
          </QueryClientProvider>
        </ErrorBoundary>
      </AntdApp>
    </ConfigProvider>
  </React.StrictMode>,
);
