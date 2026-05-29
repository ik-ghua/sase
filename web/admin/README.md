# SASE 平台运维控制台前端

平台运维(platform_admin)用控制台。

- **Slice 41**:项目骨架 + AdminLayout + 7 占位页面
- **Slice 42**:启动鉴权探活 + AuthGuard + dev token 登录 + OIDC 跳转 UI(端到端待真 IdP)
- **Slice 43**:**租户列表页接真 API**(GET /api/v1/platform/tenants);TanStack Query + antd Table + status 筛选 + 排序 + 刷新;**端到端验证 Slice 42 鉴权探活闭环**
- **Slice 44**:**错误边界 + 全局错误处理**;`ApiError` 统一错误类型 + `toApiError` 解析;401 集中登出(client onResponse middleware → logout → AuthGuard 响应式跳 /login);`ErrorBoundary`(渲染期异常)+ `AppError`(403/404/5xx→Result,其它→Alert);QueryClient 全局 retry(401/403 不重试)
- **Slice 45**:**PoP 注册页**(首个写操作页);`Pops.tsx` 列表 GET + 新建 POST(Modal 表单)+ 编辑 PATCH(仅 status/max_users;name/region/endpoint 不可改防 ID 漂移);useMutation + 409 冲突可读提示 + antd message toast;**端到端验证 CSRF cookie+header + Bearer 在 POST/PATCH 真联通**
- **Slice 46**:**平台管理员页**(完整 CRUD,含删除);`Admins.tsx` 列表 + 新建 POST + 编辑 PATCH(status/email,subject 不可改)+ **删除 DELETE**(Popconfirm 二次确认);后端 Slice38c self-delete/self-disable 拦截 → 前端直接展示后端 400 文案(不预判,后端权威);409 subject 冲突提示。**菜单页推进到 3/5**(租户/PoP/平台管理员)
- **Slice 47**:**平台审计页**(只读);`Audit.tsx` GET /platform/audit?limit=N;双层审计 source api(handler)/data(DB 触发器,result=0 显示「触发器」哨兵);source/result Tag 色彩区分;limit 选择器 + 时间倒序排序 + 来源筛选。**4/5**
- **Slice 48**:**管理员令牌签发页**;`AdminTokens.tsx` POST /platform/admin-tokens;role 选择(tenant_admin/auditor 需 tenant_id;platform_admin 无 tenant_id 须已登记);**token 只显示一次**(签发 Modal + 复制按钮 + 提醒);403(subject 不在表)/503(RBAC 未配)可读提示。**5/5 菜单页全完成**
- **Slice 50(g)**:**租户详情 + PATCH + 注销/取消**(租户页从只读升为可操作);`Tenants.tsx` 加「详情」操作列 → Drawer:Descriptions 详情 + 编辑表单(PATCH `/tenants/{tid}`,**只发改动字段** `buildPatch` diff;配额留空=不改、0=限死、暂不能改回「不限」LP-PC1)+ 生命周期(注销 POST `.../decommission` 可选 grace_hours、取消 POST `.../decommission/cancel`);按 status 门控操作(active/suspended 可编辑+可注销;offboarding 显示取消注销;decommissioned 终态只读)。Vitest 40/40(新增 6:Drawer 打开 / PATCH 只发改动 / 无修改不调用 / 注销 body 空 / offboarding 取消按钮 / decommissioned 终态)

## 技术栈
- **React 18** + **TypeScript 5.5(strict)** + **Vite 5**
- **Ant Design v5**(中后台 UI;默认蓝 `#1677ff`,亮色 only)
- **React Router v6** + **TanStack Query v5** + **openapi-fetch**
- **Zustand**(本地状态)
- **Vitest** + **@testing-library/react**(单测)
- **pnpm**(包管理)

## 命令

```bash
pnpm install     # 装依赖
pnpm dev         # 启 dev server,默认 http://localhost:5173
pnpm build       # TypeScript 编译 + Vite 构建,产物 dist/
pnpm test        # 跑 Vitest 单测(*.test.ts)
pnpm test:e2e    # 跑 Playwright 真 Chromium e2e(*.e2e.ts);需先起后端+vite,且 SASE_DEV_TOKEN=<bootstrap token>
pnpm lint        # ESLint 静态检查(0 警告)
pnpm typegen     # 从 ../../api/openapi/admin.yaml 重新生成 src/api/types.ts
```

### e2e(Slice 51/52,真浏览器)
- `e2e/console.e2e.ts`:dev-token 登录 → 租户页(真数据)→ 详情 Drawer → PoP 新建(浏览器真写)。
- `e2e/prefill.e2e.ts`:编辑表单预填(Pops/Admins 编辑 Modal)—— **真浏览器验 antd `destroyOnHidden` Modal 的 `initialValues` 预填**;jsdom 单测掩盖过此类时序 bug(Slice52)。
- `e2e/oidc.e2e.ts`:**真 OIDC 端到端**(自托管 dex)—— 浏览器→dex 真登录→callback 种 `sase_session` cookie(Slice54)。需先按 `e2e/dex-config.yaml` 注释部署 dex + 建 idp_config,跑时设 `OIDC_TID`/`OIDC_IDP`。**注**:OIDC 签发的是租户用户会话,admin API authz 只认 Bearer 不读该 cookie,故验的是 OIDC 机制非"登进控制台"。
- `e2e/dex-config.yaml`:dev-only dex(OIDC IdP)配置 + 部署说明。
- `e2e/helpers.ts`:共享 `login(page)`。

跑法:
```bash
# 1. 按上「后端起步」起 api-server(取日志里的 platform_admin token)+ pnpm dev
# 2. 注入 token 跑 e2e:
SASE_DEV_TOKEN='<粘贴 bootstrap token>' pnpm test:e2e
```
**注**:e2e 用 `*.e2e.ts` 命名与 vitest 的 `*.test.ts` 分流;chromium 经官方 CDN 安装(`npx playwright install chromium`)。

## 后端起步(dev 联调时)—— 2026-05-29 已活体验证

前端的 `/api` 自动 proxy 到 `https://localhost:8443`(Vite 配置 `VITE_API_TARGET` 可覆盖,changeOrigin + secure:false 跳过自签证书校验)。**vite proxy → localhost HTTPS 上游已验证可通**(Slice 49 卡的 "HTTP to HTTPS" 是跨机/SSH 隧道特有,后端在本机 localhost 时无此问题)。

后端 dev 启动(go1.26.3 后本机可直接 `go run`;DSN 可指本地或 VM PG):
```bash
cd /Users/hg/work/sase
OUT=./certs go run ./cmd/devpki              # 一次性生成 dev mTLS 证书到 ./certs
H=192.168.11.66:5432                          # VM PG;本地 PG 换成 localhost:5432
SASE_DB_RW_DSN="postgres://app_rw:app_rw_dev@$H/sase?sslmode=disable" \
SASE_DB_RO_DSN="postgres://app_ro:app_ro_dev@$H/sase?sslmode=disable" \
SASE_DB_PLATFORM_DSN="postgres://app_platform_ro:app_platform_ro_dev@$H/sase?sslmode=disable" \
SASE_DB_PLATFORM_RW_DSN="postgres://app_platform_rw:app_platform_rw_dev@$H/sase?sslmode=disable" \
SASE_TLS_DIR=./certs \
SASE_BOOTSTRAP_PLATFORM_ADMIN=ops \
SASE_CSRF_ALLOWED_ORIGINS=http://localhost:5173 \
go run ./cmd/api-server
# 启动日志打印一枚 15min platform_admin token → 粘到前端 /login「dev token」Tab
```

⚠️ **`SASE_CSRF_ALLOWED_ORIGINS=http://localhost:5173` 在 dev 必设**:前端(5173)与后端(8443)跨源,
经 vite proxy `changeOrigin:true` 后端看到 `Origin: localhost:5173` 而 `Host: localhost:8443` → 非同源,
CSRF Origin 检查会拒写请求(403 "csrf origin check failed")。把前端源登记进白名单即放行(也对齐生产:
生产同样要把控制台真实源加进 `SASE_CSRF_ALLOWED_ORIGINS`)。

未起后端时 `/api/*` 请求 502/连接拒,但 dev server 本身可正常加载页面(仅业务调用失败)。

## 已知调整(对清单偏差)

- `@types/node@^25.9.1` — 提示词清单未列;`vite.config.ts` 用 `path`/`__dirname`/`fileURLToPath` 需要 Node 类型,补装
- 其余依赖与提示词清单完全一致

## CSRF 协同(Slice 40 后端)

后端 Slice 40 中间件:GET 任意非白名单 API 颁发 `csrf_token` cookie(非 HttpOnly);写方法必须把 cookie 值复制到 `X-CSRF-Token` header。

前端处理:`src/api/client.ts` 的 openapi-fetch middleware 在 POST/PATCH/PUT/DELETE 自动注入 header(`getCsrfTokenFromCookie()` from `src/lib/csrf.ts`)。

**前端首屏需 GET 一次任意 API 才能拿到 cookie**,否则写请求 403。下一刀做"首屏 ping" 或登录页 GET。

## 目录布局

```
web/admin/
├── package.json / tsconfig.json / vite.config.ts / index.html
├── .eslintrc.cjs / .prettierrc.json / .gitignore / .npmrc
└── src/
    ├── main.tsx              # ConfigProvider + QueryClientProvider + RouterProvider
    ├── App.tsx               # RouterProvider 包装
    ├── App.test.tsx          # smoke 测试(渲染 AdminLayout)
    ├── test-setup.ts         # jest-dom matchers
    ├── vite-env.d.ts
    ├── styles/global.css     # 系统字体栈(无外部 CDN)
    ├── api/{client.ts,types.ts}  # openapi-fetch + 自动生成类型
    ├── lib/csrf.ts           # getCsrfTokenFromCookie()
    ├── stores/auth.ts        # Zustand auth store(占位)
    ├── layouts/AdminLayout.tsx   # Sider(5菜单)+ Header + Content<Outlet/>
    ├── pages/{Dashboard,Tenants,Pops,Admins,Audit,Login,NotFound}.tsx
    └── routes/index.tsx      # createBrowserRouter
```

## 登录方式(Slice 42)

### dev 模式(本地开发期)
1. 后端启动加 env `SASE_BOOTSTRAP_PLATFORM_ADMIN=ops`,启动期会打印一枚 15min platform_admin token
2. 前端访问 `/login` → "dev token" Tab → 粘 token → "使用 dev token 登录"
3. 鉴权探活 → 渲染 Dashboard

⚠️ token 持久化到 localStorage(XSS 风险),**仅 dev 期可接受**。生产期切 OIDC 模式 → HttpOnly cookie。

### 生产 OIDC 模式
1. 前端访问 `/login` → "OIDC 跳转" Tab → 输 tenant_id + idp_id → "跳转 IdP"
2. 浏览器跳 `/api/v1/idp/login?...&return_to=/` → IdP → callback set HttpOnly `sase_session` cookie + 302 回 return_to
3. 前端 AuthGuard 再次探活 → 200 OK → 渲染

⚠️ **dev 期无真 IdP sandbox**,本模式 UI 通但端到端跑不通(后端 OIDC discovery 会失败)。

### 鉴权探活机制
- App mount → AuthGuard 调 `useAuthStore.probe()`
- 探活流程:GET `/api/v1/trust/pubkey` 触发 csrf cookie 颁发;GET `/api/v1/platform/tenants` 探活:
  - 200 → authenticated + platform_admin → 渲染受保护页
  - 401 → unauthenticated → 跳 `/login`
  - 403 → forbidden(角色非 platform_admin)→ 提示页

## 下一刀候选(优先级排)

- ~~(a) 租户列表页接真 API~~ **✅ Slice 43 已完成**
- ~~(b) 错误边界 + 全局 loading~~ **✅ Slice 44 已完成**
- ~~(c) PoP 注册页~~ **✅ Slice 45 已完成**
- ~~(d) 平台管理员页~~ **✅ Slice 46 已完成**
- ~~平台审计页~~ **✅ Slice 47 已完成**
- ~~管理员令牌页~~ **✅ Slice 48 已完成(5/5 菜单页全完成)**
- ~~(e) antd 包体优化:Vite manualChunks~~ **✅ Slice 53 已完成**(antd-vendor/react-vendor/query-vendor 拆包,app 代码 48KB;`E2E_BASE_URL=http://localhost:4173 pnpm preview` + e2e 验生产构建)
- (f) **真 IdP sandbox 联调**(需要真 corpid/appid 或 dex 部署)
- ~~(g) 租户详情/PATCH/decommission~~ **✅ Slice 50 已完成**
- (h) **真后端活体联调**:起后端 + bootstrap token,浏览器跑通登录→列表→写操作全链路
