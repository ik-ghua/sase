// Package httpapi 注册 Admin REST 路由(租户作用域 + RBAC 鉴权;Go 1.22 方法+路径变量路由)。
// 只依赖各业务模块的 Service 接口,不跨模块内部(总览 3.3 规则 1)。
package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/agentenroll"
	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/authz"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/credrefresh"
	"github.com/ikuai8/sase/internal/csrf"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/fw"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/oidc"
	"github.com/ikuai8/sase/internal/platform"
	"github.com/ikuai8/sase/internal/platformaudit"
	"github.com/ikuai8/sase/internal/platformrbac"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/ratelimit"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/risk"
	"github.com/ikuai8/sase/internal/secret"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

// Register 在 mux 上挂载 Admin API(/api/v1/):请求经 authz 鉴权 → audit 审计变更 → 业务 handler。
// /healthz 等非 /api/v1 路由不受影响(由 booting 注册,无需鉴权)。
// AdminRoutePatterns 是 Admin API 路由的**权威清单**(method + path;Go 1.22 ServeMux 模式)。
// 作 OpenAPI 一致性测试(`openapi_conformance_test.go`)的单一比对源:spec 路径须与本清单逐条一致。
// Register 启动时断言实际注册的 handler 集合与本清单**完全一致**(fail-loud),故清单不会与实现漂移。
// 注:本清单是 **Admin API(api mux,/api/v1/)** 的;设备面 /renew(:8444,RegisterDevice)是设备端点、不在控制台 OpenAPI 范围。
var AdminRoutePatterns = []string{
	"POST /api/v1/tenants",
	"GET /api/v1/tenants/{tid}",
	"PATCH /api/v1/tenants/{tid}",
	"POST /api/v1/tenants/{tid}/users",
	"GET /api/v1/tenants/{tid}/users",
	"POST /api/v1/tenants/{tid}/apps",
	"GET /api/v1/tenants/{tid}/apps",
	"POST /api/v1/tenants/{tid}/connectors",
	"GET /api/v1/tenants/{tid}/connectors",
	"POST /api/v1/tenants/{tid}/policies",
	"GET /api/v1/tenants/{tid}/policies",
	"POST /api/v1/tenants/{tid}/policies/compile",
	"GET /api/v1/tenants/{tid}/policies/bundle",
	"POST /api/v1/tenants/{tid}/credentials",
	"POST /api/v1/tenants/{tid}/credentials/revoke",
	"GET /api/v1/tenants/{tid}/audit",
	// 风险评分快照只读查询(risk RLS 持久化):某主体最新风险快照。handler 用 path tid 做 RLS 上下文。
	"GET /api/v1/tenants/{tid}/risk/{subject}",
	// 风险评分快照列表(N2):列本租户全部快照(score 降序、subject 升序)。handler 用 path tid 做 RLS 上下文。
	"GET /api/v1/tenants/{tid}/risk",
	"POST /api/v1/tenants/{tid}/idp/configs",
	"GET /api/v1/tenants/{tid}/idp/configs",
	"GET /api/v1/tenants/{tid}/idp/configs/{cid}",
	"PATCH /api/v1/tenants/{tid}/idp/configs/{cid}",
	"DELETE /api/v1/tenants/{tid}/idp/configs/{cid}",
	"POST /api/v1/tenants/{tid}/swg/rules",
	"GET /api/v1/tenants/{tid}/swg/rules",
	"PUT /api/v1/tenants/{tid}/swg/rules/{id}",
	"DELETE /api/v1/tenants/{tid}/swg/rules/{id}",
	"POST /api/v1/tenants/{tid}/sites",
	"GET /api/v1/tenants/{tid}/sites",
	"POST /api/v1/tenants/{tid}/fw/rules",
	"GET /api/v1/tenants/{tid}/fw/rules",
	"PUT /api/v1/tenants/{tid}/fw/rules/{id}",
	"DELETE /api/v1/tenants/{tid}/fw/rules/{id}",
	"POST /api/v1/tenants/{tid}/dlp/rules",
	"GET /api/v1/tenants/{tid}/dlp/rules",
	"PUT /api/v1/tenants/{tid}/dlp/rules/{id}",
	"DELETE /api/v1/tenants/{tid}/dlp/rules/{id}",
	"POST /api/v1/tenants/{tid}/enrollments",
	"POST /api/v1/tenants/{tid}/devices/revoke",
	// 已登记设备列表(ZTP 可见性,M2):只读,只暴露非敏感列(不含激活码)。handler 用 path tid 做 RLS 上下文。
	"GET /api/v1/tenants/{tid}/devices",
	"GET /api/v1/platform/tenants",
	"POST /api/v1/platform/tenants/{tid}/decommission",
	"POST /api/v1/platform/tenants/{tid}/decommission/cancel",
	"POST /api/v1/platform/admin-tokens",
	"POST /api/v1/platform/decommissions/sweep",
	// PoP 节点注册(Slice38a / PC-API-3,平台后端铺路);写经 app_platform_rw,读经 app_platform_ro
	"POST /api/v1/platform/pop-nodes",
	"GET /api/v1/platform/pop-nodes",
	"GET /api/v1/platform/pop-nodes/{pid}",
	"PATCH /api/v1/platform/pop-nodes/{pid}",
	// 平台级审计读端点(Slice39,与 tenant audit_log /api/v1/tenants/{tid}/audit 对称)
	"GET /api/v1/platform/audit",
	// 平台 RBAC(Slice38c,multiplatform admin 持久化)
	"POST /api/v1/platform/admins",
	"GET /api/v1/platform/admins",
	"GET /api/v1/platform/admins/{aid}",
	"PATCH /api/v1/platform/admins/{aid}",
	"DELETE /api/v1/platform/admins/{aid}",
	"GET /api/v1/trust/pubkey",
	"POST /api/v1/enroll",
	// 真 OS 级 ZTNA Agent per-user 入网(Slice80;公开端点 = IdP token 引导信任,authz 白名单 + CSRF skip + IP 限流)
	"POST /api/v1/agent/enroll",
	// IdP OIDC 登录入口/回调(Slice37a;authz 已放行,未认证用户经 IdP 换发 SASE 会话凭证)
	"GET /api/v1/idp/login",
	"GET /api/v1/idp/callback",
	// 会话登录/登出(W2):用令牌换 HttpOnly sase_session cookie / 清 cookie。authz 已放行(login 自证身份)。
	"POST /api/v1/login",
	"POST /api/v1/logout",
}

// Register 装配 Admin API 路由。
// oidcDeps / agentEnrollSvc / popReg / platformAuditSvc / platformRBAC / riskSvc 均可为 nil(测试/无 PLATFORM_RW DSN):对应端点返 503(端点仍在,守住路由清单)。
func Register(mux *http.ServeMux, tenantSvc tenant.Service, identitySvc identity.Service, policySvc policy.Service, resourceSvc resource.Service, auditSvc audit.Service, swgSvc swg.Service, siteSvc site.Service, fwSvc fw.Service, dlpSvc dlp.Service, enrollSvc enroll.Service, platformSvc platform.Service, popReg platform.PopRegistry, platformAuditSvc platformaudit.Service, platformRBAC platformrbac.Service, idpSvc idp.Service, oidcDeps *oidc.HandlerDeps, agentEnrollSvc *agentenroll.Service, enrollLimiter *ratelimit.Limiter, verifier *cred.Verifier, adminActiveChecker authz.AdminActiveChecker, apiRec *metrics.APIRecorder, riskSvc *risk.Service) {
	// 路由表(pattern → handler);键须与 AdminRoutePatterns 完全一致(下方 assert 守)。
	handlers := map[string]http.Handler{
		"POST /api/v1/tenants":                          createTenant(tenantSvc),
		"GET /api/v1/tenants/{tid}":                     getTenant(tenantSvc),
		"PATCH /api/v1/tenants/{tid}":                   updateTenant(tenantSvc),
		"POST /api/v1/tenants/{tid}/users":              createUser(identitySvc),
		"GET /api/v1/tenants/{tid}/users":               listUsers(identitySvc),
		"POST /api/v1/tenants/{tid}/apps":               createApp(resourceSvc),
		"GET /api/v1/tenants/{tid}/apps":                listApps(resourceSvc),
		"POST /api/v1/tenants/{tid}/connectors":         createConnector(resourceSvc),
		"GET /api/v1/tenants/{tid}/connectors":          listConnectors(resourceSvc),
		"POST /api/v1/tenants/{tid}/policies":           createPolicy(policySvc),
		"GET /api/v1/tenants/{tid}/policies":            listPolicies(policySvc),
		"POST /api/v1/tenants/{tid}/policies/compile":   compilePolicies(policySvc),
		"GET /api/v1/tenants/{tid}/policies/bundle":     getActiveBundle(policySvc),
		"POST /api/v1/tenants/{tid}/credentials":        issueCredential(identitySvc),
		"POST /api/v1/tenants/{tid}/credentials/revoke": revokeCredential(identitySvc),
		"GET /api/v1/tenants/{tid}/audit":               listAudit(auditSvc),
		// 风险评分快照只读查询(risk RLS 持久化):riskSvc nil → 503;快照层未配 → 503;无快照 → 404。
		"GET /api/v1/tenants/{tid}/risk/{subject}": getRiskScore(riskSvc),
		// 风险评分快照列表(N2):列本租户全部快照(score 降序、subject 升序)。riskSvc nil / 快照层未配 → 503。
		"GET /api/v1/tenants/{tid}/risk": listRiskScores(riskSvc),
		// IdP 配置 CRUD(Slice36,secret 模块首个加密消费者:client_secret 经租户 DEK 加密落库)
		"POST /api/v1/tenants/{tid}/idp/configs":         createIDPConfig(idpSvc),
		"GET /api/v1/tenants/{tid}/idp/configs":          listIDPConfigs(idpSvc),
		"GET /api/v1/tenants/{tid}/idp/configs/{cid}":    getIDPConfig(idpSvc),
		"PATCH /api/v1/tenants/{tid}/idp/configs/{cid}":  updateIDPConfig(idpSvc),
		"DELETE /api/v1/tenants/{tid}/idp/configs/{cid}": deleteIDPConfig(idpSvc),
		"POST /api/v1/tenants/{tid}/swg/rules":           createSWGRule(swgSvc),
		"GET /api/v1/tenants/{tid}/swg/rules":            listSWGRules(swgSvc),
		"PUT /api/v1/tenants/{tid}/swg/rules/{id}":       updateSWGRule(swgSvc),
		"DELETE /api/v1/tenants/{tid}/swg/rules/{id}":    deleteSWGRule(swgSvc),
		"POST /api/v1/tenants/{tid}/sites":               createSite(siteSvc),
		"GET /api/v1/tenants/{tid}/sites":                listSites(siteSvc),
		"POST /api/v1/tenants/{tid}/fw/rules":            createFWRule(fwSvc),
		"GET /api/v1/tenants/{tid}/fw/rules":             listFWRules(fwSvc),
		"PUT /api/v1/tenants/{tid}/fw/rules/{id}":        updateFWRule(fwSvc),
		"DELETE /api/v1/tenants/{tid}/fw/rules/{id}":     deleteFWRule(fwSvc),
		"POST /api/v1/tenants/{tid}/dlp/rules":           createDLPRule(dlpSvc),
		"GET /api/v1/tenants/{tid}/dlp/rules":            listDLPRules(dlpSvc),
		"PUT /api/v1/tenants/{tid}/dlp/rules/{id}":       updateDLPRule(dlpSvc),
		"DELETE /api/v1/tenants/{tid}/dlp/rules/{id}":    deleteDLPRule(dlpSvc),
		"POST /api/v1/tenants/{tid}/enrollments":         createEnrollment(enrollSvc),
		"POST /api/v1/tenants/{tid}/devices/revoke":      revokeDevice(enrollSvc),
		// 已登记设备列表(M2):handler 用 path tid 做 RLS;platform_admin 经 path-tid 读任意租户(对齐 listUsers/listPolicies)。
		"GET /api/v1/tenants/{tid}/devices": listDevices(enrollSvc),
		// 平台跨租户(PC-API-1):全租户列表。authz 默认分支已限 platform_admin;经 platform 模块 InPlatformTx 读策展视图。
		"GET /api/v1/platform/tenants": listPlatformTenants(platformSvc),
		// 平台租户注销宽限期(PC-API-2b):/platform/* 经 authz 默认分支限 platform_admin(租户管理员不能注销自身)。
		"POST /api/v1/platform/tenants/{tid}/decommission":        decommissionTenant(tenantSvc),
		"POST /api/v1/platform/tenants/{tid}/decommission/cancel": cancelDecommissionTenant(tenantSvc),
		// PC-API-5:平台签发 tenant 作用域 admin 令牌(IdP-based 登录到位前的临时机制)。
		"POST /api/v1/platform/admin-tokens": issueAdminToken(identitySvc, auditSvc, platformAuditSvc, platformRBAC),
		// 硬删自动清扫(Slice35,串起 Slice33c 注销宽限+Slice34 secret 销毁):宽限期已到的租户硬删 DEK + 状态→decommissioned。
		// Slice36(b)重构:编排移至 platform.RunDecommissionSweep(handler 与 cmd cron 共用单一编排源)。
		"POST /api/v1/platform/decommissions/sweep": sweepDecommissions(platformSvc),
		// PoP 节点注册(Slice38a):popReg nil → 503 NotConfigured(同 oidcDeps 形态,守路由清单)
		"POST /api/v1/platform/pop-nodes":        createPopNode(popReg, platformAuditSvc),
		"GET /api/v1/platform/pop-nodes":         listPopNodes(popReg),
		"GET /api/v1/platform/pop-nodes/{pid}":   getPopNode(popReg),
		"PATCH /api/v1/platform/pop-nodes/{pid}": updatePopNode(popReg, platformAuditSvc),
		// Slice39:平台级审计读取(与 tenant audit 对称;authz 默认分支已限 platform_admin)
		"GET /api/v1/platform/audit": listPlatformAudit(platformAuditSvc),
		// Slice38c:平台 RBAC CRUD;authz 默认分支已限 platform_admin
		"POST /api/v1/platform/admins":         createPlatformAdmin(platformRBAC, platformAuditSvc),
		"GET /api/v1/platform/admins":          listPlatformAdmins(platformRBAC),
		"GET /api/v1/platform/admins/{aid}":    getPlatformAdmin(platformRBAC),
		"PATCH /api/v1/platform/admins/{aid}":  updatePlatformAdmin(platformRBAC, platformAuditSvc),
		"DELETE /api/v1/platform/admins/{aid}": deletePlatformAdmin(platformRBAC, platformAuditSvc),
		"GET /api/v1/trust/pubkey":             trustPubkey(identitySvc),
		// ZTP 兑换:公开(设备凭激活码),authz 中已放行;路径不带 {tid}(租户由激活码前缀解析)。公开端点按来源 IP 限流,防枚举/暴力。
		"POST /api/v1/enroll": ratelimit.Wrap(enrollLimiter, ratelimit.ClientIP, redeemEnrollment(enrollSvc)),
		// 真 OS 级 ZTNA Agent per-user 入网(Slice80):公开端点(引导态无 mTLS/cred,信任来自 IdP token),
		// authz 白名单 + CSRF skip + 复用 /enroll 的 IP 限流防枚举;agentEnrollSvc nil → 503(守路由清单,同 oidcDeps)。
		"POST /api/v1/agent/enroll": ratelimit.Wrap(enrollLimiter, ratelimit.ClientIP, agentEnroll(agentEnrollSvc)),
		// IdP OIDC 登录/回调:authz 已放行未认证;oidcDeps nil 时返 503(便兼容无 OIDC 部署 + 测试 nil 注入)
		"GET /api/v1/idp/login":    oidcLogin(oidcDeps),
		"GET /api/v1/idp/callback": oidcCallback(oidcDeps),
		// 会话登录/登出(W2):login 验令牌(同 authz 校验)→ 种 HttpOnly sase_session cookie;logout 清 cookie。
		// R2(Slice74 reviewer 跟进):/login 是未认证公开端点,按来源 IP 限流(同 /enroll、/renew 模式),
		// 防探测/暴力/资源消耗(签名验证 CPU)。logout 只清自己 cookie(无副作用、幂等),不限流。
		"POST /api/v1/login":  ratelimit.Wrap(loginLimiter(), ratelimit.ClientIP, sessionLogin(authz.NewGuard(verifier))),
		"POST /api/v1/logout": sessionLogout(),
	}
	assertRouteCoverage(handlers) // fail-loud:handler 集合须与 AdminRoutePatterns 逐条一致(防清单↔实现漂移)

	api := http.NewServeMux()
	for pat, h := range handlers {
		api.Handle(pat, h)
	}

	// 顺序(Slice40 起):**csrf**(写方法 double-submit + Origin 校验;GET 颁发 cookie)→ authz(鉴权)→ actor(归因)→ audit → api 业务
	// csrf 在 authz 之前:无效 token 早拒,避免做无用的签名验证;白名单覆盖设备/公开端点。
	// **AllowedOrigins**(env-gated `SASE_CSRF_ALLOWED_ORIGINS` 逗号分隔)生产严格;空走同源(dev 便利)。
	csrfMW := csrf.Middleware(csrf.Config{
		AllowedOrigins: csrfAllowedOriginsFromEnv(),
		Skip: map[string]bool{
			"/api/v1/enroll":       true, // 设备端点(非浏览器,无 cookie)
			"/api/v1/agent/enroll": true, // Agent 引导入网(非浏览器/无 cookie;信任来自 IdP token,Slice80)
			"/api/v1/idp/login":    true, // GET 跳 IdP;白名单避免冗余颁发(GET 本身不校验)
			"/api/v1/idp/callback": true, // GET IdP→服务端跳转
			"/api/v1/trust/pubkey": true, // 公开只读
			// 会话登录(W2):首次登录浏览器尚无 csrf_token cookie(double-submit 无从满足),
			// 故白名单(同 /idp/callback)。防护退化为:① 请求体须含合法签名令牌(攻击者无从伪造);
			// ② 即便 CSRF 强制浏览器发起 login,得到的也只是把**攻击者自己的**令牌种进受害者浏览器
			//    (login-CSRF,非提权——受害者会以攻击者身份登录,无横向危害,且无凭证可窃)。
			"/api/v1/login": true,
			// 登出无副作用(只清 cookie,幂等),白名单避免登出受 CSRF token 缺失阻塞。
			"/api/v1/logout": true,
		},
	})
	chain := csrfMW(authz.NewGuard(verifier).WithAdminActiveChecker(adminActiveChecker).Middleware(audit.ActorMiddleware(audit.Middleware(auditSvc)(api))))
	// 最外层 RED 指标(Slice59→60):route 取内层 api mux 注册的 pattern(低基数模板,非真实路径/不打 tenant);
	// apiRec=nil 则透传(测试不启用)。
	routeOf := func(r *http.Request) string { _, pat := api.Handler(r); return pat }
	mux.Handle("/api/v1/", metrics.HTTPMiddleware(apiRec, routeOf)(chain))
}

// loginRate/loginBurst 是 /login 限流参数(R2,Slice74 reviewer 跟进)。
//
// 速率依据:/login 是人工交互登录(非高频自动化),且令牌为密码学签名不可伪造
// → 真实威胁是探测/暴力尝试的**资源消耗**(每次验签耗 CPU)而非令牌猜解。
// 取 burst=10、稳态 0.5/s(≈30 次/分钟/IP):对人(含输错重试/多标签页)足够宽松,
// 同时把单 IP 自动化 hammer 钳到 ~30/min。比 /enroll(1/5s)宽——登录交互频率天然高于设备入网。
// 局限同 ratelimit 包:单实例内存计数,多副本不共享(生产网关侧另做分布式限流,本限流为纵深兜底)。
const (
	loginRate  = 0.5
	loginBurst = 10
)

// loginLimiterOnce/loginLimiterInst 实现进程级 /login 限流器单例。
//
// 为何 package-level 单例:Register 签名不含 ctx 且生产/测试会多次调用;
// 用单例使**整个进程仅一个 /login 限流桶 + 一个 janitor goroutine**,
// 既避免每次 Register 泄漏 goroutine(测试多次调用),又让多 mux 共享同一 IP 视图。
var (
	loginLimiterOnce sync.Once
	loginLimiterInst *ratelimit.Limiter
)

// loginLimiter 懒构造进程级 /login 限流器(首次调用启动唯一 janitor)。
func loginLimiter() *ratelimit.Limiter {
	loginLimiterOnce.Do(func() {
		loginLimiterInst = ratelimit.New(loginRate, loginBurst)
		// janitor:周期淘汰空闲 IP 桶,约束公开端点内存(IP 键不可无界增长)。
		// context.Background():进程级单例,生命周期=进程;每进程仅此一个 janitor goroutine。
		loginLimiterInst.StartJanitor(context.Background(), 10*time.Minute, 30*time.Minute)
	})
	return loginLimiterInst
}

// csrfAllowedOriginsFromEnv 从 SASE_CSRF_ALLOWED_ORIGINS 读逗号分隔列表(scheme://host[:port])。
// 空 → 中间件走同源回退(dev 便利);生产部署必须显式列(否则跨子域/CDN 行为不可控)。
func csrfAllowedOriginsFromEnv() []string {
	v := os.Getenv("SASE_CSRF_ALLOWED_ORIGINS")
	if v == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// maxDetailLen 限审计 detail 长度(防超长 user-controlled 串撑爆审计/SIEM 解析侧)。
const maxDetailLen = 256

// sanitizeDetail 剥换行/回车(防"detail 内嵌 \n 伪造分割字段污染 SIEM 解析",评审 Slice33e S1)+ 截断 ≤ maxDetailLen。
func sanitizeDetail(s string) string {
	r := []rune(s)
	for i, c := range r {
		if c == '\n' || c == '\r' || c == 0 {
			r[i] = ' '
		}
	}
	if len(r) > maxDetailLen {
		r = r[:maxDetailLen]
	}
	return string(r)
}

// assertRouteCoverage fail-loud 校验 handler 集合与 AdminRoutePatterns 逐条一致(启动期程序错误即 panic):
// 防"加了 handler 忘登清单"或"清单有项无 handler",使 AdminRoutePatterns 始终等于实际路由(OpenAPI 测试可信比对)。
func assertRouteCoverage(handlers map[string]http.Handler) {
	want := make(map[string]bool, len(AdminRoutePatterns))
	for _, p := range AdminRoutePatterns {
		want[p] = true
		if handlers[p] == nil {
			panic("httpapi: AdminRoutePatterns 有 " + p + " 但 handlers 缺(路由清单↔实现漂移)")
		}
	}
	for p := range handlers {
		if !want[p] {
			panic("httpapi: handlers 有 " + p + " 但不在 AdminRoutePatterns 清单(漏登清单)")
		}
	}
}

func getTenant(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := svc.Get(r.Context(), r.PathValue("tid"))
		if errors.Is(err, tenant.ErrNotFound) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		if err != nil {
			writeInternalErr(w, "getTenant", err)
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

// updateTenant 部分更新租户(PC-API-2a,平台运维:停用/恢复/改名)。authz 已限 platform_admin(租户本身写=平台级)。
func updateTenant(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var patch tenant.Patch
		if !decode(w, r, &patch) {
			return
		}
		t, err := svc.Update(r.Context(), r.PathValue("tid"), patch)
		switch {
		case errors.Is(err, tenant.ErrNotFound):
			http.Error(w, "tenant not found", http.StatusNotFound)
		case errors.Is(err, tenant.ErrNoPatchFields), errors.Is(err, tenant.ErrInvalidPatch):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case err != nil:
			writeInternalErr(w, "updateTenant", err)
		default:
			writeJSON(w, http.StatusOK, t)
		}
	}
}

// defaultDecommissionGrace 是注销宽限期默认值(LP-PC5 时长待定;30 天供客户导出/挽留窗口,可经请求 grace_hours 覆盖)。
const defaultDecommissionGrace = 30 * 24 * time.Hour

// decommissionTenant 标注租户进入注销宽限期(PC-API-2b)。/platform/* 经 authz 限 platform_admin。
func decommissionTenant(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GraceHours int `json:"grace_hours"` // 0/缺省 → 用默认
		}
		// body 可选(空 body 用默认宽限期):容忍 EOF(空/无 body),仅在 body 存在但非法时 400。
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		grace := defaultDecommissionGrace
		if body.GraceHours > 0 {
			grace = time.Duration(body.GraceHours) * time.Hour
		}
		t, err := svc.Decommission(r.Context(), r.PathValue("tid"), grace)
		switch {
		case errors.Is(err, tenant.ErrNotFound):
			http.Error(w, "tenant not found", http.StatusNotFound)
		case errors.Is(err, tenant.ErrInvalidPatch):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case err != nil:
			writeInternalErr(w, "decommissionTenant", err)
		default:
			writeJSON(w, http.StatusOK, t)
		}
	}
}

// cancelDecommissionTenant 在宽限期内取消注销(PC-API-2b)。
func cancelDecommissionTenant(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := svc.CancelDecommission(r.Context(), r.PathValue("tid"))
		switch {
		case errors.Is(err, tenant.ErrNotDecommissioning):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			writeInternalErr(w, "cancelDecommissionTenant", err)
		default:
			writeJSON(w, http.StatusOK, t)
		}
	}
}

// IdP 配置 CRUD(Slice36)。Config 响应**不含 client_secret**(防意外序列化;adapter 后续刀走 GetClientSecret)。
// Create/Update 接受 client_secret 明文,服务端 secret.Encrypt 加密入库。
func createIDPConfig(svc idp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req idp.CreateRequest
		if !decode(w, r, &req) {
			return
		}
		c, err := svc.Create(r.Context(), r.PathValue("tid"), req)
		switch {
		case errors.Is(err, idp.ErrInvalidPatch):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, secret.ErrNotFound), errors.Is(err, secret.ErrDestroyed):
			http.Error(w, "tenant DEK not available: "+err.Error(), http.StatusConflict)
		case err != nil:
			writeInternalErr(w, "createIDPConfig", err)
		default:
			writeJSON(w, http.StatusCreated, c)
		}
	}
}

func listIDPConfigs(svc idp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cs, err := svc.List(r.Context(), r.PathValue("tid"))
		if err != nil {
			writeInternalErr(w, "listIDPConfigs", err)
			return
		}
		writeJSON(w, http.StatusOK, cs)
	}
}

func getIDPConfig(svc idp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := svc.Get(r.Context(), r.PathValue("tid"), r.PathValue("cid"))
		switch {
		case errors.Is(err, idp.ErrNotFound):
			http.Error(w, "idp config not found", http.StatusNotFound)
		case err != nil:
			writeInternalErr(w, "getIDPConfig", err)
		default:
			writeJSON(w, http.StatusOK, c)
		}
	}
}

func updateIDPConfig(svc idp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var patch idp.Patch
		if !decode(w, r, &patch) {
			return
		}
		c, err := svc.Update(r.Context(), r.PathValue("tid"), r.PathValue("cid"), patch)
		switch {
		case errors.Is(err, idp.ErrNotFound):
			http.Error(w, "idp config not found", http.StatusNotFound)
		case errors.Is(err, idp.ErrInvalidPatch):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, secret.ErrDestroyed):
			http.Error(w, "tenant DEK destroyed: "+err.Error(), http.StatusConflict)
		case err != nil:
			writeInternalErr(w, "updateIDPConfig", err)
		default:
			writeJSON(w, http.StatusOK, c)
		}
	}
}

func deleteIDPConfig(svc idp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := svc.Delete(r.Context(), r.PathValue("tid"), r.PathValue("cid"))
		switch {
		case errors.Is(err, idp.ErrNotFound):
			http.Error(w, "idp config not found", http.StatusNotFound)
		case err != nil:
			writeInternalErr(w, "deleteIDPConfig", err)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

// sweepDecommissions 硬删自动清扫(Slice35+36b)。platform_admin 触发;编排移至 platform.RunDecommissionSweep
// (handler 与 cmd cron 共用单一编排源,避免 drift)。失败结构由 platform.SweepResult/Skip 定义,JSON 序列化等价。
func sweepDecommissions(platformSvc platform.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := platformSvc.RunDecommissionSweep(r.Context())
		if err != nil {
			writeInternalErr(w, "sweepDecommissions", err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// issueAdminToken 平台签发 admin 令牌(PC-API-5 / Slice38c 扩展)。支持的 role:
//   - tenant_admin / auditor:**必带 tenant_id**(tenant-scoped 作用域,审计落 target tenant);
//   - **platform_admin(Slice38c 新增)**:**必查 platformrbac.IsActive(subject)** 且 **不带 tenant_id**;
//     subject 不在 platform_admins 表 / 非 active → 403;**绕过表的唯一路径仅 bootstrap_platform_admin env**(应急通道)。
//
// **IdP-based 管理员登录到位前的临时机制**(signed 令牌 + ≤12h TTL),非生产终态——生产应走 IdP 登录换令牌。
//
// **双向审计**(评审 B2 / Slice39 闭环):
//   - tenant audit_log:detail 落 target tenant(运营查租户视角);**platform_admin 路径无 target tenant,跳过**;
//   - platform_audit_log:落平台视角的同事件(target_tenant_id 关联,role=platform_admin 时 target 为空);
//   - **detail 只记 subject+role,绝不记 token**(凭证泄露面);两边写均失败仅 log,不阻塞签发链(best-effort)。
func issueAdminToken(identitySvc identity.Service, auditSvc audit.Service, platformAuditSvc platformaudit.Service, platformRBAC platformrbac.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Subject    string `json:"subject"`
			Role       string `json:"role"`
			TenantID   string `json:"tenant_id"`
			TTLSeconds int    `json:"ttl_seconds"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.Subject == "" {
			http.Error(w, "subject required", http.StatusBadRequest)
			return
		}
		switch body.Role {
		case authz.RoleTenantAdmin, authz.RoleAuditor:
			if body.TenantID == "" {
				http.Error(w, "tenant_id required for tenant-scoped role", http.StatusBadRequest)
				return
			}
		case authz.RolePlatformAdmin:
			// Slice38c:必查 platform_admins 表(绕过=应急 bootstrap env-only)
			// 参数校验先于 deps 检查(纯参数错应返 400 即便 RBAC 未配置)
			if body.TenantID != "" {
				http.Error(w, "tenant_id must be empty for platform_admin (cross-tenant scope)", http.StatusBadRequest)
				return
			}
			if platformRBAC == nil {
				http.Error(w, "platform RBAC not configured", http.StatusServiceUnavailable)
				return
			}
			ok, err := platformRBAC.IsActive(r.Context(), body.Subject)
			if err != nil {
				log.Printf("[admin] platform_admin 表查询失败 subject=%s: %v", body.Subject, err)
				http.Error(w, "platform RBAC check failed", http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "subject not in platform_admins or disabled", http.StatusForbidden)
				return
			}
		default:
			http.Error(w, "role must be tenant_admin, auditor, or platform_admin", http.StatusBadRequest)
			return
		}
		ttl := time.Duration(body.TTLSeconds) * time.Second
		token, err := identitySvc.IssueAdminToken(r.Context(), body.Subject, body.Role, body.TenantID, ttl)
		switch {
		case errors.Is(err, identity.ErrNoSigner):
			http.Error(w, err.Error(), http.StatusServiceUnavailable) // 签发器未就绪,对齐 issueCredential 模式
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest) // 余多为参数错(角色/scope/TTL)
			return
		}
		// 实际生效 TTL(IssueAdminToken 钳制:<=0 或 >MaxAdminTTL → MaxAdminTTL);用相同逻辑算 expires_at
		effectiveTTL := ttl
		if effectiveTTL <= 0 || effectiveTTL > identity.MaxAdminTTL {
			effectiveTTL = identity.MaxAdminTTL
		}
		expiresAt := time.Now().Add(effectiveTTL)

		// 显式审计(平台路径,api 中间件不归属)
		if p, ok := authz.FromContext(r.Context()); ok {
			detail := sanitizeDetail("subject=" + body.Subject + " role=" + body.Role)
			// (1) tenant audit_log:target tenant 视角(谁给本租户发了令牌)
			// **role=platform_admin 时 TenantID 为空,跳过 tenant audit_log**(无 target tenant 可归属;由 platform_audit_log 兜底)
			if body.TenantID != "" {
				//nolint:contextcheck // 审计写独立于请求 ctx(客户端断开不丢审计,同 audit middleware)
				if e := auditSvc.Record(context.Background(), audit.Entry{
					TenantID:     body.TenantID,
					ActorSubject: p.Subject,
					ActorRole:    p.Role,
					Action:       "POST /api/v1/platform/admin-tokens",
					Result:       http.StatusOK,
					Detail:       detail,
					Source:       audit.SourceAPI,
				}); e != nil {
					log.Printf("[admin] admin-token tenant 审计失败 target=%s subject=%s: %v", body.TenantID, body.Subject, e)
				}
			}
			// (2) platform_audit_log:平台视角统一留痕(target_tenant_id 关联);评审 B2 Slice39 闭环
			if platformAuditSvc != nil {
				//nolint:contextcheck // 同上
				if e := platformAuditSvc.Record(context.Background(), platformaudit.Entry{
					ActorSubject:   p.Subject,
					ActorRole:      p.Role,
					Action:         "POST /api/v1/platform/admin-tokens",
					Result:         http.StatusOK,
					Detail:         detail,
					Source:         platformaudit.SourceAPI,
					TargetTenantID: body.TenantID,
				}); e != nil {
					log.Printf("[admin] admin-token platform 审计失败 target=%s subject=%s: %v", body.TenantID, body.Subject, e)
				}
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"token":      token,
			"subject":    body.Subject,
			"role":       body.Role,
			"tenant_id":  body.TenantID,
			"expires_at": expiresAt,
		})
	}
}

func createTenant(svc tenant.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var t tenant.Tenant
		if !decode(w, r, &t) {
			return
		}
		if t.ID == "" {
			t.ID = uuid.NewString()
		}
		if err := svc.Create(r.Context(), &t); err != nil {
			writeInternalErr(w, "createTenant", err)
			return
		}
		writeJSON(w, http.StatusCreated, t)
	}
}

func createUser(svc identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var u identity.User
		if !decode(w, r, &u) {
			return
		}
		u.TenantID = r.PathValue("tid") // 路径是租户作用域的唯一真相,覆盖 body
		if u.ID == "" {
			u.ID = uuid.NewString()
		}
		if err := svc.Create(r.Context(), &u); err != nil {
			writeInternalErr(w, "createUser", err)
			return
		}
		writeJSON(w, http.StatusCreated, u)
	}
}

func listUsers(svc identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		us, err := svc.ListByTenant(r.Context(), r.PathValue("tid"))
		if err != nil {
			writeInternalErr(w, "listUsers", err)
			return
		}
		writeJSON(w, http.StatusOK, us)
	}
}

func createPolicy(svc policy.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p policy.Policy
		if !decode(w, r, &p) {
			return
		}
		if err := svc.CreatePolicy(r.Context(), r.PathValue("tid"), &p); err != nil {
			writeInternalErr(w, "createPolicy", err)
			return
		}
		writeJSON(w, http.StatusCreated, p)
	}
}

// listPolicies 列出该租户编写态策略(Slice58)。handler 用 path tid 做 RLS 上下文,
// 故 platform_admin(TenantID 空)可读任意租户;authz 已守作用域。
func listPolicies(svc policy.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ps, err := svc.ListByTenant(r.Context(), r.PathValue("tid"))
		if err != nil {
			log.Printf("[admin] listPolicies tid=%s failed: %v", r.PathValue("tid"), err)
			http.Error(w, "list policies failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, ps)
	}
}

func compilePolicies(svc policy.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := svc.Compile(r.Context(), r.PathValue("tid"))
		if err != nil {
			// 编译错误(含 fail-closed 校验/冲突)回 422,带定位信息供租户管理员修正
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func getActiveBundle(svc policy.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := svc.ActiveBundle(r.Context(), r.PathValue("tid"))
		if errors.Is(err, policy.ErrNoActiveBundle) {
			http.Error(w, "no active bundle", http.StatusNotFound)
			return
		}
		if err != nil {
			writeInternalErr(w, "getActiveBundle", err)
			return
		}
		writeJSON(w, http.StatusOK, b)
	}
}

func createApp(svc resource.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var a resource.App
		if !decode(w, r, &a) {
			return
		}
		if err := svc.CreateApp(r.Context(), r.PathValue("tid"), &a); err != nil {
			// 错误码治理(Slice73):校验错→400、app_key 唯一冲突→409、DB/内部错→500 脱敏。
			writeValidationOr500(w, "createApp", err, resource.ErrInvalidResource)
			return
		}
		writeJSON(w, http.StatusCreated, a)
	}
}

func listApps(svc resource.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		as, err := svc.ListApps(r.Context(), r.PathValue("tid"))
		if err != nil {
			writeInternalErr(w, "listApps", err)
			return
		}
		writeJSON(w, http.StatusOK, as)
	}
}

func createConnector(svc resource.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c resource.Connector
		if !decode(w, r, &c) {
			return
		}
		if err := svc.CreateConnector(r.Context(), r.PathValue("tid"), &c); err != nil {
			// 错误码治理(Slice73):校验错→400、唯一冲突→409(connectors 无 UNIQUE,实际不触发,留作纵深)、DB/内部错→500 脱敏。
			writeValidationOr500(w, "createConnector", err, resource.ErrInvalidResource)
			return
		}
		writeJSON(w, http.StatusCreated, c)
	}
}

func listConnectors(svc resource.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cs, err := svc.ListConnectors(r.Context(), r.PathValue("tid"))
		if err != nil {
			writeInternalErr(w, "listConnectors", err)
			return
		}
		writeJSON(w, http.StatusOK, cs)
	}
}

func issueCredential(svc identity.Service) http.HandlerFunc {
	type reqBody struct {
		UserID     string   `json:"user_id"`
		Groups     []string `json:"groups"`
		Posture    string   `json:"posture"`
		TTLSeconds int      `json:"ttl_seconds"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body reqBody
		if !decode(w, r, &body) {
			return
		}
		ttl := time.Duration(body.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 5 * time.Minute // 默认短 TTL(L1 3.8)
		}
		token, jti, err := svc.IssueCredential(r.Context(), r.PathValue("tid"), body.UserID, body.Groups, body.Posture, ttl)
		if errors.Is(err, identity.ErrNoSigner) {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			writeInternalErr(w, "issueCredential", err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"token": token, "jti": jti})
	}
}

func revokeCredential(svc identity.Service) http.HandlerFunc {
	type reqBody struct {
		JTI     string `json:"jti"`
		Subject string `json:"subject"`
		Reason  string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body reqBody
		if !decode(w, r, &body) {
			return
		}
		if err := svc.RevokeCredential(r.Context(), r.PathValue("tid"), body.JTI, body.Subject, body.Reason); err != nil {
			writeInternalErr(w, "revokeCredential", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "jti": body.JTI})
	}
}

// writeRuleError 把规则 CRUD 错误分流为 HTTP 状态(Slice66 错误码治理):
//   - 不存在(含跨租户 RLS 不可见)→ 404(通用文案);
//   - 校验失败(ErrInvalidRule)→ 400(校验信息对调用方有用且安全,可回显);
//   - 其它(DB/内部)→ 500(脱敏:记日志保留细节,响应只给通用文案,不泄漏内部错误)。
func writeRuleError(w http.ResponseWriter, op string, err error, notFound, invalid error) {
	switch {
	case errors.Is(err, notFound):
		http.Error(w, "规则不存在", http.StatusNotFound)
	case errors.Is(err, invalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		log.Printf("[admin] %s 内部错误: %v", op, err)
		http.Error(w, "服务端错误", http.StatusInternalServerError)
	}
}

func createSWGRule(svc swg.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule swg.Rule
		if !decode(w, r, &rule) {
			return
		}
		if err := svc.CreateRule(r.Context(), r.PathValue("tid"), &rule); err != nil {
			writeRuleError(w, "create swg rule", err, swg.ErrNotFound, swg.ErrInvalidRule)
			return
		}
		writeJSON(w, http.StatusCreated, rule)
	}
}

func listSWGRules(svc swg.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rs, err := svc.ListRules(r.Context(), r.PathValue("tid"))
		if err != nil {
			log.Printf("[admin] list swg rules 内部错误: %v", err)
			http.Error(w, "服务端错误", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rs)
	}
}

func createFWRule(svc fw.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule fw.Rule
		if !decode(w, r, &rule) {
			return
		}
		if err := svc.CreateRule(r.Context(), r.PathValue("tid"), &rule); err != nil {
			writeRuleError(w, "create fw rule", err, fw.ErrNotFound, fw.ErrInvalidRule)
			return
		}
		writeJSON(w, http.StatusCreated, rule)
	}
}

func listFWRules(svc fw.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rs, err := svc.ListRules(r.Context(), r.PathValue("tid"))
		if err != nil {
			log.Printf("[admin] list fw rules 内部错误: %v", err)
			http.Error(w, "服务端错误", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rs)
	}
}

func createDLPRule(svc dlp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule dlp.Rule
		if !decode(w, r, &rule) {
			return
		}
		if err := svc.CreateRule(r.Context(), r.PathValue("tid"), &rule); err != nil {
			writeRuleError(w, "create dlp rule", err, dlp.ErrNotFound, dlp.ErrInvalidRule)
			return
		}
		writeJSON(w, http.StatusCreated, rule)
	}
}

func listDLPRules(svc dlp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rs, err := svc.ListRules(r.Context(), r.PathValue("tid"))
		if err != nil {
			log.Printf("[admin] list dlp rules 内部错误: %v", err)
			http.Error(w, "服务端错误", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rs)
	}
}

// ── 安全规则 PUT(全量替换)/ DELETE(三项能力对称;PUT 复用 Create 校验,DELETE 幂等)──
// 错误码分流见 writeRuleError(404/400/500);成功 PUT → 200+规则、DELETE → 204。

func updateSWGRule(svc swg.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule swg.Rule
		if !decode(w, r, &rule) {
			return
		}
		if err := svc.UpdateRule(r.Context(), r.PathValue("tid"), r.PathValue("id"), &rule); err != nil {
			writeRuleError(w, "update swg rule", err, swg.ErrNotFound, swg.ErrInvalidRule)
			return
		}
		writeJSON(w, http.StatusOK, rule)
	}
}

func deleteSWGRule(svc swg.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeleteRule(r.Context(), r.PathValue("tid"), r.PathValue("id")); err != nil {
			writeRuleError(w, "delete swg rule", err, swg.ErrNotFound, swg.ErrInvalidRule)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func updateFWRule(svc fw.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule fw.Rule
		if !decode(w, r, &rule) {
			return
		}
		if err := svc.UpdateRule(r.Context(), r.PathValue("tid"), r.PathValue("id"), &rule); err != nil {
			writeRuleError(w, "update fw rule", err, fw.ErrNotFound, fw.ErrInvalidRule)
			return
		}
		writeJSON(w, http.StatusOK, rule)
	}
}

func deleteFWRule(svc fw.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeleteRule(r.Context(), r.PathValue("tid"), r.PathValue("id")); err != nil {
			writeRuleError(w, "delete fw rule", err, fw.ErrNotFound, fw.ErrInvalidRule)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func updateDLPRule(svc dlp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule dlp.Rule
		if !decode(w, r, &rule) {
			return
		}
		if err := svc.UpdateRule(r.Context(), r.PathValue("tid"), r.PathValue("id"), &rule); err != nil {
			writeRuleError(w, "update dlp rule", err, dlp.ErrNotFound, dlp.ErrInvalidRule)
			return
		}
		writeJSON(w, http.StatusOK, rule)
	}
}

func deleteDLPRule(svc dlp.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeleteRule(r.Context(), r.PathValue("tid"), r.PathValue("id")); err != nil {
			writeRuleError(w, "delete dlp rule", err, dlp.ErrNotFound, dlp.ErrInvalidRule)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func createSite(svc site.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var s site.Site
		if !decode(w, r, &s) {
			return
		}
		if err := svc.CreateSite(r.Context(), r.PathValue("tid"), &s); err != nil {
			// 错误码治理(Slice73):校验错→400、site_key 唯一冲突→409、DB/内部错→500 脱敏。
			writeValidationOr500(w, "createSite", err, site.ErrInvalidSite)
			return
		}
		writeJSON(w, http.StatusCreated, s)
	}
}

// listSites 列出该租户 SD-WAN 站点。handler 用 **path tid 做 RLS 上下文**
// (platform_admin TenantID 空,经 path-tid RLS 可读任意租户;对齐 listUsers/listDevices/listPolicies 模式)。
// authz 已守作用域:tenant_admin/auditor 限本租户、platform_admin 任意。
// 内部错脱敏(log + 通用文案,不泄漏 DB 细节)。
func listSites(svc site.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ss, err := svc.ListSites(r.Context(), r.PathValue("tid"))
		if err != nil {
			log.Printf("[admin] listSites tid=%s failed: %v", r.PathValue("tid"), err)
			http.Error(w, "list sites failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, ss)
	}
}

// createEnrollment 由租户管理员为某设备(connector/cpe)预置入网记录,返回一次性激活码。
func createEnrollment(svc enroll.Service) http.HandlerFunc {
	type reqBody struct {
		Kind     string `json:"kind"`     // "connector" | "cpe"
		Identity string `json:"identity"` // 签入证书 CommonName(connector app / cpe site_key)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body reqBody
		if !decode(w, r, &body) {
			return
		}
		code, err := svc.CreateEnrollment(r.Context(), r.PathValue("tid"), body.Kind, body.Identity)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"activation_code": code})
	}
}

// revokeDevice 由租户管理员撤销某设备入网(此后续期被拒,设备在 ≤证书有效期内自然掉线)。
func revokeDevice(svc enroll.Service) http.HandlerFunc {
	type reqBody struct {
		Identity string `json:"identity"` // 设备身份(connector app / cpe site_key)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body reqBody
		if !decode(w, r, &body) {
			return
		}
		if err := svc.RevokeDevice(r.Context(), r.PathValue("tid"), body.Identity); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "identity": body.Identity})
	}
}

// listDevices 列出该租户已登记设备(ZTP 可见性,M2)。handler 用 **path tid 做 RLS 上下文**
// (platform_admin TenantID 空,经 path-tid RLS 可读任意租户;对齐 listUsers/listPolicies/getRiskScore 模式)。
// authz 已守作用域:tenant_admin/auditor 限本租户、platform_admin 任意。
// 只返回非敏感列(enroll.Device 不含激活码);内部错脱敏(log + 通用文案,不泄漏 DB 细节)。
func listDevices(svc enroll.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ds, err := svc.ListDevices(r.Context(), r.PathValue("tid"))
		if err != nil {
			log.Printf("[admin] listDevices tid=%s failed: %v", r.PathValue("tid"), err)
			http.Error(w, "list devices failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, ds)
	}
}

// RegisterDevice 在 mTLS 设备端点 mux 上挂 ZTP 续期 + Agent 会话凭证刷新(Slice81)。须由
// RequireAndVerifyClientCert 的 server 承载:tenant/identity 取自已校验的对端证书(非请求体),设备无法借此
// 续成他租户/他身份。无 admin RBAC。按来源 IP 限流(纵深:即便持合法证书也限制频率)。
//
// refreshSvc nil(测试/未配置)→ 刷新端点返 503(端点存在,守路由形态,同 agentEnroll/oidcDeps);
// refreshLimiter rate 略高于 renewLimiter(cred 刷新远比证书续期频繁,§3.6.1 TTL 30min vs 24h)。
func RegisterDevice(mux *http.ServeMux, enrollSvc enroll.Service, renewLimiter *ratelimit.Limiter,
	refreshSvc *credrefresh.Service, refreshLimiter *ratelimit.Limiter) {
	mux.Handle("POST /api/v1/renew", ratelimit.Wrap(renewLimiter, ratelimit.ClientIP, renewDevice(enrollSvc)))
	mux.Handle("POST /api/v1/agent/session/refresh", ratelimit.Wrap(refreshLimiter, ratelimit.ClientIP, agentSessionRefresh(refreshSvc)))
}

// agentSessionRefresh 是真 OS 级 ZTNA Agent 的会话凭证静默刷新端点(Slice81,§3.6.1)。:8444 设备面,与
// /renew 同 mTLS 模型(出示当前租户绑定设备证书 role:device,tenant/device-id 取自已校验证书,非请求体)。
//
// 认证 = **设备 mTLS(transport)+ 出示当前签名 cred(app 层,经 svc.Refresh 验签)** 双重,免重新 IdP 登录。
// body 仅 {current_cred_token, posture}(**无 groups**:重签 groups 唯一来源是验签 cred,防 body 提权,§3.6.1)。
// 错误分流:cred 无效/主体不符→401,设备撤销/用户停用→403,参数错→400,内部错→500 脱敏(log 保细节)。
// refreshSvc nil → 503(端点存在但未配置)。
func agentSessionRefresh(svc *credrefresh.Service) http.HandlerFunc {
	type reqBody struct {
		CurrentCredToken string `json:"current_cred_token"`
		Posture          string `json:"posture"`
	}
	if svc == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Agent 会话刷新未配置", http.StatusServiceUnavailable)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client cert required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0] // 已由 server mTLS(本 CA)校验
		tenant, ok := devpki.TenantFromCert(cert)
		if !ok || cert.Subject.CommonName == "" {
			http.Error(w, "cert without tenant/identity", http.StatusForbidden)
			return
		}
		// 纵深:刷新端点专供 role:device 设备(Agent 的租户绑定证书);非 device 角色(如 role:pop)拒。
		if role, rok := devpki.RoleFromCert(cert); !rok || role != devpki.RoleDevice {
			http.Error(w, "device role required", http.StatusForbidden)
			return
		}
		// body 上限(同 /agent/enroll 的 R1):收 cred token + posture,均小,1 MiB 宽裕。
		r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
		var body reqBody
		if !decode(w, r, &body) {
			return
		}
		res, err := svc.Refresh(r.Context(), credrefresh.Request{
			TenantID:         tenant,                  // 取自证书 Org(权威)
			DeviceID:         cert.Subject.CommonName, // 取自证书 CN(权威)
			CurrentCredToken: body.CurrentCredToken,   // 待验签(提取 subject + groups)
			Posture:          body.Posture,            // 来自请求体(姿态非唯一门禁)
		})
		switch {
		case errors.Is(err, credrefresh.ErrBadRequest):
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		case errors.Is(err, credrefresh.ErrCredInvalid), errors.Is(err, credrefresh.ErrSubjectMismatch):
			// 凭证无效/主体不符:401(不区分细节,设备据此重走 IdP 入网)。
			http.Error(w, "credential invalid", http.StatusUnauthorized)
			return
		case errors.Is(err, credrefresh.ErrDeviceRevoked), errors.Is(err, credrefresh.ErrUserDisabled):
			http.Error(w, "device or user not active", http.StatusForbidden)
			return
		case err != nil:
			// 内部错(DB/吊销表/签发):脱敏(log 保细节,响应仅通用文案)。
			log.Printf("[device] agentSessionRefresh tenant=%s device=%s 内部错误: %v", tenant, cert.Subject.CommonName, err)
			http.Error(w, "session refresh failed", http.StatusInternalServerError)
			return
		}
		// 成功:仅返回新会话凭证 + jti + 有效期(不含任何敏感配置)。
		writeJSON(w, http.StatusOK, map[string]any{
			"session_token": res.SessionToken,
			"session_jti":   res.SessionJTI,
			"expires_in":    res.ExpiresIn,
		})
	}
}

func renewDevice(svc enroll.Service) http.HandlerFunc {
	type reqBody struct {
		CSRPEM string `json:"csr_pem"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client cert required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0] // 已由 server mTLS(本 CA)校验
		tenant, ok := devpki.TenantFromCert(cert)
		if !ok || cert.Subject.CommonName == "" {
			http.Error(w, "cert without tenant/identity", http.StatusForbidden)
			return
		}
		var body reqBody
		if !decode(w, r, &body) {
			return
		}
		certPEM, err := svc.Renew(r.Context(), tenant, cert.Subject.CommonName, []byte(body.CSRPEM))
		if err != nil {
			http.Error(w, "renew failed", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"cert_pem": string(certPEM)})
	}
}

// redeemEnrollment 由设备(凭激活码 + 本地生成的 CSR)兑换租户绑定证书。公开端点(尚无 mTLS/令牌)。
func redeemEnrollment(svc enroll.Service) http.HandlerFunc {
	type reqBody struct {
		ActivationCode string `json:"activation_code"`
		CSRPEM         string `json:"csr_pem"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body reqBody
		if !decode(w, r, &body) {
			return
		}
		certPEM, err := svc.Redeem(r.Context(), body.ActivationCode, []byte(body.CSRPEM))
		if err != nil {
			// 激活码无效/已兑换/CSR 非法 → 401(不泄露细节,设备据此重新申请)
			http.Error(w, "enrollment failed", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"cert_pem": string(certPEM)})
	}
}

// agentEnroll 是真 OS 级 ZTNA Agent 的 per-user 入网编排端点(Slice80,L2 §3.10.1)。公开端点
// (引导态无 mTLS/cred;authz 白名单 + CSRF skip + IP 限流);信任来自请求体 IdP code(控制面 adapter.Exchange
// 验签 id_token + 校 PKCE)+ code/state 一次性。daemon 本地生成 device key+CSR(私钥不离设备)、本地 PKCE
// verifier(随 code 交换)。**响应不含 client_secret/私钥**;session_token 是会话凭证,明示。
//
// agentEnrollSvc nil(测试/无 OIDC 配置)→ 503(端点存在但未配置,守路由清单,同 oidcDeps)。
// 错误分流:IdP 配置错→404、IdP 认证失败→401、用户停用→403、参数错→400、内部错→500 脱敏(log 保细节)。
func agentEnroll(svc *agentenroll.Service) http.HandlerFunc {
	type reqBody struct {
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		RedirectURI  string `json:"redirect_uri"`
		TenantID     string `json:"tenant_id"`
		IDPID        string `json:"idp_id"`
		DeviceID     string `json:"device_id"`
		CSRPem       string `json:"csr_pem"`
		Posture      string `json:"posture"`
	}
	if svc == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Agent 入网未配置(需 OIDC 依赖)", http.StatusServiceUnavailable)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// body 上限(Slice80 reviewer S1):/agent/enroll 是未认证公开端点(引导态)且收 CSR PEM,
		// 经 MaxBytesReader 收敛防异常超大 body 内存放大(同 /login 的 R1)。CSR PEM 仅数 KB,1 MiB 宽裕。
		r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
		var body reqBody
		if !decode(w, r, &body) {
			return
		}
		res, err := svc.Enroll(r.Context(), agentenroll.Request{
			Code:         body.Code,
			CodeVerifier: body.CodeVerifier,
			RedirectURI:  body.RedirectURI,
			TenantID:     body.TenantID,
			IDPID:        body.IDPID,
			DeviceID:     body.DeviceID,
			CSRPem:       []byte(body.CSRPem),
			Posture:      body.Posture,
		})
		switch {
		case errors.Is(err, agentenroll.ErrBadRequest):
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		case errors.Is(err, agentenroll.ErrIDPConfig):
			// IdP 配置不存在/禁用:统一 404(不区分以免泄露存在性)。
			http.Error(w, "IdP 配置不可用", http.StatusNotFound)
			return
		case errors.Is(err, agentenroll.ErrIDPAuth):
			http.Error(w, "IdP 认证失败", http.StatusUnauthorized)
			return
		case errors.Is(err, agentenroll.ErrUserDisabled):
			http.Error(w, "用户已停用", http.StatusForbidden)
			return
		case err != nil:
			// 内部错(DB/secret/签发):脱敏(log 保细节,响应仅通用文案,防泄露 DB/IdP URL 等)。
			log.Printf("[admin] agentEnroll tenant=%s idp=%s device=%s 内部错误: %v", body.TenantID, body.IDPID, body.DeviceID, err)
			http.Error(w, "Agent 入网失败", http.StatusInternalServerError)
			return
		}
		// 成功:响应不含 client_secret/私钥;cert_pem 为租户绑定设备证书,session_token 为会话凭证。
		writeJSON(w, http.StatusOK, map[string]any{
			"cert_pem":      string(res.CertPEM),
			"session_token": res.SessionToken,
			"session_jti":   res.SessionJTI,
			"expires_in":    res.ExpiresIn,
			"user_id":       res.UserID,
		})
	}
}

func listAudit(svc audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		es, err := svc.ListByTenant(r.Context(), r.PathValue("tid"), 100)
		if err != nil {
			writeInternalErr(w, "listAudit", err)
			return
		}
		writeJSON(w, http.StatusOK, es)
	}
}

// getRiskScore 返回某主体最新风险快照(risk RLS 持久化)。handler 用 **path tid 做 RLS 上下文**
// (platform_admin TenantID 空,经 path-tid RLS 可读任意租户;对齐 listPolicies/listUsers 模式)。
// authz 已守作用域:tenant_admin/auditor 限本租户、platform_admin 任意。
// riskSvc nil(测试/未装配)或快照层未配(WithStore 未注入)→ 503;无快照 → 404;内部错脱敏(log + 通用文案)。
func getRiskScore(riskSvc *risk.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if riskSvc == nil {
			http.Error(w, "risk 服务未配置", http.StatusServiceUnavailable)
			return
		}
		tid := r.PathValue("tid")
		subject := r.PathValue("subject")
		sc, err := riskSvc.GetScore(r.Context(), tid, subject)
		switch {
		case errors.Is(err, risk.ErrNoStore):
			http.Error(w, "风险快照持久化未启用", http.StatusServiceUnavailable)
		case errors.Is(err, risk.ErrNoScore):
			http.Error(w, "该主体无风险快照", http.StatusNotFound)
		case err != nil:
			log.Printf("[admin] getRiskScore tid=%s subject=%s failed: %v", tid, subject, err)
			http.Error(w, "查询风险快照失败", http.StatusInternalServerError)
		default:
			writeJSON(w, http.StatusOK, sc)
		}
	}
}

// listRiskScores 列本租户全部风险快照(N2;score 降序、subject 升序)。handler 用 **path tid 做 RLS 上下文**
// (platform_admin TenantID 空,经 path-tid RLS 可读任意租户;对齐 getRiskScore/listPolicies/listUsers 模式)。
// authz 已守作用域:tenant_admin/auditor 限本租户、platform_admin 任意。
// riskSvc nil(测试/未装配)或快照层未配(WithStore 未注入)→ 503;内部错脱敏(log + 通用文案)。
func listRiskScores(riskSvc *risk.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if riskSvc == nil {
			http.Error(w, "risk 服务未配置", http.StatusServiceUnavailable)
			return
		}
		tid := r.PathValue("tid")
		scs, err := riskSvc.ListScores(r.Context(), tid)
		switch {
		case errors.Is(err, risk.ErrNoStore):
			http.Error(w, "风险快照持久化未启用", http.StatusServiceUnavailable)
		case err != nil:
			log.Printf("[admin] listRiskScores tid=%s failed: %v", tid, err)
			http.Error(w, "查询风险快照失败", http.StatusInternalServerError)
		default:
			writeJSON(w, http.StatusOK, scs)
		}
	}
}

// listPlatformTenants 跨租户列出全租户摘要(平台运维控制台,PC-API-1)。authz 已限 platform_admin。
func listPlatformTenants(svc platform.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts, err := svc.ListTenants(r.Context())
		if err != nil {
			writeInternalErr(w, "listPlatformTenants", err)
			return
		}
		writeJSON(w, http.StatusOK, ts)
	}
}

func trustPubkey(svc identity.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		pub, ok := svc.IssuerPublicKey()
		if !ok {
			http.Error(w, "no issuer configured", http.StatusServiceUnavailable)
			return
		}
		// 算法无关:下发 alg + 公钥字节,验证侧据 alg 选 scheme(crypto-agility,R7 国密)
		writeJSON(w, http.StatusOK, map[string]string{
			"alg":    pub.Alg,
			"pubkey": base64.RawURLEncoding.EncodeToString(pub.Bytes),
		})
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// oidcLogin/oidcCallback 把可选 *oidc.HandlerDeps 转 http.Handler:
// nil → 503(端点存在但未配置,前端能识别需配 IdP);非 nil → 走真 OIDC handler。
func oidcLogin(deps *oidc.HandlerDeps) http.HandlerFunc {
	if deps == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "OIDC 未配置(SASE_OIDC_CALLBACK_URL 未设)", http.StatusServiceUnavailable)
		}
	}
	return oidc.LoginHandler(deps)
}

func oidcCallback(deps *oidc.HandlerDeps) http.HandlerFunc {
	if deps == nil {
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "OIDC 未配置(SASE_OIDC_CALLBACK_URL 未设)", http.StatusServiceUnavailable)
		}
	}
	return oidc.CallbackHandler(deps)
}

// maxLoginBodyBytes 限制 /login 请求体大小(R1,Slice74 W2 reviewer 跟进):
// /login 是**未认证可达的公开端点**,任何来源都可发请求体;不设上限则 json.Decoder 会把整个
// body 读进内存,攻击者可用一个超大 body 做未认证内存放大(资源耗尽)。
// 1 MiB 远大于真实 login 体(`{"token":"<几百字节签名令牌>"}`,通常 < 1 KiB),只截断异常超大输入,
// 不影响任何正常登录。对齐常见 Web 框架默认 body 上限量级(1 MiB),给排障留足余量。
const maxLoginBodyBytes = 1 << 20 // 1 MiB

// sessionLogin(W2)用一枚有效 admin 令牌换取 HttpOnly `sase_session` cookie:
// 把"平台控制台登录态"从前端 localStorage Bearer(自承 XSS 风险)迁到 HttpOnly cookie(JS 不可读)。
//
// 令牌来源:请求体 `{"token": "..."}`(MVP:既有 IssueAdminToken 签出的令牌 / bootstrap 令牌;
// IdP-平台-SSO 到位后由同一会话签发点接入,见报告诚实边界)。
//
// **校验严格性**:经 guard.VerifyAdminToken —— 与 authz 中间件 authenticate **完全相同**的验签 + 有效期 +
// 合法 admin 角色校验,不放宽。非法/过期/非 admin 角色令牌 → 401。
//
// **token 绝不回响应体**:只进 HttpOnly cookie;响应体仅含非敏感会话信息(role/tenant_id/exp),便前端展示。
//
// **R1 body 上限**:r.Body 经 http.MaxBytesReader 收敛到 maxLoginBodyBytes(只在本公开端点单独包,
// 不动全局 decode,避免波及其它已认证 handler 行为);超限 → 413(*http.MaxBytesError),其它 JSON 错 → 400。
func sessionLogin(guard *authz.Guard) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				// 超大 body:未认证内存放大防御。413 与 4xx 既有约定一致(客户端错,可回显类别)。
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if body.Token == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		p, err := guard.VerifyAdminToken(body.Token)
		if err != nil {
			// 不泄漏内部验签错误细节(脱敏):统一 401(签名错/过期/非 admin 角色)。
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		exp, err := guard.TokenExpiry(body.Token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// cookie Max-Age 与令牌剩余有效期对齐(钳到 ≥1s;过期令牌已被上面 Verify 拒)。
		maxAge := int(time.Until(exp).Seconds())
		if maxAge < 1 {
			maxAge = 1
		}
		http.SetCookie(w, &http.Cookie{
			Name:     authz.SessionCookieName,
			Value:    body.Token,
			Path:     "/",
			MaxAge:   maxAge,
			HttpOnly: true, // 防 JS 读(XSS 即便注入也拿不到 token,消除 localStorage Bearer 面)
			Secure:   r.TLS != nil || strings.HasPrefix(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https"),
			SameSite: http.SameSiteLaxMode, // 同 OIDC callback:跨站顶层导航回本站仍带 cookie
		})
		// 响应体只回非敏感会话信息(**不含 token**;token 只在 HttpOnly cookie)
		writeJSON(w, http.StatusOK, map[string]any{
			"subject":    p.Subject,
			"role":       p.Role,
			"tenant_id":  p.TenantID,
			"expires_at": exp,
		})
	}
}

// sessionLogout(W2)清除 `sase_session` cookie(Max-Age<0 立即失效)。幂等(无 cookie 也 200)。
// 注:令牌仍在其 TTL 内有效(无服务端会话存储,stateless);要立即吊销 platform_admin 令牌走
// platform_admins disable/delete(Slice55/56 主动撤销,per-request 复查)。
func sessionLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     authz.SessionCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1, // 立即删除
			HttpOnly: true,
			Secure:   r.TLS != nil || strings.HasPrefix(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https"),
			SameSite: http.SameSiteLaxMode,
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
	}
}

// PoP 注册 handlers(Slice38a + Slice39 双层审计接入)。
// popReg nil → 503(端点存在但平台写池未配置);守路由清单 + 便兼容测试。
//
// **双层审计**(Slice39,对应 LP-PC-platform-audit 锚):
//   - source=data  DB 触发器 platform_audit_tr 挂 pop_nodes 表,业务事务内原子写
//     (data.InPlatformTxRW 已注入 actor GUC → 触发器 platform_audit_row 读出主体)
//   - source=api   handler 显式 recordPlatformAudit(含失败 4xx/500,**覆盖 2xx-零变更盲区**)
//
// 注:成功路径触发器与 handler 各写一条(actor/action 一致;source 区分);
//
//	失败路径只有 handler 写(事务 ROLLBACK → 触发器无效果)。
func popNotConfigured(w http.ResponseWriter) {
	// 文案对客脱敏(S8):env 名仅 log,不回响应体——防 SaaS 公网暴露内部配置提示给攻击者。
	log.Printf("[platform] PoP 端点 503: SASE_DB_PLATFORM_RW_DSN 未设")
	http.Error(w, "PoP registry not configured", http.StatusServiceUnavailable)
}

// popActor 取请求 Principal 的 subject + role(用于审计归因),无则 anonymous/none。
func popActor(r *http.Request) (subject, role string) {
	if p, ok := authz.FromContext(r.Context()); ok {
		return p.Subject, p.Role
	}
	return "anonymous", "none"
}

// recordPlatformAudit:写 source=api 平台审计;nil svc → noop(测试简化路径);失败仅 log(best-effort)。
// ctx 用 context.WithoutCancel 取消独立(客户端断开不丢审计;对齐 audit middleware / OIDC handler)。
func recordPlatformAudit(ctx context.Context, svc platformaudit.Service, subject, role, action string, result int, detail string) {
	if svc == nil {
		return
	}
	//nolint:contextcheck // 审计写独立于请求 ctx(同 audit middleware)
	if err := svc.Record(context.WithoutCancel(ctx), platformaudit.Entry{
		ActorSubject: subject, ActorRole: role, Action: action, Result: result,
		Detail: sanitizeDetail(detail), Source: platformaudit.SourceAPI,
	}); err != nil {
		log.Printf("[platform] audit Record failed action=%s actor=%s: %v", action, subject, err)
	}
}

func createPopNode(popReg platform.PopRegistry, auditSvc platformaudit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if popReg == nil {
			popNotConfigured(w)
			return
		}
		subject, role := popActor(r)
		const action = "POST /api/v1/platform/pop-nodes"
		var body platform.CreatePopRequest
		if !decode(w, r, &body) {
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusBadRequest, "bad json")
			return
		}
		p, err := popReg.Create(r.Context(), body)
		if err != nil {
			var code int
			switch {
			case errors.Is(err, platform.ErrInvalidPopPatch):
				code = http.StatusBadRequest
				http.Error(w, err.Error(), code)
			case errors.Is(err, platform.ErrPopAlreadyExists):
				code = http.StatusConflict
				http.Error(w, err.Error(), code)
			default:
				code = http.StatusInternalServerError
				log.Printf("[platform] createPopNode actor=%s name=%q failed: %v", subject, body.Name, err)
				http.Error(w, "create pop failed", code)
			}
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, code, "name="+body.Name)
			return
		}
		// 成功:写 source=api(触发器已写 source=data,见包注释)
		recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusCreated, "name="+p.Name+" region="+p.Region+" id="+p.ID)
		writeJSON(w, http.StatusCreated, p)
	}
}

func listPopNodes(popReg platform.PopRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if popReg == nil {
			popNotConfigured(w)
			return
		}
		ps, err := popReg.List(r.Context())
		if err != nil {
			subject, _ := popActor(r)
			log.Printf("[platform] listPopNodes actor=%s failed: %v", subject, err)
			http.Error(w, "list pop failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, ps)
	}
}

func getPopNode(popReg platform.PopRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if popReg == nil {
			popNotConfigured(w)
			return
		}
		pid := r.PathValue("pid")
		p, err := popReg.Get(r.Context(), pid)
		if err != nil {
			if errors.Is(err, platform.ErrPopNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			subject, _ := popActor(r)
			log.Printf("[platform] getPopNode actor=%s id=%s failed: %v", subject, pid, err)
			http.Error(w, "get pop failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, p)
	}
}

func updatePopNode(popReg platform.PopRegistry, auditSvc platformaudit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if popReg == nil {
			popNotConfigured(w)
			return
		}
		subject, role := popActor(r)
		pid := r.PathValue("pid")
		action := "PATCH /api/v1/platform/pop-nodes/" + pid
		var patch platform.PopPatch
		// PATCH:容忍空 body(EOF);所有 nil 字段交 Update 走 ErrInvalidPopPatch 统一拒(S4 与 decommissionTenant 同口径)
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusBadRequest, "bad json")
			return
		}
		p, err := popReg.Update(r.Context(), pid, patch)
		if err != nil {
			var code int
			switch {
			case errors.Is(err, platform.ErrPopNotFound):
				code = http.StatusNotFound
				http.Error(w, err.Error(), code)
			case errors.Is(err, platform.ErrInvalidPopPatch):
				code = http.StatusBadRequest
				http.Error(w, err.Error(), code)
			default:
				code = http.StatusInternalServerError
				log.Printf("[platform] updatePopNode actor=%s id=%s failed: %v", subject, pid, err)
				http.Error(w, "update pop failed", code)
			}
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, code, "id="+pid)
			return
		}
		recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusOK, "id="+p.ID+" status="+p.Status)
		writeJSON(w, http.StatusOK, p)
	}
}

// listPlatformAudit:Slice39,平台级审计读端点(authz 默认分支已限 platform_admin)。
// nil svc → 503(端点存在但平台审计未配置);limit query 上限 1000 防一次拉爆。
func listPlatformAudit(svc platformaudit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			http.Error(w, "platform audit not configured", http.StatusServiceUnavailable)
			return
		}
		limit := 100
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		if limit > 1000 {
			limit = 1000
		}
		es, err := svc.List(r.Context(), limit)
		if err != nil {
			subject, _ := popActor(r)
			log.Printf("[platform] listPlatformAudit actor=%s failed: %v", subject, err)
			http.Error(w, "list platform audit failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, es)
	}
}

// 平台 RBAC handlers(Slice38c;authz 在 /platform/* 默认分支已限 platform_admin)。
// platformRBAC nil → 503;双层审计(触发器自动 + handler 显式)同 Slice39 PoP 模式。
//
// **删除自己防锁死**:DELETE 不允许 subject == 当前调用方 Principal.Subject(否则可能锁死最后一枚 admin)。
// 注:"最后一枚 active admin 强制保留"由 service 层 guardLastActive 事务内强制(Slice55),删/禁最后一枚 active → ErrLastActiveAdmin(400)。

func platformRBACNotConfigured(w http.ResponseWriter) {
	log.Printf("[platform] RBAC 端点 503: SASE_DB_PLATFORM_RW_DSN 未设")
	http.Error(w, "platform RBAC not configured", http.StatusServiceUnavailable)
}

func createPlatformAdmin(svc platformrbac.Service, auditSvc platformaudit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			platformRBACNotConfigured(w)
			return
		}
		subject, role := popActor(r)
		const action = "POST /api/v1/platform/admins"
		var body platformrbac.CreateRequest
		if !decode(w, r, &body) {
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusBadRequest, "bad json")
			return
		}
		body.CreatedBy = subject // 创建者从 Principal 取,不信任客户端
		a, err := svc.Create(r.Context(), body)
		if err != nil {
			var code int
			switch {
			case errors.Is(err, platformrbac.ErrInvalidAdminPatch):
				code = http.StatusBadRequest
				http.Error(w, err.Error(), code)
			case errors.Is(err, platformrbac.ErrAdminAlreadyExists):
				code = http.StatusConflict
				http.Error(w, err.Error(), code)
			default:
				code = http.StatusInternalServerError
				log.Printf("[platform] createPlatformAdmin actor=%s subject=%q failed: %v", subject, body.Subject, err)
				http.Error(w, "create platform admin failed", code)
			}
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, code, "subject="+body.Subject)
			return
		}
		recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusCreated, "subject="+a.Subject+" id="+a.ID)
		writeJSON(w, http.StatusCreated, a)
	}
}

func listPlatformAdmins(svc platformrbac.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			platformRBACNotConfigured(w)
			return
		}
		as, err := svc.List(r.Context())
		if err != nil {
			subject, _ := popActor(r)
			log.Printf("[platform] listPlatformAdmins actor=%s failed: %v", subject, err)
			http.Error(w, "list platform admins failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, as)
	}
}

func getPlatformAdmin(svc platformrbac.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			platformRBACNotConfigured(w)
			return
		}
		aid := r.PathValue("aid")
		a, err := svc.Get(r.Context(), aid)
		if err != nil {
			if errors.Is(err, platformrbac.ErrAdminNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			subject, _ := popActor(r)
			log.Printf("[platform] getPlatformAdmin actor=%s id=%s failed: %v", subject, aid, err)
			http.Error(w, "get platform admin failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, a)
	}
}

func updatePlatformAdmin(svc platformrbac.Service, auditSvc platformaudit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			platformRBACNotConfigured(w)
			return
		}
		subject, role := popActor(r)
		aid := r.PathValue("aid")
		action := "PATCH /api/v1/platform/admins/" + aid
		var patch platformrbac.Patch
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusBadRequest, "bad json")
			return
		}
		// **B5 防自助锁死**:patch.Status=disabled 时若目标=自己 → 400(用其他 admin 操作或 last-admin disable 等更复杂场景留运维)。
		// 自禁防"误操作自己";"最后一枚 active 被他人/bootstrap disable"由 service guardLastActive 事务内兜底(Slice55)。
		if patch.Status != nil && *patch.Status == "disabled" {
			if p, ok := authz.FromContext(r.Context()); ok {
				if target, gerr := svc.Get(r.Context(), aid); gerr == nil && target.Subject == p.Subject {
					http.Error(w, "cannot disable self (ask another platform_admin to do it)", http.StatusBadRequest)
					recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusBadRequest, "id="+aid+" self-disable-rejected")
					return
				}
			}
		}
		a, err := svc.Update(r.Context(), aid, patch)
		if err != nil {
			var code int
			switch {
			case errors.Is(err, platformrbac.ErrAdminNotFound):
				code = http.StatusNotFound
				http.Error(w, err.Error(), code)
			case errors.Is(err, platformrbac.ErrInvalidAdminPatch):
				code = http.StatusBadRequest
				http.Error(w, err.Error(), code)
			case errors.Is(err, platformrbac.ErrLastActiveAdmin):
				code = http.StatusBadRequest
				http.Error(w, err.Error(), code)
			default:
				code = http.StatusInternalServerError
				log.Printf("[platform] updatePlatformAdmin actor=%s id=%s failed: %v", subject, aid, err)
				http.Error(w, "update platform admin failed", code)
			}
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, code, "id="+aid)
			return
		}
		recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusOK, "id="+a.ID+" status="+a.Status)
		writeJSON(w, http.StatusOK, a)
	}
}

func deletePlatformAdmin(svc platformrbac.Service, auditSvc platformaudit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			platformRBACNotConfigured(w)
			return
		}
		subject, role := popActor(r)
		aid := r.PathValue("aid")
		action := "DELETE /api/v1/platform/admins/" + aid
		// **删除自己防锁死**:取目标行的 subject 与调用方 Principal 比较
		target, err := svc.Get(r.Context(), aid)
		if err != nil {
			if errors.Is(err, platformrbac.ErrAdminNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusNotFound, "id="+aid)
				return
			}
			log.Printf("[platform] deletePlatformAdmin actor=%s id=%s pre-get failed: %v", subject, aid, err)
			http.Error(w, "delete platform admin failed", http.StatusInternalServerError)
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusInternalServerError, "id="+aid)
			return
		}
		// **B2**:取 Principal 直接(authz 已守 /platform/* 限 platform_admin → Principal 必存在;若缺,500 而非靠 "anonymous" 字面值兜底)
		p, ok := authz.FromContext(r.Context())
		if !ok {
			log.Printf("[platform] deletePlatformAdmin: Principal 缺失(authz 配置异常?) id=%s", aid)
			http.Error(w, "delete platform admin failed", http.StatusInternalServerError)
			return
		}
		if target.Subject == p.Subject {
			http.Error(w, "cannot delete self (use PATCH to disable instead)", http.StatusBadRequest)
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusBadRequest, "id="+aid+" self-delete-rejected")
			return
		}
		if err := svc.Delete(r.Context(), aid); err != nil {
			var code int
			switch {
			case errors.Is(err, platformrbac.ErrAdminNotFound):
				code = http.StatusNotFound
				http.Error(w, err.Error(), code)
			case errors.Is(err, platformrbac.ErrLastActiveAdmin):
				code = http.StatusBadRequest
				http.Error(w, err.Error(), code)
			default:
				code = http.StatusInternalServerError
				log.Printf("[platform] deletePlatformAdmin actor=%s id=%s failed: %v", subject, aid, err)
				http.Error(w, "delete platform admin failed", code)
			}
			recordPlatformAudit(r.Context(), auditSvc, subject, role, action, code, "id="+aid)
			return
		}
		recordPlatformAudit(r.Context(), auditSvc, subject, role, action, http.StatusOK, "id="+aid+" subject="+target.Subject)
		writeJSON(w, http.StatusOK, map[string]string{"id": aid})
	}
}
