// Package authz 是管理面(Admin API)鉴权:Bearer 令牌认证 + 角色/租户作用域授权(RBAC)。
//
// 上承控制面 L2(横切 authz)、L1 RBAC。管理面为 server-TLS(无客户端证书,Slice 8),故身份用
// cred 签名的 admin 令牌(claims.Role)。授权按 方法 + 路径 判定,叠加在数据层 RLS 之上(纵深)。
//
// 三角色:platform_admin(跨租户)/ tenant_admin(本租户读写)/ auditor(本租户只读)。
// 租户作用域:tenant_admin/auditor 的令牌 tenant 必须等于路径 {tid};platform_admin 不限。
package authz

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ikuai8/sase/internal/cred"
)

// 角色。
const (
	RolePlatformAdmin = "platform_admin"
	RoleTenantAdmin   = "tenant_admin"
	RoleAuditor       = "auditor"
)

// Principal 是已认证的调用方。
type Principal struct {
	Subject  string
	Role     string
	TenantID string // tenant_admin/auditor 的作用域租户;platform_admin 留空
}

type ctxKey struct{}

// FromContext 取已认证调用方(中间件注入)。
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// AdminActiveChecker 判定 platform_admin subject 是否仍有效(在 platform_admins 表且 active)。
// 用于 admin 令牌**主动撤销**(Slice55):管理员被 disable/delete 后,其已签出令牌每请求复查 → 即时失效。
// 返回 (false, nil) → 撤销;(_, err) → 无法判定(fail-closed,拒)。bootstrap 应急通道由实现侧豁免(不在表)。
// **仅对 platform_admin 令牌调用**(tenant_admin/auditor 不在该表,Middleware 按角色门控不调用)。
type AdminActiveChecker func(ctx context.Context, subject string) (bool, error)

// Guard 用签发公钥校验 admin 令牌并做授权。
type Guard struct {
	verifier    *cred.Verifier
	now         func() time.Time
	adminActive AdminActiveChecker // 可选;nil = 不启用主动撤销(向后兼容)
}

// NewGuard 构造。
func NewGuard(verifier *cred.Verifier) *Guard {
	return &Guard{verifier: verifier, now: time.Now}
}

// WithAdminActiveChecker 注入 platform_admin 主动撤销校验(per-request 复查 subject 仍 active)。
// nil 则不启用。返回 g 便于链式。
func (g *Guard) WithAdminActiveChecker(c AdminActiveChecker) *Guard {
	g.adminActive = c
	return g
}

// VerifyAdminToken 校验一枚 admin 令牌串(验签 + 有效期 + 角色为合法 admin 角色),返回 Principal。
// 供会话登录端点(POST /api/v1/login)复用——与 Middleware authenticate **完全相同**的校验,不放宽。
// 注:**不**做 platform_admin 主动撤销(AdminActiveChecker)复查;那是 per-request 中间件职责,
// 登录时签出的 cookie 在后续每个请求仍会经中间件复查 active(故撤销对 cookie 同样即时生效)。
func (g *Guard) VerifyAdminToken(token string) (Principal, error) {
	claims, err := g.verifier.Verify(token, g.now())
	if err != nil {
		return Principal{}, err
	}
	if !adminRoles[claims.Role] {
		return Principal{}, errors.New("非管理面令牌(无 admin 角色)")
	}
	return Principal{Subject: claims.Subject, Role: claims.Role, TenantID: claims.TenantID}, nil
}

// TokenExpiry 返回令牌的过期时间(供登录端点设 cookie Max-Age 与回响非敏感会话信息;不含 token 本身)。
// 仅在 token 已验签通过后调用有意义;此处只解出 exp,不重复验签。
func (g *Guard) TokenExpiry(token string) (time.Time, error) {
	claims, err := g.verifier.Verify(token, g.now())
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(claims.ExpireAt, 0), nil
}

var adminRoles = map[string]bool{RolePlatformAdmin: true, RoleTenantAdmin: true, RoleAuditor: true}

// ValidAdminRole 判定是否合法管理面角色。
func ValidAdminRole(role string) bool { return adminRoles[role] }

// ScopeValid 校验角色与租户作用域的搭配:platform_admin 必须不带租户(跨租户),其余必须带租户。
func ScopeValid(role, tenantID string) bool {
	if role == RolePlatformAdmin {
		return tenantID == ""
	}
	return tenantID != ""
}

// Middleware 包裹 Admin API:公开端点放行,其余先认证再授权,注入 Principal。
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 公开:取签发公钥(pop-agent 引导用,公钥非密)
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/trust/pubkey" {
			next.ServeHTTP(w, r)
			return
		}
		// 公开:ZTP 设备入网兑换(设备凭激活码认证,尚无 mTLS 证书 / 管理面令牌)
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/enroll" {
			next.ServeHTTP(w, r)
			return
		}
		// 公开:真 OS 级 ZTNA Agent per-user 入网(Slice80)。引导态设备无 mTLS 证书/无 SASE 凭证;
		// 信任来自请求体 IdP code(控制面 Exchange 验 id_token 签名 + PKCE)。同 /enroll 形态免中间件鉴权。
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/agent/enroll" {
			next.ServeHTTP(w, r)
			return
		}
		// 公开:IdP 登录入口与回调(用户尚未持有 SASE 凭证,经 IdP 认证后换发,Slice37a)
		if r.Method == http.MethodGet && (r.URL.Path == "/api/v1/idp/login" || r.URL.Path == "/api/v1/idp/callback") {
			next.ServeHTTP(w, r)
			return
		}
		// 公开:会话登录/登出(W2)。login 用请求体里的令牌自证身份(首次无 cookie/Bearer),
		// 故必须免中间件鉴权;handler 内部用 VerifyAdminToken 严格验签,不持有效令牌则 401。
		// logout 只清 cookie(无副作用、幂等),也放行。
		if r.Method == http.MethodPost && (r.URL.Path == "/api/v1/login" || r.URL.Path == "/api/v1/logout") {
			next.ServeHTTP(w, r)
			return
		}
		p, err := g.authenticate(r)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		// 主动撤销(Slice55):platform_admin 令牌每请求复查 subject 仍 active(disable/delete 即时失效)。
		// bootstrap 应急通道由 checker 实现侧豁免(不在表);DB 错 → fail-closed(503,不放行)。
		if p.Role == RolePlatformAdmin && g.adminActive != nil {
			active, cerr := g.adminActive(r.Context(), p.Subject)
			if cerr != nil {
				http.Error(w, "service unavailable: 无法校验管理员状态", http.StatusServiceUnavailable)
				return
			}
			if !active {
				http.Error(w, "unauthorized: 平台管理员已停用或删除,令牌失效", http.StatusUnauthorized)
				return
			}
		}
		if !authorize(p, r.Method, r.URL.Path) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// SessionCookieName 是会话令牌 cookie 名(W2:cookie→authz 桥接)。
// 由 POST /api/v1/login 与 OIDC callback(Slice37c)种;HttpOnly,JS 不可读(消除 localStorage Bearer 的 XSS 面)。
const SessionCookieName = "sase_session"

// authenticate 校验 admin 令牌 → Principal。令牌来源二选一:
//  1. Authorization: Bearer <token>(优先);
//  2. 无 Bearer header 时回退 `sase_session` cookie(W2 桥接,平台控制台用 HttpOnly 会话 cookie)。
//
// **两种来源用完全相同的验签/角色校验**(不放宽任何检查):令牌经 cred.Verifier 验签 + 有效期,
// 且 claims.Role 须为合法 admin 角色。ZTNA 会话令牌(Role 空)在此被拒。
func (g *Guard) authenticate(r *http.Request) (Principal, error) {
	tok, err := extractToken(r)
	if err != nil {
		return Principal{}, err
	}
	claims, err := g.verifier.Verify(tok, g.now())
	if err != nil {
		return Principal{}, err
	}
	if !adminRoles[claims.Role] {
		return Principal{}, errors.New("非管理面令牌(无 admin 角色)")
	}
	return Principal{Subject: claims.Subject, Role: claims.Role, TenantID: claims.TenantID}, nil
}

// extractToken 取令牌串:Bearer header 优先,否则回退 sase_session cookie;两者皆无 → 错误。
// 仅取原始串,验签/角色/active 校验由 authenticate 与 Middleware 统一处理(cookie 与 Bearer 同路径)。
func extractToken(r *http.Request) (string, error) {
	const pfx = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, pfx) {
		return strings.TrimPrefix(h, pfx), nil
	}
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value, nil
	}
	return "", errors.New("缺 Bearer 令牌或会话 cookie")
}

// authorize 按 方法 + 路径 判定(纯函数,易审计/测)。
func authorize(p Principal, method, path string) bool {
	rest := strings.TrimPrefix(path, "/api/v1/")
	write := method != http.MethodGet

	switch {
	case rest == "tenants": // 建租户 = 平台级操作
		return p.Role == RolePlatformAdmin
	case strings.HasPrefix(rest, "tenants/"): // 租户作用域 /tenants/{tid} 或 /tenants/{tid}/...
		parts := strings.SplitN(rest[len("tenants/"):], "/", 2)
		tid := parts[0]
		if tid == "" {
			return false
		}
		// 租户**本身**的写(PATCH/PUT/DELETE on /tenants/{tid},无子路径)= 生命周期(停用/恢复/注销/改档),
		// 属平台级运维,只 platform_admin——**租户管理员不能改自己租户的状态/档**(防自助解封/升档)。
		// 当前仅 PATCH 端点;PUT/DELETE 预留同一闸(SaaS 注销倾向软删=offboarding 状态,非硬 DELETE,见平台控制台 L2 LP-PC5)。
		if len(parts) == 1 && write {
			return p.Role == RolePlatformAdmin
		}
		if p.Role == RoleAuditor && write {
			return false // 只读
		}
		if p.Role == RolePlatformAdmin {
			return true // 跨租户
		}
		return p.TenantID == tid // tenant_admin/auditor 限本租户(含 GET /tenants/{tid} 看自身)
	default: // 其它管理端点:平台级(安全默认)
		return p.Role == RolePlatformAdmin
	}
}
