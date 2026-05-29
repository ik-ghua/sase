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

// Guard 用签发公钥校验 admin 令牌并做授权。
type Guard struct {
	verifier *cred.Verifier
	now      func() time.Time
}

// NewGuard 构造。
func NewGuard(verifier *cred.Verifier) *Guard {
	return &Guard{verifier: verifier, now: time.Now}
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
		// 公开:IdP 登录入口与回调(用户尚未持有 SASE 凭证,经 IdP 认证后换发,Slice37a)
		if r.Method == http.MethodGet && (r.URL.Path == "/api/v1/idp/login" || r.URL.Path == "/api/v1/idp/callback") {
			next.ServeHTTP(w, r)
			return
		}
		p, err := g.authenticate(r)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if !authorize(p, r.Method, r.URL.Path) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// authenticate 校验 Bearer admin 令牌 → Principal。ZTNA 会话令牌(Role 空)在此被拒。
func (g *Guard) authenticate(r *http.Request) (Principal, error) {
	const pfx = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, pfx) {
		return Principal{}, errors.New("缺 Bearer 令牌")
	}
	claims, err := g.verifier.Verify(strings.TrimPrefix(h, pfx), g.now())
	if err != nil {
		return Principal{}, err
	}
	if !adminRoles[claims.Role] {
		return Principal{}, errors.New("非管理面令牌(无 admin 角色)")
	}
	return Principal{Subject: claims.Subject, Role: claims.Role, TenantID: claims.TenantID}, nil
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
