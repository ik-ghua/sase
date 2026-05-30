// Package oidc 是 IdP OIDC 登录适配:把用户从外部 IdP(Keycloak/dex/任意标准 OIDC IdP)
// 认证后的身份换成 SASE 自签短 TTL 会话凭证(L1 3.4 令牌交换 / 3.8 短 TTL)。
//
// 角色定位:
//   - Adapter 接口:抽象「跳 IdP authorize URL → 收回调 code → 换 token+userinfo」,
//     genericAdapter 是标准 OIDC 实现(coreos/go-oidc + oauth2);
//     厂商方言(企微/钉钉/飞书,各家 OAuth2 端点与用户信息字段不全标准 OIDC)= 后续刀。
//   - StateStore:登录开始时记 {tenant_id, idp_id, code_verifier, redirect_uri},
//     回调时按 state ID 一次性取(防 CSRF + 跨 IdP 注入)。
//   - handler:经 idp.Service.GetClientSecret(Slice36 解密)拿明文 client_secret 构造 adapter,
//     回调成功后经 identity.EnsureUserByExternalID 找/建 User + IssueCredential 换会话凭证。
//
// 安全模型:
//   - state 是服务端持有的 capability(随机 32B):客户端只回 state ID,服务端按 ID 找回上下文。
//     **不**把 tenant_id/idp_id 等放进 state 让客户端回传(避免被改);
//   - PKCE S256 强制(防 code 截获,即便走公共网络回调);
//   - 单一 callback URL `/api/v1/idp/callback`(对所有租户/IdP 复用一条,IdP 注册简单),
//     租户/IdP 信息走服务端 state(不走 query)→ 攻击者无法伪造跨租户 IdP 切换。
//   - IdP `client_secret` 仅在构造 adapter 时短窗内存(secret 模块解密返回 []byte),
//     不写日志、不入 state。
package oidc

import (
	"context"
	"errors"
)

// 错误 sentinel。
var (
	// ErrInvalidState 状态 ID 不存在或被冒充。
	ErrInvalidState = errors.New("oidc: state 不存在或非法")
	// ErrStateExpired 状态 ID 已过期(TTL 内未回调,可能用户放弃登录或攻击者重放)。
	ErrStateExpired = errors.New("oidc: state 已过期")
	// ErrIDPDisabled IdP 配置存在但状态非 active。
	ErrIDPDisabled = errors.New("oidc: IdP 已禁用")
)

// UserInfo 是 IdP 认证后取得的标准用户信息(Adapter.Exchange 返回)。
type UserInfo struct {
	Subject string   // IdP 侧主键(OIDC `sub`,永久,跨登录不变)。EnsureUserByExternalID 用此 → SASE 用户 ID
	Email   string   // 可选(取决于 IdP 是否暴露 email scope)
	Name    string   // 可选(OIDC `name` 或 `preferred_username`)
	Groups  []string // 可选(取决于 IdP groups claim)
}

// Adapter 抽象单个 IdP 的 OIDC 登录交互。每次登录都构造一个新实例(adapter 绑特定 IdPConfig)。
// state 与 code_verifier 由调用方生成持有(state↔StateStore、verifier↔StateStore.Record),
// adapter 仅负责把它们正确组进 IdP URL 与 token 交换请求(无状态)。
type Adapter interface {
	// AuthURL 用调用方提供的 state + code_verifier 构造 IdP 授权 URL(PKCE S256 method)。
	AuthURL(ctx context.Context, state, codeVerifier, redirectURI string) (string, error)
	// Exchange 用 IdP 回的 code + 之前存的 code_verifier 换 IdP token,经 userinfo 拿用户身份。
	Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (UserInfo, error)
}

// GenerateCodeVerifier 生成 PKCE code_verifier(handler 用)。导出供测试与 handler 调用。
func GenerateCodeVerifier() (string, error) { return generateCodeVerifier() }

// CodeChallengeS256 由 code_verifier 算 PKCE code_challenge(method=S256)。
// 导出供 Agent daemon(agentd.idpEnroll)本地构造 IdP authorize URL(daemon 持 verifier、只暴露 challenge)。
func CodeChallengeS256(verifier string) string { return codeChallengeS256(verifier) }
