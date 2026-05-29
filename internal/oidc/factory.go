package oidc

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/ikuai8/sase/internal/idp"
)

// IdP kind 取值域(与 idp.Config.Kind 同源;OpenAPI enum 应同步)。
// L1 3.3 IdPConfig.type 与 sase-l2-cp-identity-idp.md §3.1 表对齐。
const (
	KindOIDC     = "oidc"     // 标准 OIDC(任意 issuer + discovery)
	KindWeCom    = "wecom"    // 企业微信(OAuth2 + 自家 API,非标准 OIDC,Slice37b-1)
	KindDingTalk = "dingtalk" // 钉钉(OAuth2 + 自家 API,Slice37b-2 待)
	KindFeishu   = "feishu"   // 飞书/Lark(OAuth2 + 自家 API,Slice37b-2 待)
)

// ErrUnsupportedKind 表示 cfg.Kind 不在已实现的 adapter 列表内。
var ErrUnsupportedKind = errors.New("oidc: 不支持的 IdP kind")

// InvalidateForIDP 按 IdP kind + clientID 淘汰对应 adapter 的 access_token 缓存(Slice37c)。
// 调用时机:idp.Service.Delete 提交后 hook 调用(防 stale token 滞留进程);未来 ClientSecret 轮换也应调。
// kind=oidc/dingtalk 无 corp/app token 缓存(generic 走 IdP discovery 即时;dingtalk per-user 不缓存),noop;
// kind=wecom/feishu 走各自 invalidate* 按 client_id 后缀清。
func InvalidateForIDP(kind, clientID string) {
	switch kind {
	case KindWeCom:
		invalidateWeComCache(clientID)
	case KindFeishu:
		invalidateFeishuCache(clientID)
		// KindOIDC / KindDingTalk:无 adapter-level cache,noop
	}
}

// DispatchFactory 是生产默认 factory:按 cfg.Kind 派发到对应 adapter 实现。
// 后续刀加新厂商(钉钉/飞书)= 在此 switch 加 case + 实现新 adapter,无需改 handler。
//
// 安全模型差异(诚实标注):
//   - oidc(generic):PKCE S256 强制 + id_token 校验(JWKS) → 三道核心防线齐
//   - wecom/dingtalk/feishu:三家**均不支持 PKCE**、**无 id_token JWT** → 防线退化为「服务端 state TakeOnce」
//   - 后端调 IdP API 受 IdP 认证(client_secret)+ 短 TTL 会话凭证;adapter 内注释明示。
func DispatchFactory(ctx context.Context, cfg *idp.Config, clientSecret []byte) (Adapter, error) {
	if cfg == nil {
		return nil, errors.New("oidc.DispatchFactory: cfg=nil")
	}
	// Slice37c:从 cfg.Extra 取 *_auth_host / *_oauth_host(私有化部署/灰度域名)。
	// **客户端只能控制运营层 Extra 字段**(经 IdP CRUD 写入);adapter 不读未配项即走生产默认。
	// 字段命名按厂商约定:wecom_auth_host / dingtalk_oauth_host / feishu_auth_host。
	authHostWecom := extraString(cfg.Extra, "wecom_auth_host")
	oauthHostDingtalk := extraString(cfg.Extra, "dingtalk_oauth_host")
	authHostFeishu := extraString(cfg.Extra, "feishu_auth_host")
	switch cfg.Kind {
	case KindOIDC, "":
		// 兼容空 Kind 视为 OIDC(老配置数据 / OpenAPI 默认行为)
		return NewGeneric(ctx, GenericConfig{
			IssuerURL: cfg.Endpoint, ClientID: cfg.ClientID, ClientSecret: string(clientSecret),
		})
	case KindWeCom:
		return NewWeCom(ctx, WeComConfig{
			CorpID:     cfg.ClientID,
			CorpSecret: string(clientSecret),
			APIBase:    cfg.Endpoint, // 空 → 走生产默认 https://qyapi.weixin.qq.com
			AuthHost:   authHostWecom,
		})
	case KindDingTalk:
		return NewDingTalk(ctx, DingTalkConfig{
			ClientID:     cfg.ClientID,
			ClientSecret: string(clientSecret),
			APIBase:      cfg.Endpoint, // 空 → 走生产默认 https://api.dingtalk.com
			OAuthHost:    oauthHostDingtalk,
		})
	case KindFeishu:
		return NewFeishu(ctx, FeishuConfig{
			AppID:     cfg.ClientID,
			AppSecret: string(clientSecret),
			APIBase:   cfg.Endpoint, // 空 → 走生产默认 https://open.feishu.cn
			AuthHost:  authHostFeishu,
		})
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKind, cfg.Kind)
	}
}

// extraString 从 cfg.Extra 取一个字符串字段;不存在/非 string 返空(派发给 adapter 走生产默认)。
// B8 log 排障:非 string 类型(运营误配 int/object 等)log 一条提示,**不阻塞登录**(走默认行为)。
func extraString(extra map[string]any, key string) string {
	if extra == nil {
		return ""
	}
	v, ok := extra[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		log.Printf("[oidc] cfg.Extra[%q] 非 string(%T),退默认", key, v)
		return ""
	}
	return s
}
