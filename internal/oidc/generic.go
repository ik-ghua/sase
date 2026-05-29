package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// GenericConfig 是 generic OIDC adapter 的入参。
type GenericConfig struct {
	IssuerURL    string   // OIDC issuer(用于 discovery `/.well-known/openid-configuration`)
	ClientID     string   // IdP 端注册的 client_id
	ClientSecret string   // IdP 端注册的 client_secret(由 idp.Service.GetClientSecret 解密拿到,短窗内存)
	Scopes       []string // 额外 scope(总会附加 openid;默认带 profile/email)
}

// genericAdapter 是标准 OIDC 实现:Provider(discovery)+ oauth2 Config(state/PKCE)+ IDTokenVerifier。
// 每次登录构造一个新实例(避免长持 client_secret 在内存)。
type genericAdapter struct {
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewGeneric 构造 generic OIDC adapter。issuer discovery 经一次 HTTP 调用(IdP /.well-known);
// 失败立即返错(配置/网络错由调用方决定是否兜底)。
func NewGeneric(ctx context.Context, cfg GenericConfig) (Adapter, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("oidc.NewGeneric: issuer_url/client_id/client_secret 必填")
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc.NewGeneric: discovery: %w", err)
	}
	scopes := append([]string{oidc.ScopeOpenID, "profile", "email"}, cfg.Scopes...)
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}
	idTokVerifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	return &genericAdapter{provider: provider, oauth: oauthCfg, verifier: idTokVerifier}, nil
}

// AuthURL 构造 IdP authorize URL,启用 PKCE S256(防 code 截获)。
func (a *genericAdapter) AuthURL(_ context.Context, state, codeVerifier, redirectURI string) (string, error) {
	if state == "" || codeVerifier == "" || redirectURI == "" {
		return "", errors.New("oidc.AuthURL: state/code_verifier/redirect_uri 必填")
	}
	// 复制 oauth Config 注 redirect_uri(单一 callback URL 设计,避免修改共享 oauth)
	oc := *a.oauth
	oc.RedirectURL = redirectURI
	return oc.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallengeS256(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

// Exchange 用 code + code_verifier 换 IdP token,校 id_token,取 userinfo。
// **id_token 必须校验**(防 IdP 假冒/中间人篡改);userinfo 是 IdP 额外端点,信任 IdP 自签证书 +
// access_token 即可(已由 oauth2 client 携带)。
func (a *genericAdapter) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (UserInfo, error) {
	if code == "" || codeVerifier == "" || redirectURI == "" {
		return UserInfo{}, errors.New("oidc.Exchange: code/code_verifier/redirect_uri 必填")
	}
	oc := *a.oauth
	oc.RedirectURL = redirectURI
	tok, err := oc.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.Exchange token: %w", err)
	}
	// 校 id_token(签名 + aud=client_id + iss + 有效期);必有 id_token 否则 IdP 未正确配置
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return UserInfo{}, errors.New("oidc.Exchange: IdP 未返回 id_token")
	}
	if _, err := a.verifier.Verify(ctx, rawIDToken); err != nil {
		return UserInfo{}, fmt.Errorf("oidc.Exchange: id_token 校验失败: %w", err)
	}
	// userinfo:用 access_token 拿 sub/email/name/groups
	userInfo, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.Exchange: userinfo: %w", err)
	}
	var claims struct {
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := userInfo.Claims(&claims); err != nil {
		return UserInfo{}, fmt.Errorf("oidc.Exchange: 解析 userinfo: %w", err)
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	return UserInfo{
		Subject: userInfo.Subject,
		Email:   claims.Email,
		Name:    name,
		Groups:  claims.Groups,
	}, nil
}
