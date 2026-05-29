package oidc

// 钉钉(DingTalk)登录 adapter(Slice37b-2)。
//
// 协议形态(新版 dingtalk-oauth2,非完整 OIDC):
//   ① 浏览器跳 https://login.dingtalk.com/oauth2/auth?redirect_uri=...&response_type=code&client_id=APP_ID&scope=openid&state=...&prompt=consent
//   ② 用户授权后回调 redirect_uri?code=...&state=...
//   ③ POST https://api.dingtalk.com/v1.0/oauth2/userAccessToken
//     JSON body:{clientId, clientSecret, code, grantType:"authorization_code"}
//     → {accessToken(2h TTL), refreshToken, corpId, unionId}
//   ④ GET https://api.dingtalk.com/v1.0/contact/users/me
//     Header: x-acs-dingtalk-access-token: USER_ACCESS_TOKEN
//     → {unionId, openId, nick, email, stateCode(1=企业内/-1=企业外)}
//
// 与企微差异:
//   - **不需要 corp/app 级 token**(code 直接换 user token);**无 cache 价值**(per-user token,登录即换);
//   - subject=unionId(跨钉钉应用稳定的用户唯一标识);
//   - 鉴权 Header `x-acs-dingtalk-access-token`,非 query/标准 Bearer;
//   - 错误结构 `{code(string), message, requestid}`;
//   - 仅接受 stateCode=1 的**企业内成员**(stateCode=-1 是外部联系人/未关注,fail-closed 拒)。
//
// 安全模型同企微:**无 PKCE / 无 id_token**,防线 = 服务端 state TakeOnce + clientSecret + HTTPS。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	dingtalkDefaultAPIBase   = "https://api.dingtalk.com"
	dingtalkDefaultOAuthHost = "https://login.dingtalk.com"
)

// DingTalkConfig 是钉钉 adapter 入参。
type DingTalkConfig struct {
	ClientID     string // APP_ID(IdPConfig.ClientID 映射)
	ClientSecret string // APP_SECRET
	APIBase      string // 可选(测试 mock 注入);空→ dingtalkDefaultAPIBase
	OAuthHost    string // 可选(测试 mock 注入);空→ dingtalkDefaultOAuthHost
}

// ErrDingTalkExternalUser 表示 contact/users/me 返回 stateCode != 1(外部联系人/未关注),
// fail-closed 拒绝(Slice37b-2 仅企业内成员)。
var ErrDingTalkExternalUser = errors.New("dingtalk: 非企业内成员(stateCode!=1)登录暂不支持")

type dingtalkAdapter struct {
	clientID     string
	clientSecret string
	apiBase      string
	oauthHost    string
	httpClient   *http.Client
}

// NewDingTalk 构造钉钉 adapter。
func NewDingTalk(_ context.Context, cfg DingTalkConfig) (Adapter, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("oidc.NewDingTalk: client_id/client_secret 必填")
	}
	apiBase := cfg.APIBase
	if apiBase == "" {
		apiBase = dingtalkDefaultAPIBase
	}
	oauthHost := cfg.OAuthHost
	if oauthHost == "" {
		oauthHost = dingtalkDefaultOAuthHost
	}
	return &dingtalkAdapter{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		apiBase:      strings.TrimRight(apiBase, "/"),
		oauthHost:    strings.TrimRight(oauthHost, "/"),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// AuthURL 构造钉钉 authorize URL(无 PKCE,codeVerifier 入参被忽略)。
func (a *dingtalkAdapter) AuthURL(_ context.Context, state, _ /*codeVerifier*/, redirectURI string) (string, error) {
	if state == "" || redirectURI == "" {
		return "", errors.New("oidc.dingtalk.AuthURL: state/redirect_uri 必填")
	}
	q := url.Values{
		"client_id":     {a.clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {state},
		"prompt":        {"consent"},
	}
	return a.oauthHost + "/oauth2/auth?" + q.Encode(), nil
}

// ErrDingTalkUnionIDMismatch:S1 防御纵深 —— userAccessToken 与 users/me 返回的 unionId 不一致,
// 可能是中间人在两跳之间替换 token 导向他人。fail-closed 拒(评审 S1)。
var ErrDingTalkUnionIDMismatch = errors.New("dingtalk: unionId 在 userAccessToken 与 users/me 之间不一致")

// Exchange:code→userAccessToken→contact/users/me;S1 校 unionId 两源一致。
func (a *dingtalkAdapter) Exchange(ctx context.Context, code, _ /*codeVerifier*/, _ /*redirectURI*/ string) (UserInfo, error) {
	if code == "" {
		return UserInfo{}, errors.New("oidc.dingtalk.Exchange: code 必填")
	}
	userToken, tokenUnionID, err := a.getUserAccessToken(ctx, code)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.dingtalk: code→userAccessToken: %w", err)
	}
	infoUnionID, name, email, err := a.getUserInfo(ctx, userToken)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.dingtalk: users/me: %w", err)
	}
	// S1:两源 unionId 一致性校验(钉钉两跳间若不一致,拒;tokenUnionID 可能为空——老版本响应不带,此时只校 users/me 主源)
	if tokenUnionID != "" && tokenUnionID != infoUnionID {
		return UserInfo{}, ErrDingTalkUnionIDMismatch
	}
	return UserInfo{Subject: infoUnionID, Name: name, Email: email}, nil
}

// ---------- 钉钉 HTTP helpers ----------

// dingtalkAPIError:钉钉 v1.0 API 错误响应(code 是字符串,例 "Forbidden.AccessDenied")。
type dingtalkAPIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *dingtalkAPIError) Error() string {
	return fmt.Sprintf("dingtalk API code=%s msg=%s", e.Code, e.Message)
}

// getUserAccessToken:POST /v1.0/oauth2/userAccessToken JSON body 换 user-scoped accessToken。
// 返回 accessToken **以及** unionId(钉钉响应已带)——用于 S1 Exchange 内的双源一致性校验。
func (a *dingtalkAdapter) getUserAccessToken(ctx context.Context, code string) (accessToken, unionID string, err error) {
	body, _ := json.Marshal(map[string]string{
		"clientId":     a.clientID,
		"clientSecret": a.clientSecret,
		"code":         code,
		"grantType":    "authorization_code",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiBase+"/v1.0/oauth2/userAccessToken", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("读响应: %w", err)
	}
	// S2 修复:HTTP 200 和 4xx 都尝试 apiErr 解析(钉钉极少数业务错走 200 + code 非空,与 wecom/feishu 同形态);
	// 4xx 走原路径(走过来的多数情形)。
	if resp.StatusCode != http.StatusOK {
		var apiErr dingtalkAPIError
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Code != "" {
			return "", "", &apiErr
		}
		return "", "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(raw, 200))
	}
	// 200 路径:先探 apiErr(200 + code 非空 → 业务错)
	var apiErr dingtalkAPIError
	if json.Unmarshal(raw, &apiErr) == nil && apiErr.Code != "" {
		return "", "", &apiErr
	}
	var ok struct {
		AccessToken string `json:"accessToken"`
		ExpireIn    int    `json:"expireIn"`
		UnionID     string `json:"unionId"` // S1:用于与 users/me 返回的 unionId 比对
	}
	if err := json.Unmarshal(raw, &ok); err != nil {
		return "", "", fmt.Errorf("解 userAccessToken: %w body=%s", err, truncate(raw, 200))
	}
	if ok.AccessToken == "" {
		return "", "", errors.New("dingtalk: userAccessToken 返回字段缺失")
	}
	return ok.AccessToken, ok.UnionID, nil
}

// getUserInfo:GET /v1.0/contact/users/me;Header x-acs-dingtalk-access-token=USER_ACCESS_TOKEN。
// 返回 unionId/nick/email/stateCode;stateCode!=1 视外部用户 → ErrDingTalkExternalUser。
//
// 注:钉钉文档原始要求 Header 名小写 `x-acs-dingtalk-access-token`(评审 S3);
// Go net/http stdlib 经 textproto.MIMEHeader 自动 canonical 化为 X-Acs-Dingtalk-Access-Token,
// 钉钉 API 网关大小写不敏感,实际生产兼容。
func (a *dingtalkAdapter) getUserInfo(ctx context.Context, userToken string) (unionID, name, email string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.apiBase+"/v1.0/contact/users/me", nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("x-acs-dingtalk-access-token", userToken)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", "", fmt.Errorf("读响应: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr dingtalkAPIError
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Code != "" {
			return "", "", "", &apiErr
		}
		return "", "", "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(raw, 200))
	}
	var info struct {
		UnionID   string `json:"unionId"`
		OpenID    string `json:"openId"`
		Nick      string `json:"nick"`
		Email     string `json:"email"`
		StateCode int    `json:"stateCode"` // 1=企业内 / -1=外部联系人 / 0=未知
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return "", "", "", fmt.Errorf("解 users/me: %w body=%s", err, truncate(raw, 200))
	}
	// stateCode 缺省 0 也按 fail-closed 处理(企业外/未知一律拒)
	if info.StateCode != 1 {
		return "", "", "", ErrDingTalkExternalUser
	}
	if info.UnionID == "" {
		return "", "", "", errors.New("dingtalk: users/me 未返回 unionId")
	}
	return info.UnionID, info.Nick, info.Email, nil
}
