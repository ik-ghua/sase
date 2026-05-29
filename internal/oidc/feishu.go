package oidc

// 飞书(Feishu / Lark)登录 adapter(Slice37b-2)。
//
// 协议形态(v3 内部应用):
//   ① 浏览器跳 https://accounts.feishu.cn/open-apis/authen/v1/authorize?client_id=APP_ID&redirect_uri=...&response_type=code&state=...
//   ② 用户授权后回调 redirect_uri?code=...&state=...
//   ③ 服务端用 app_id+app_secret 换 **app_access_token**(应用级,2h TTL,**必须缓存**,同企微 corp token 模板):
//     POST /open-apis/auth/v3/app_access_token/internal  {app_id, app_secret} → {app_access_token, expire}
//   ④ app_access_token + code 换 user_access_token(per-user):
//     POST /open-apis/authen/v1/oidc/access_token  Header: Authorization: Bearer APP_TOKEN
//     body {grant_type:"authorization_code", code} → {data:{access_token,...}}
//   ⑤ user_access_token → user 身份:
//     GET /open-apis/authen/v1/user_info  Header: Authorization: Bearer USER_TOKEN
//     → {data:{union_id, open_id, name, email, en_name, ...}}
//
// 与企微/钉钉差异:
//   - **三步链 + 应用级 token 缓存**(三家最复杂);
//   - subject=union_id(跨飞书租户应用稳定);
//   - 错误结构 `{code(int), msg}`(同企微 errcode 风格,但字段名是 code);
//   - 鉴权 Header `Authorization: Bearer ...`(标准 Bearer)。
//
// 安全模型同企微/钉钉:无 PKCE / 无 id_token,防线 = 服务端 state + app_secret + HTTPS。

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
	"sync"
	"time"
)

const (
	feishuDefaultAPIBase  = "https://open.feishu.cn"
	feishuDefaultAuthHost = "https://accounts.feishu.cn"
	feishuTokenTTLBuffer  = 5 * time.Minute
)

// FeishuConfig 是飞书 adapter 入参。
type FeishuConfig struct {
	AppID     string // APP_ID(IdPConfig.ClientID)
	AppSecret string // APP_SECRET
	APIBase   string // 可选(测试 mock 注入);空→ feishuDefaultAPIBase
	AuthHost  string // 可选(测试 mock 注入);空→ feishuDefaultAuthHost
}

// ErrFeishuMissingUnionID 表示 user_info 未返 union_id(罕见,可能是应用未配权限或飞书账号异常)。
var ErrFeishuMissingUnionID = errors.New("feishu: user_info 未返回 union_id")

type feishuAdapter struct {
	appID      string
	appSecret  string
	apiBase    string
	authHost   string
	httpClient *http.Client
}

// NewFeishu 构造飞书 adapter。
func NewFeishu(_ context.Context, cfg FeishuConfig) (Adapter, error) {
	if cfg.AppID == "" || cfg.AppSecret == "" {
		return nil, errors.New("oidc.NewFeishu: app_id/app_secret 必填")
	}
	apiBase := cfg.APIBase
	if apiBase == "" {
		apiBase = feishuDefaultAPIBase
	}
	authHost := cfg.AuthHost
	if authHost == "" {
		authHost = feishuDefaultAuthHost
	}
	return &feishuAdapter{
		appID:      cfg.AppID,
		appSecret:  cfg.AppSecret,
		apiBase:    strings.TrimRight(apiBase, "/"),
		authHost:   strings.TrimRight(authHost, "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// AuthURL:无 PKCE,codeVerifier 入参被忽略;scope 留空(默认 identity 基础)。
func (a *feishuAdapter) AuthURL(_ context.Context, state, _ /*codeVerifier*/, redirectURI string) (string, error) {
	if state == "" || redirectURI == "" {
		return "", errors.New("oidc.feishu.AuthURL: state/redirect_uri 必填")
	}
	q := url.Values{
		"client_id":     {a.appID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"state":         {state},
	}
	return a.authHost + "/open-apis/authen/v1/authorize?" + q.Encode(), nil
}

// Exchange:三步链(app_access_token cache → user_access_token → user_info)。
func (a *feishuAdapter) Exchange(ctx context.Context, code, _ /*codeVerifier*/, _ /*redirectURI*/ string) (UserInfo, error) {
	if code == "" {
		return UserInfo{}, errors.New("oidc.feishu.Exchange: code 必填")
	}
	appToken, err := a.getAppAccessToken(ctx)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.feishu: app_access_token: %w", err)
	}
	userToken, err := a.getUserAccessToken(ctx, appToken, code)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.feishu: user_access_token: %w", err)
	}
	unionID, name, email, err := a.getUserInfo(ctx, userToken)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.feishu: user_info: %w", err)
	}
	if unionID == "" {
		return UserInfo{}, ErrFeishuMissingUnionID
	}
	return UserInfo{Subject: unionID, Name: name, Email: email}, nil
}

// ---------- 飞书 HTTP helpers ----------

// feishuAPIError:飞书统一错误响应({code:int, msg:string},code!=0 即错)。
type feishuAPIError struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func (e *feishuAPIError) Error() string {
	return fmt.Sprintf("feishu API code=%d msg=%s", e.Code, e.Msg)
}

// postFeishuJSON:POST JSON,Bearer Header 可选(空则不带);响应必为 {code, msg, ...},code!=0 转 feishuAPIError。
// out 反序列化整个响应(包含 data 字段)。
func (a *feishuAdapter) postFeishuJSON(ctx context.Context, path string, bearer string, body any, out any) error {
	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiBase+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return a.doFeishu(req, out)
}

// getFeishuJSON:GET,Bearer Header;响应 {code,msg,data}。
func (a *feishuAdapter) getFeishuJSON(ctx context.Context, path, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	return a.doFeishu(req, out)
}

func (a *feishuAdapter) doFeishu(req *http.Request, out any) error {
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("读响应: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(raw, 200))
	}
	// 探 code(业务错走 HTTP 200 + code!=0;HTTP 错才走上面)
	var base feishuAPIError
	if err := json.Unmarshal(raw, &base); err != nil {
		return fmt.Errorf("解 code: %w body=%s", err, truncate(raw, 200))
	}
	if base.Code != 0 {
		return &base
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("解业务体: %w", err)
		}
	}
	return nil
}

// getAppAccessToken:走缓存,未命中经 sync.Map + 单飞 mutex + 双检(同 wecom 模板)。
func (a *feishuAdapter) getAppAccessToken(ctx context.Context) (string, error) {
	key := a.apiBase + "|" + a.appID
	if tok, ok := feishuTokenCacheGet(key); ok {
		return tok, nil
	}
	mu := feishuTokenLock(key)
	mu.Lock()
	defer mu.Unlock()
	if tok, ok := feishuTokenCacheGet(key); ok {
		return tok, nil
	}
	var resp struct {
		AppAccessToken string `json:"app_access_token"`
		Expire         int    `json:"expire"`
	}
	body := map[string]string{"app_id": a.appID, "app_secret": a.appSecret}
	if err := a.postFeishuJSON(ctx, "/open-apis/auth/v3/app_access_token/internal", "", body, &resp); err != nil {
		return "", err
	}
	if resp.AppAccessToken == "" || resp.Expire <= 0 {
		return "", errors.New("feishu: app_access_token 返回字段缺失")
	}
	ttl := time.Duration(resp.Expire)*time.Second - feishuTokenTTLBuffer
	if ttl < time.Minute {
		ttl = time.Minute
	}
	feishuTokenCachePut(key, resp.AppAccessToken, time.Now().Add(ttl))
	return resp.AppAccessToken, nil
}

// getUserAccessToken:Bearer APP_TOKEN + {grant_type, code} → data.access_token。
func (a *feishuAdapter) getUserAccessToken(ctx context.Context, appToken, code string) (string, error) {
	var resp struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	body := map[string]string{"grant_type": "authorization_code", "code": code}
	if err := a.postFeishuJSON(ctx, "/open-apis/authen/v1/oidc/access_token", appToken, body, &resp); err != nil {
		return "", err
	}
	if resp.Data.AccessToken == "" {
		return "", errors.New("feishu: user access_token 返回字段缺失")
	}
	return resp.Data.AccessToken, nil
}

// getUserInfo:GET /authen/v1/user_info,Bearer USER_TOKEN → data.{union_id, name, email}。
func (a *feishuAdapter) getUserInfo(ctx context.Context, userToken string) (unionID, name, email string, err error) {
	var resp struct {
		Data struct {
			UnionID string `json:"union_id"`
			Name    string `json:"name"`
			Email   string `json:"email"`
		} `json:"data"`
	}
	if err := a.getFeishuJSON(ctx, "/open-apis/authen/v1/user_info", userToken, &resp); err != nil {
		return "", "", "", err
	}
	return resp.Data.UnionID, resp.Data.Name, resp.Data.Email, nil
}

// ---------- app_access_token 缓存(package-level,同 wecom 模板) ----------

type feishuCachedToken struct {
	access   string
	expireAt time.Time
}

var (
	feishuTokenCache sync.Map // key string(apiBase|app_id)→ feishuCachedToken
	feishuTokenLocks sync.Map // key string → *sync.Mutex(单飞)
)

func feishuTokenCacheGet(key string) (string, bool) {
	v, ok := feishuTokenCache.Load(key)
	if !ok {
		return "", false
	}
	tok := v.(feishuCachedToken)
	if time.Now().After(tok.expireAt) {
		feishuTokenCache.Delete(key) // 顺手淘汰(评审 B4 反馈,Slice37b-1 wecom 未做;此处新增主动加上)
		return "", false
	}
	return tok.access, true
}

func feishuTokenCachePut(key, access string, expireAt time.Time) {
	feishuTokenCache.Store(key, feishuCachedToken{access: access, expireAt: expireAt})
}

func feishuTokenLock(key string) *sync.Mutex {
	if v, ok := feishuTokenLocks.Load(key); ok {
		return v.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := feishuTokenLocks.LoadOrStore(key, mu)
	return actual.(*sync.Mutex)
}

// invalidateFeishuCache 按 app_id 清缓存(Slice37c:IdP 删除/轮换 secret 联动)。
// 同 wecom 模板:key 形态 "apiBase|app_id",未知 apiBase 时 Range 找 endsWith。
func invalidateFeishuCache(appID string) {
	if appID == "" {
		return
	}
	suffix := "|" + appID
	feishuTokenCache.Range(func(k, _ any) bool {
		if ks, ok := k.(string); ok && strings.HasSuffix(ks, suffix) {
			feishuTokenCache.Delete(ks)
			feishuTokenLocks.Delete(ks)
		}
		return true
	})
}
