package oidc

// 企业微信(WeCom)登录 adapter(Slice37b-1)。
//
// 协议形态(非标准 OIDC,L2 §3.1 表):
//   ① 浏览器跳 https://open.weixin.qq.com/connect/oauth2/authorize?appid=CORPID&redirect_uri=...&response_type=code&scope=snsapi_base&state=...#wechat_redirect
//   ② 用户授权后回调 redirect_uri?code=...&state=...
//   ③ 服务端用 corpid+corpsecret 换 access_token(/cgi-bin/gettoken,2h TTL,**必须缓存**)
//   ④ access_token + code → /cgi-bin/user/getuserinfo → userid(corp 内永久标识)
//   ⑤(可选,丰富资料)access_token + userid → /cgi-bin/user/get → name/email/...
//
// 安全模型 vs 标准 OIDC:
//   - **无 PKCE**(AuthURL 入参 codeVerifier 被忽略):服务端 state TakeOnce 是唯一 CSRF/重放防线;
//   - **无 id_token**(无 JWS 签名校验):身份信赖 corpsecret(IdP 端鉴别 client)+ HTTPS 通道完整性;
//   - corpsecret 由 secret 模块加密落库(Slice36),解密后**短窗内存**;
//   - access_token 缓存按 (APIBase, corpid) 索引,**进程内 sync.Map**(单实例;集群需 Redis,后续刀)。
//
// 已知不支持:
//   - 外部联系人(open contacts):仅返 OpenId 无 UserId,**本刀只接收 corp 内成员**(UserId 必填);
//   - snsapi_privateinfo(需企业应用 AgentID + 用户授权弹窗):本刀仅 snsapi_base(静默登录,corp 内成员可用)。

import (
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

// 生产默认端点(可被 WeComConfig.APIBase / AuthHost 覆盖,主要用于测试 mock 注入)。
const (
	wecomDefaultAPIBase  = "https://qyapi.weixin.qq.com"
	wecomDefaultAuthHost = "https://open.weixin.qq.com"
)

// wecomTokenTTLBuffer:access_token 实际 TTL 2h,提前 5min 续约,避免临界过期。
const wecomTokenTTLBuffer = 5 * time.Minute

// WeComConfig 是企微 adapter 入参。
type WeComConfig struct {
	CorpID     string // corpid(IdPConfig.ClientID 映射)
	CorpSecret string // corpsecret(idp.Service.GetClientSecret 解密拿到)
	APIBase    string // 可选(测试 mock 注入);空→ wecomDefaultAPIBase
	AuthHost   string // 可选(测试 mock 注入);空→ wecomDefaultAuthHost
}

// wecomAdapter 是 WeCom Adapter 实现。每次登录构造一个新实例(请求作用域,无状态字段);
// access_token 缓存在 package-level wecomTokenCache(共享,跨请求复用)。
type wecomAdapter struct {
	corpID     string
	corpSecret string
	apiBase    string
	authHost   string
	httpClient *http.Client
}

// NewWeCom 构造企微 adapter。corpid/corpsecret 必填。
func NewWeCom(_ context.Context, cfg WeComConfig) (Adapter, error) {
	if cfg.CorpID == "" || cfg.CorpSecret == "" {
		return nil, errors.New("oidc.NewWeCom: corpid/corpsecret 必填")
	}
	apiBase := cfg.APIBase
	if apiBase == "" {
		apiBase = wecomDefaultAPIBase
	}
	authHost := cfg.AuthHost
	if authHost == "" {
		authHost = wecomDefaultAuthHost
	}
	return &wecomAdapter{
		corpID:     cfg.CorpID,
		corpSecret: cfg.CorpSecret,
		apiBase:    strings.TrimRight(apiBase, "/"),
		authHost:   strings.TrimRight(authHost, "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// AuthURL 构造企微 authorize URL。**codeVerifier 入参被忽略**(企微无 PKCE,见包注释)。
func (a *wecomAdapter) AuthURL(_ context.Context, state, _ /*codeVerifier*/, redirectURI string) (string, error) {
	if state == "" || redirectURI == "" {
		return "", errors.New("oidc.wecom.AuthURL: state/redirect_uri 必填")
	}
	// scope=snsapi_base:静默登录(corp 内成员无需弹窗确认,适合内部办公系统);
	// scope=snsapi_privateinfo 可拿手机号等私有信息,需 AgentID + 用户授权,**Slice37b-1 不支持**。
	q := url.Values{
		"appid":         {a.corpID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"snsapi_base"},
		"state":         {state},
	}
	return a.authHost + "/connect/oauth2/authorize?" + q.Encode() + "#wechat_redirect", nil
}

// Exchange 用 code 换 UserInfo(走 access_token 缓存 → getuserinfo → user/get 三步)。
func (a *wecomAdapter) Exchange(ctx context.Context, code, _ /*codeVerifier*/, _ /*redirectURI*/ string) (UserInfo, error) {
	if code == "" {
		return UserInfo{}, errors.New("oidc.wecom.Exchange: code 必填")
	}
	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.wecom: 取 access_token: %w", err)
	}
	// Step1:code → userid
	userID, err := a.getUserIDByCode(ctx, accessToken, code)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oidc.wecom: code→userid: %w", err)
	}
	// Step2:userid → name/email
	name, email, err := a.getUserDetail(ctx, accessToken, userID)
	if err != nil {
		// 详情失败不中断(name/email 都是辅助字段;identity 主键是 userID);只 log
		// (但仍返回主键以完成登录)
		return UserInfo{Subject: userID}, nil //nolint:nilerr // 细节失败降级:已经能拿到 subject,登录可继续
	}
	return UserInfo{Subject: userID, Name: name, Email: email}, nil
}

// ---------- 内部 HTTP helpers ----------

// wecomAPIError:企微 API 统一错误响应(errcode != 0 即业务错)。
type wecomAPIError struct {
	Code int    `json:"errcode"`
	Msg  string `json:"errmsg"`
}

func (e *wecomAPIError) Error() string {
	return fmt.Sprintf("wecom API errcode=%d msg=%s", e.Code, e.Msg)
}

// callAPI:GET 企微 API,解析 JSON,业务 errcode != 0 转 wecomAPIError。out 是用于解码业务字段的结构。
func (a *wecomAdapter) callAPI(ctx context.Context, path string, q url.Values, out any) error {
	reqURL := a.apiBase + path + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MiB 上限防 IdP 异常巨响应
	if err != nil {
		return fmt.Errorf("读响应: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(body, 200))
	}
	// 先用 wecomAPIError 探 errcode;失败再按业务结构解
	var base wecomAPIError
	if err := json.Unmarshal(body, &base); err != nil {
		return fmt.Errorf("解 errcode: %w body=%s", err, truncate(body, 200))
	}
	if base.Code != 0 {
		return &base
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("解业务体: %w", err)
		}
	}
	return nil
}

// getAccessToken 从缓存取或经 /cgi-bin/gettoken 换;按 (apiBase, corpid) 索引避免测试冲突。
func (a *wecomAdapter) getAccessToken(ctx context.Context) (string, error) {
	key := a.apiBase + "|" + a.corpID
	if tok, ok := wecomTokenCacheGet(key); ok {
		return tok, nil
	}
	// 缓存未命中 → 经 mu 单飞,避免并发同时调 IdP(rate-limit)
	mu := wecomTokenLock(key)
	mu.Lock()
	defer mu.Unlock()
	// 双检:获锁后再查一次,有人刚换过就用
	if tok, ok := wecomTokenCacheGet(key); ok {
		return tok, nil
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	q := url.Values{"corpid": {a.corpID}, "corpsecret": {a.corpSecret}}
	if err := a.callAPI(ctx, "/cgi-bin/gettoken", q, &resp); err != nil {
		return "", err
	}
	if resp.AccessToken == "" || resp.ExpiresIn <= 0 {
		return "", errors.New("wecom: gettoken 返回字段缺失")
	}
	ttl := time.Duration(resp.ExpiresIn)*time.Second - wecomTokenTTLBuffer
	if ttl < time.Minute {
		ttl = time.Minute // 兜底极短 TTL
	}
	wecomTokenCachePut(key, resp.AccessToken, time.Now().Add(ttl))
	return resp.AccessToken, nil
}

// ErrExternalContact 表示企微返回了 OpenId(外部联系人或未关注成员),Slice37b-1 仅 corp 内成员。
// sentinel(评审 B13):便测试 errors.Is + 文案可改不破契约。
var ErrExternalContact = errors.New("wecom: 外部联系人(OpenId)登录暂不支持,Slice37b-1 仅 corp 内成员")

func (a *wecomAdapter) getUserIDByCode(ctx context.Context, accessToken, code string) (string, error) {
	var resp struct {
		UserID string `json:"UserId"` // 企微返回字段首字母大写
		OpenID string `json:"OpenId"`
	}
	q := url.Values{"access_token": {accessToken}, "code": {code}}
	if err := a.callAPI(ctx, "/cgi-bin/user/getuserinfo", q, &resp); err != nil {
		return "", err
	}
	// **OpenId 出现即拒**(评审 B7,收紧):企微某些场景同时返 UserId+OpenId,但 OpenId 存在 ≡ 不是纯 corp 内身份;
	// fail-closed 拒绝,只接受"仅 UserId 无 OpenId"的纯 corp 成员。
	if resp.OpenID != "" {
		return "", ErrExternalContact
	}
	if resp.UserID == "" {
		return "", errors.New("wecom: getuserinfo 未返回 UserId")
	}
	return resp.UserID, nil
}

func (a *wecomAdapter) getUserDetail(ctx context.Context, accessToken, userID string) (name, email string, err error) {
	var resp struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	q := url.Values{"access_token": {accessToken}, "userid": {userID}}
	if err := a.callAPI(ctx, "/cgi-bin/user/get", q, &resp); err != nil {
		return "", "", err
	}
	return resp.Name, resp.Email, nil
}

// ---------- access_token 缓存(package-level,跨请求复用,sync.Map + 单飞 mutex) ----------

type wecomCachedToken struct {
	access   string
	expireAt time.Time
}

var (
	wecomTokenCache sync.Map // key string(apiBase|corpid)→ wecomCachedToken
	wecomTokenLocks sync.Map // key string → *sync.Mutex(单飞:并发同 key 同时缺失只让一个 goroutine 实际调 IdP)
)

func wecomTokenCacheGet(key string) (string, bool) {
	v, ok := wecomTokenCache.Load(key)
	if !ok {
		return "", false
	}
	tok := v.(wecomCachedToken)
	if time.Now().After(tok.expireAt) {
		wecomTokenCache.Delete(key) // 顺手淘汰(Slice37b-1 评审 B4,Slice37c 对齐 feishu 模板)
		return "", false
	}
	return tok.access, true
}

// invalidateWeComCache 按 corpid 清缓存(Slice37c:IdP 删除/轮换 secret 联动)。
// key 形态 "apiBase|corpid",未知 apiBase → Range 遍历找 endsWith("|" + corpid) 的全删。
func invalidateWeComCache(corpID string) {
	if corpID == "" {
		return
	}
	suffix := "|" + corpID
	wecomTokenCache.Range(func(k, _ any) bool {
		if ks, ok := k.(string); ok && strings.HasSuffix(ks, suffix) {
			wecomTokenCache.Delete(ks)
			wecomTokenLocks.Delete(ks)
		}
		return true
	})
}

func wecomTokenCachePut(key, access string, expireAt time.Time) {
	wecomTokenCache.Store(key, wecomCachedToken{access: access, expireAt: expireAt})
}

func wecomTokenLock(key string) *sync.Mutex {
	if v, ok := wecomTokenLocks.Load(key); ok {
		return v.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := wecomTokenLocks.LoadOrStore(key, mu)
	return actual.(*sync.Mutex)
}

// truncate 安全截断字节切片用作错误信息(防 IdP 异常超长响应撑爆 log)。
func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "...(trunc)"
	}
	return string(b)
}
