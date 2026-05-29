package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/secret"
)

// IDPSvc 是 handler 依赖 idp.Service 的窄接口(便测试 mock,避免直接绑实现)。
type IDPSvc interface {
	Get(ctx context.Context, tenantID, id string) (*idp.Config, error)
	GetClientSecret(ctx context.Context, tenantID, id string) ([]byte, error)
}

// IdentitySvc 是 handler 依赖 identity.Service 的窄接口。
type IdentitySvc interface {
	EnsureUserByExternalID(ctx context.Context, tenantID, idpID, externalID, email string) (identity.User, error)
	IssueCredential(ctx context.Context, tenantID, userID string, groups []string, posture string, ttl time.Duration) (token, jti string, err error)
}

// AuditSvc 是 handler 依赖 audit.Service 的窄接口(只用 Record)。可为 nil(测试简化路径);
// 生产强烈建议注入——登录是关键安全事件,失败尝试(state 错/IdP 拒/DEK 销毁)亦须留痕。
type AuditSvc interface {
	Record(ctx context.Context, e audit.Entry) error
}

// AdapterFactory 给定 IdPConfig 与解密后的 client_secret,造一个一次性 Adapter。
// 测试时可替换为 mock(返回桩 adapter)。生产:默认 GenericFactory(走 NewGeneric)。
type AdapterFactory func(ctx context.Context, cfg *idp.Config, clientSecret []byte) (Adapter, error)

// GenericFactory 默认 factory:把 IdPConfig.Endpoint 作 OIDC issuer。
// 后续刀加厂商 factory 时(企微/钉钉/飞书),按 cfg.Kind 派发即可。
//
// 注:cfg.Endpoint(string)与 cfg.ClientID(string)在传入 oauth2.Config 时被拷贝为 string,
// 整个 adapter 生命周期内驻留;**zeroize 入参 clientSecret 仅减少**字节切片副本,不能消除 string 化后副本
// (handler 内 adapter 是请求作用域、随回应结束 GC,可接受)。
func GenericFactory(ctx context.Context, cfg *idp.Config, clientSecret []byte) (Adapter, error) {
	if cfg == nil {
		return nil, errors.New("oidc.GenericFactory: cfg=nil")
	}
	return NewGeneric(ctx, GenericConfig{
		IssuerURL:    cfg.Endpoint,
		ClientID:     cfg.ClientID,
		ClientSecret: string(clientSecret),
	})
}

// HandlerDeps 是 LoginHandler/CallbackHandler 共享依赖。
type HandlerDeps struct {
	IDPSvc      IDPSvc
	Identity    IdentitySvc
	StateStore  StateStore
	Audit       AuditSvc // 可 nil:测试或不需登录审计的部署。生产建议必设
	Factory     AdapterFactory
	CallbackURL string // 本服务 /api/v1/idp/callback 的绝对 URL(IdP 端须配同一 URL)
	SessionTTL  time.Duration
}

func (d *HandlerDeps) ttl() time.Duration {
	if d.SessionTTL <= 0 {
		return 30 * time.Minute // 默认 30min(会话短 TTL,L1 3.8;identity.MaxTTL=1h 内)
	}
	return d.SessionTTL
}

// errorResponse 是 OIDC handler 错误响应的 JSON 形状。Login 成功走 303,
// Callback 成功走 200 + CallbackResponse;此结构仅用于错误。
type errorResponse struct {
	Error string `json:"error"`
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

// writeInternalErr 把内部错(DB/secret/IdP 网络/EnsureUser/IssueCredential 等)分两路:
//   - 对用户:返回 code + 通用文案(不泄露上游错的细节);
//   - 对运维:经 log.Printf 保留 err 全文 + tag(便排障)。
//
// 防 H4 信息泄漏:**公开端点直接 err.Error() 会暴露 DB schema/IdP 内部 URL/连接元数据等**。
func writeInternalErr(w http.ResponseWriter, code int, publicMsg, tag string, err error) {
	log.Printf("[oidc] %s: %v", tag, err)
	writeErr(w, code, publicMsg)
}

// LoginHandler 返回登录入口 http.HandlerFunc。
// 路径:GET /api/v1/idp/login?tenant_id=<tid>&idp_id=<cid>&return_to=<spa-path>
//   - 校 query;读 IdPConfig 并校 status=active;
//   - 解密 client_secret(短窗内存);
//   - 生成 PKCE verifier + StateStore.Put(rec, 含 return_to) 拿 state ID;
//   - adapter.AuthURL(state, verifier, callback) → 303 跳 IdP。
//
// **return_to 安全(Slice37c)**:必须是同源相对路径(以 "/" 开头),否则强制改用默认 "/";
// **绝不接受 absolute URL**,防 open-redirect 把用户引到攻击者域。落服务端 state 不暴露给客户端篡改。
//
// 审计:Login 成功不写审计(state put 还不算"已认证");失败也不审计(攻击者随便扫不写库)。
// 真正的"登录尝试" = Callback,在那里写审计(成功 + 各类失败 + 失败原因)。
func LoginHandler(deps *HandlerDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tid := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		cid := strings.TrimSpace(r.URL.Query().Get("idp_id"))
		if tid == "" || cid == "" {
			writeErr(w, http.StatusBadRequest, "tenant_id/idp_id 必填")
			return
		}
		returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
		cfg, err := deps.IDPSvc.Get(ctx, tid, cid)
		if err != nil {
			if errors.Is(err, idp.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "IdP 配置不存在")
				return
			}
			writeInternalErr(w, http.StatusInternalServerError, "oidc login failed", "login get idp", err)
			return
		}
		if cfg.Status != "active" {
			writeErr(w, http.StatusForbidden, ErrIDPDisabled.Error())
			return
		}
		clientSecret, err := deps.IDPSvc.GetClientSecret(ctx, tid, cid)
		if err != nil {
			switch {
			case errors.Is(err, secret.ErrNotFound), errors.Is(err, secret.ErrDestroyed):
				writeErr(w, http.StatusConflict, "IdP key unavailable")
			default:
				writeInternalErr(w, http.StatusInternalServerError, "oidc login failed", "login get client_secret", err)
			}
			return
		}
		defer zeroize(clientSecret)
		adapter, err := deps.Factory(ctx, cfg, clientSecret)
		if err != nil {
			writeInternalErr(w, http.StatusBadGateway, "OIDC discovery failed", "login discovery", err)
			return
		}
		verifier, err := generateCodeVerifier()
		if err != nil {
			writeInternalErr(w, http.StatusInternalServerError, "oidc login failed", "code_verifier", err)
			return
		}
		stateID, err := deps.StateStore.Put(ctx, StateRecord{
			TenantID: tid, IDPID: cid, CodeVerifier: verifier, RedirectURI: deps.CallbackURL, ReturnTo: returnTo,
		})
		if err != nil {
			writeInternalErr(w, http.StatusInternalServerError, "oidc login failed", "state put", err)
			return
		}
		authURL, err := adapter.AuthURL(ctx, stateID, verifier, deps.CallbackURL)
		if err != nil {
			writeInternalErr(w, http.StatusInternalServerError, "oidc login failed", "auth url", err)
			return
		}
		// 安全:303 See Other(避免浏览器重发 POST;此处 GET 已最小可能,但 303 更明确语义)
		http.Redirect(w, r, authURL, http.StatusSeeOther)
	}
}

// sanitizeReturnTo 校验 return_to:必须以 "/" 开头(同源相对路径)且**不**以 "//" 开头
// (`//evil.com/x` 会被浏览器视作 protocol-relative URL,跳转到 evil.com → open redirect)。
// 不合规一律退默认 "/"(应用首页),不报错——客户端不应靠 return_to 控错。
//
// **B1 深度防御**:显式拦控制字符(\r/\n/\t/NUL 等),不依赖 Go net/http stdlib `headerNewlineToSpace`
// 内部细节兜底(stdlib 内部行为不属于稳定契约;且 \r/\n 转空格仍可能让 SPA 路由器误判路径)。
func sanitizeReturnTo(s string) string {
	const defaultReturnTo = "/"
	if s == "" {
		return defaultReturnTo
	}
	// 必须以 / 开头但不是 // 开头(防 protocol-relative)+ 不含 \(反斜杠浏览器有时解 /,IE/老浏览器历史问题)
	if len(s) < 1 || s[0] != '/' || (len(s) >= 2 && s[1] == '/') || strings.Contains(s, "\\") {
		return defaultReturnTo
	}
	// 拦控制字符(B1):任意 < 0x20 或 == 0x7f 直接退默认
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return defaultReturnTo
		}
	}
	// 截断防超长(state record 占内存上限,与 detail 同口径)
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

// CallbackResponse 是回调成功返回的会话凭证 JSON。
// 注:当前返回 JSON;前端 SPA 接入后可选改为设置 httpOnly cookie + 302 → return_to(后续刀)。
type CallbackResponse struct {
	Token     string `json:"token"`
	JTI       string `json:"jti"`
	ExpiresIn int    `json:"expires_in"` // 秒
	UserID    string `json:"user_id"`
	Email     string `json:"email,omitempty"`
}

// CallbackHandler 返回回调端点 http.HandlerFunc。
// 路径:GET /api/v1/idp/callback?code=<>&state=<>
//   - state TakeOnce → rec(校 ErrInvalidState/ErrStateExpired);
//   - 按 rec.TenantID/IDPID 再读 IdPConfig + 解密 client_secret + 构造 adapter;
//   - adapter.Exchange(code, verifier, callback) → UserInfo;
//   - identity.EnsureUserByExternalID(tid, sub, email) → User(检查 user.Status=active,H1);
//   - identity.IssueCredential → token/jti;
//   - 显式审计登录尝试(成功/失败均记;H3,关键安全事件)。
func CallbackHandler(deps *HandlerDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		q := r.URL.Query()
		// IdP 错误回传(用户在 IdP 端拒绝/出错,标准 OAuth2 error 参数)
		if e := q.Get("error"); e != "" {
			// 不附 error_description(IdP 给的字符串,公开端点不回显未消毒文本)
			writeErr(w, http.StatusBadRequest, "IdP error: "+sanitizeIDPError(e))
			return
		}
		code := strings.TrimSpace(q.Get("code"))
		stateID := strings.TrimSpace(q.Get("state"))
		if code == "" || stateID == "" {
			writeErr(w, http.StatusBadRequest, "缺 code/state")
			return
		}
		rec, err := deps.StateStore.TakeOnce(ctx, stateID)
		if err != nil {
			// state 错不归属任何租户,无 tenant 写审计;只 log
			log.Printf("[oidc] callback state: %v", err)
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// 自此 rec.TenantID 已知 → 失败也写审计(归属 target tenant)
		cfg, err := deps.IDPSvc.Get(ctx, rec.TenantID, rec.IDPID)
		if err != nil {
			recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, "", "get idp", http.StatusInternalServerError)
			writeInternalErr(w, http.StatusInternalServerError, "oidc callback failed", "callback get idp", err)
			return
		}
		if cfg.Status != "active" {
			recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, "", "idp disabled", http.StatusForbidden)
			writeErr(w, http.StatusForbidden, ErrIDPDisabled.Error())
			return
		}
		clientSecret, err := deps.IDPSvc.GetClientSecret(ctx, rec.TenantID, rec.IDPID)
		if err != nil {
			switch {
			case errors.Is(err, secret.ErrNotFound), errors.Is(err, secret.ErrDestroyed):
				recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, "", "dek unavailable", http.StatusConflict)
				writeErr(w, http.StatusConflict, "IdP key unavailable")
			default:
				recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, "", "get client_secret", http.StatusInternalServerError)
				writeInternalErr(w, http.StatusInternalServerError, "oidc callback failed", "callback get client_secret", err)
			}
			return
		}
		defer zeroize(clientSecret)
		adapter, err := deps.Factory(ctx, cfg, clientSecret)
		if err != nil {
			recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, "", "discovery", http.StatusBadGateway)
			writeInternalErr(w, http.StatusBadGateway, "OIDC discovery failed", "callback discovery", err)
			return
		}
		userInfo, err := adapter.Exchange(ctx, code, rec.CodeVerifier, rec.RedirectURI)
		if err != nil {
			recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, "", "exchange", http.StatusUnauthorized)
			writeInternalErr(w, http.StatusUnauthorized, "IdP authentication failed", "callback exchange", err)
			return
		}
		if userInfo.Subject == "" {
			recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, "", "no subject", http.StatusUnauthorized)
			writeErr(w, http.StatusUnauthorized, "IdP did not return subject")
			return
		}
		user, err := deps.Identity.EnsureUserByExternalID(ctx, rec.TenantID, rec.IDPID, userInfo.Subject, userInfo.Email)
		if err != nil {
			recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, userInfo.Subject, "ensure_user", http.StatusInternalServerError)
			writeInternalErr(w, http.StatusInternalServerError, "oidc callback failed", "callback ensure_user", err)
			return
		}
		// H1:管理员手动 disabled 的用户即便 IdP 认证通过,亦不发会话凭证(治理与登录路径对齐)。
		if user.Status != "active" {
			recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, userInfo.Subject, "user disabled", http.StatusForbidden)
			writeErr(w, http.StatusForbidden, "user disabled")
			return
		}
		ttl := deps.ttl()
		token, jti, err := deps.Identity.IssueCredential(ctx, rec.TenantID, user.ID, userInfo.Groups, "", ttl)
		if err != nil {
			recordLoginFail(ctx, deps, rec.TenantID, rec.IDPID, userInfo.Subject, "issue_credential", http.StatusInternalServerError)
			writeInternalErr(w, http.StatusInternalServerError, "oidc callback failed", "callback issue_credential", err)
			return
		}
		// 成功审计(detail 仅 idp/sub/jti 标识,**绝不含 token**,与 Slice33e issueAdminToken 同口径)
		recordLoginSuccess(ctx, deps, rec.TenantID, rec.IDPID, userInfo.Subject, jti)
		respondCallback(w, r, rec, token, jti, ttl, user)
	}
}

// respondCallback:回调成功响应分两路(Slice37c):
//   - **浏览器(Accept 含 text/html)**:Set-Cookie sase_session + 302 → rec.ReturnTo
//     —— SPA 接入闭环;cookie httpOnly+Secure+SameSite=Lax 防 XSS/CSRF;
//   - **其它(API 客户端 / curl / 老测试)**:返 JSON(默认,向后兼容 Slice37a/b 测试 / 编程客户端)。
//
// 设计取舍:浏览器默认 Accept 含 `text/html`(W3C 约定),据此区分;
// 把 cookie+302 作"opt-in by browser"而非全局默认,保证编程客户端不被意外重定向破坏。
func respondCallback(w http.ResponseWriter, r *http.Request, rec StateRecord, token, jti string, ttl time.Duration, user identity.User) {
	if isBrowser(r) {
		// Cookie 路径:浏览器登录闭环。
		// SameSite=Lax:允许跨站 GET 顶层导航回本站时携带 cookie(IdP→callback 跳转后,cookie 已发);
		// Strict 会在跨站跳转后**不发送** cookie,登录后第一个请求拿不到会话,体验破坏。
		http.SetCookie(w, &http.Cookie{
			Name:     "sase_session",
			Value:    token,
			Path:     "/", // 全站可用(前端 SPA 不知道具体后端路径分布)
			MaxAge:   int(ttl.Seconds()),
			HttpOnly: true, // 防 JS 读(XSS 即便注入也拿不到 token)
			// Secure:生产 HTTPS 必;开发 HTTP 可用。
			// **运维约定(B3)**:反向代理必须**覆写**(而非透传)`X-Forwarded-Proto`,
			// 否则恶意客户端可伪造该头让其它用户的 cookie 在 HTTP 传输时被浏览器拒收(体验破坏,非安全漏洞)。
			Secure:   r.TLS != nil || strings.HasPrefix(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https"),
			SameSite: http.SameSiteLaxMode,
		})
		// 302 跳 SPA 入口(rec.ReturnTo 已在 LoginHandler 经 sanitizeReturnTo 校验为同源相对路径)
		http.Redirect(w, r, rec.ReturnTo, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(CallbackResponse{
		Token:     token,
		JTI:       jti,
		ExpiresIn: int(ttl.Seconds()),
		UserID:    user.ID,
		Email:     user.Email,
	})
}

// isBrowser 判定 Accept 是否显式含 text/html(浏览器默认行为)。
// 编程客户端(curl/API SDK)Accept 一般 */* 或 application/json,不含 text/html → 走 JSON 路径。
func isBrowser(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// recordLoginSuccess / recordLoginFail 写 OIDC 登录审计;Audit nil 时 noop(测试简化路径)。
// 用 context.WithoutCancel(req ctx) 取消独立(同 audit middleware 语义:客户端断开不丢审计);
// 比 context.Background() 保留了请求维度 trace / values。detail 经 sanitizeAuditDetail 剥换行/截断,
// 防 SIEM 解析污染。
func recordLoginSuccess(ctx context.Context, deps *HandlerDeps, tenantID, idpID, subject, jti string) {
	if deps.Audit == nil {
		return
	}
	_ = deps.Audit.Record(context.WithoutCancel(ctx), audit.Entry{
		TenantID:     tenantID,
		ActorSubject: subject,
		ActorRole:    "", // 登录者不是 admin
		Action:       "OIDC_LOGIN",
		Result:       http.StatusOK,
		Detail:       sanitizeAuditDetail("idp=" + idpID + " sub=" + subject + " jti=" + jti),
		Source:       audit.SourceAPI,
	})
}

func recordLoginFail(ctx context.Context, deps *HandlerDeps, tenantID, idpID, subject, reason string, code int) {
	if deps.Audit == nil {
		return
	}
	_ = deps.Audit.Record(context.WithoutCancel(ctx), audit.Entry{
		TenantID:     tenantID,
		ActorSubject: subject,
		ActorRole:    "",
		Action:       "OIDC_LOGIN_FAIL",
		Result:       code,
		Detail:       sanitizeAuditDetail("idp=" + idpID + " reason=" + reason),
		Source:       audit.SourceAPI,
	})
}

// sanitizeAuditDetail 剥换行/回车/NUL + 截断 256B(同 router.sanitizeDetail 形态;
// 此处独立拷贝避免循环依赖 oidc→admin/httpapi)。
func sanitizeAuditDetail(s string) string {
	r := []rune(s)
	for i, c := range r {
		if c == '\n' || c == '\r' || c == 0 {
			r[i] = ' '
		}
	}
	const maxLen = 256
	if len(r) > maxLen {
		r = r[:maxLen]
	}
	return string(r)
}

// sanitizeIDPError 让用户回显的 IdP error 参数限定在打印 ASCII + 短串(防 IdP 注入控制字符 / 超长串)。
func sanitizeIDPError(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f && c != '"' && c != '\\' {
			b = append(b, c)
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}

// zeroize 把字节切片擦零(IdP client_secret 解密后短窗内存,用完即弃;同 secret 模块约定)。
// 注:实际局限见 GenericFactory 文档——只擦字节切片副本,oauth2.Config 内 string 化副本仍存活,
// adapter 是请求作用域、随回应结束 GC,生命周期可控。
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
