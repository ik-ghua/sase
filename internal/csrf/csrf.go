// Package csrf 是管理面 CSRF 防御中间件(Slice40,前端启动前置)。
//
// **机制:Double-Submit Cookie + Origin/Referer 同源校验(纵深)**(Slice37c 评审 + 前端讨论决策)。
//
// 工作原理:
//   - 后端首次 GET 任意 Admin API 路径 → Set-Cookie `csrf_token`(非 HttpOnly,JS 可读);
//   - 客户端 POST/PATCH/PUT/DELETE 把 cookie 值复制到 header `X-CSRF-Token`;
//   - 中间件校验:① cookie 非空 + == header(主防线;攻击者跨站无法读 cookie 无法构造正确 header);
//     ② Origin/Referer 同源(纵深 2;防 cookie 取走且 header 任意伪造的精巧攻击)。
//
// 设计取舍:
//   - **stateless**(无 session 存储);
//   - cookie 非 HttpOnly(JS 必须能读;trade-off:XSS 时攻击者能读 cookie 与 token,但配合
//     `sase_session` cookie 是 HttpOnly,会话 token 仍不可读);
//   - GET 不校验(读无副作用);
//   - 设备/公开端点白名单(`/enroll` 设备非浏览器无 cookie;`/idp/*` 是 IdP 跳转/回调 GET;`/trust/pubkey` GET)。
package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	// CookieName 是 CSRF token cookie 名;JS 可读(非 HttpOnly)。
	CookieName = "csrf_token"
	// HeaderName 是客户端复制 cookie 值后回发的 header 名。
	HeaderName = "X-CSRF-Token"
	// tokenLen 是 token 随机字节长度(b64url 编码后约 43 字符)。
	tokenLen = 32
)

// 错误 sentinel。
var (
	ErrCookieMissing  = errors.New("csrf: 缺 cookie")
	ErrHeaderMissing  = errors.New("csrf: 缺 header")
	ErrTokenMismatch  = errors.New("csrf: cookie 与 header 不一致")
	ErrOriginMissing  = errors.New("csrf: 缺 Origin/Referer")
	ErrOriginMismatch = errors.New("csrf: Origin/Referer 跨源")
)

// Config 配置 CSRF 中间件。
type Config struct {
	// AllowedOrigins 显式允许的 origin 列表(scheme://host[:port]);空 → 走 same-host(从请求 Host 推断同源)
	// 推荐生产显式列出,开发期可空走自动推断。
	AllowedOrigins []string
	// Skip 路径白名单(精确匹配 r.URL.Path);如 `/api/v1/enroll`(设备非浏览器)、`/api/v1/idp/login`(GET 也豁免颁发 cookie 的开销,虽然 GET 本就不校验)。
	Skip map[string]bool
	// SecureHint 若 true,Set-Cookie 设 Secure(生产 HTTPS);若 false,看 r.TLS / X-Forwarded-Proto 自动判。
	SecureHint bool
}

// generateToken 生成 32B 随机 token,b64url 编码(同 Slice37c sanitizeReturnTo 风格)。
func generateToken() (string, error) {
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Middleware 返回包裹 Admin API mux 的 http.Handler。
//
// 行为:
//   - GET/HEAD/OPTIONS:不校验;若 cookie 缺,**生成并 Set-Cookie**(让前端首个 GET 即拿到 token);
//   - POST/PATCH/PUT/DELETE:**两道校验**——cookie 非空 + == header,且 Origin/Referer 同源;
//   - Skip 路径(`/enroll` 等):跳过校验(GET 也不颁发 cookie,无意义)。
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.Skip == nil {
		cfg.Skip = map[string]bool{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 白名单(精确路径匹配)
			if cfg.Skip[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			method := r.Method
			// 写方法:校验 cookie+header + Origin
			if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut || method == http.MethodDelete {
				if err := verifyDoubleSubmit(r); err != nil {
					log.Printf("[csrf] %s %s rejected: %v", r.Method, r.URL.Path, err)
					http.Error(w, "csrf check failed", http.StatusForbidden)
					return
				}
				if err := verifyOrigin(r, cfg.AllowedOrigins); err != nil {
					log.Printf("[csrf] %s %s origin rejected: %v", r.Method, r.URL.Path, err)
					http.Error(w, "csrf origin check failed", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// 安全方法(GET/HEAD/OPTIONS):若 cookie 缺则颁发,然后放行
			if _, err := r.Cookie(CookieName); err != nil {
				token, gerr := generateToken()
				if gerr == nil {
					http.SetCookie(w, &http.Cookie{
						Name:     CookieName,
						Value:    token,
						Path:     "/",
						HttpOnly: false, // JS 必须能读以复制到 header
						Secure:   shouldSecure(r, cfg.SecureHint),
						SameSite: http.SameSiteLaxMode,
					})
				} else {
					log.Printf("[csrf] generateToken failed: %v", gerr)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// verifyDoubleSubmit:cookie 非空 + == header(constant-time 比较防 timing oracle)。
func verifyDoubleSubmit(r *http.Request) error {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return ErrCookieMissing
	}
	h := r.Header.Get(HeaderName)
	if h == "" {
		return ErrHeaderMissing
	}
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(h)) != 1 {
		return ErrTokenMismatch
	}
	return nil
}

// verifyOrigin:Origin 或 Referer 至少有一个,且 host 在白名单或与请求 Host 同源。
func verifyOrigin(r *http.Request, allowed []string) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// 回退 Referer(浏览器对部分跨域请求只发 Referer)
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return ErrOriginMissing
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return ErrOriginMismatch
	}
	originURL := u.Scheme + "://" + u.Host
	// 显式白名单
	for _, a := range allowed {
		if a == originURL {
			return nil
		}
	}
	// 同源回退:取请求 Host 与 scheme(经 r.TLS / X-Forwarded-Proto)
	reqScheme := "http"
	if r.TLS != nil || strings.HasPrefix(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https") {
		reqScheme = "https"
	}
	// 若 AllowedOrigins 显式配了,**不**走同源回退(生产严格);未配则走同源(dev 便利)
	if len(allowed) > 0 {
		return ErrOriginMismatch
	}
	if u.Host == r.Host && u.Scheme == reqScheme {
		return nil
	}
	return ErrOriginMismatch
}

// shouldSecure:r.TLS 非空 或 X-Forwarded-Proto=https → cookie Secure 标志开;
// 否则按 hint 走(开发期通常 false,生产 true)。
func shouldSecure(r *http.Request, hint bool) bool {
	if r.TLS != nil {
		return true
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	return hint
}
