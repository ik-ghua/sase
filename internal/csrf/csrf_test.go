package csrf

// Slice40 CSRF 中间件单元测试:验
//   ① GET 无 cookie → 200 + Set-Cookie csrf_token;后续 GET 有 cookie → 不重发;
//   ② POST 无 cookie → 403(ErrCookieMissing);
//   ③ POST cookie 非空但无 header → 403(ErrHeaderMissing);
//   ④ POST cookie != header → 403(ErrTokenMismatch);
//   ⑤ POST cookie == header + Origin 同源 → 通过;
//   ⑥ POST cookie == header + Origin 跨源 → 403(ErrOriginMismatch);
//   ⑦ POST cookie == header + 无 Origin/Referer → 403(ErrOriginMissing);
//   ⑧ AllowedOrigins 显式列了,Origin 不在列表 → 403(严格模式不走同源回退);
//   ⑨ 白名单 Skip 路径 → POST 无 cookie 也通过(设备/公开端点);
//   ⑩ PATCH/PUT/DELETE 同 POST 校验。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestCSRFGetIssuesCookie(t *testing.T) {
	mw := Middleware(Config{})(newTestHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET 应 200,得 %d", w.Code)
	}
	var got *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName {
			got = c
		}
	}
	if got == nil || got.Value == "" {
		t.Fatal("GET 无 cookie 应 Set-Cookie csrf_token")
	}
	if got.HttpOnly {
		t.Error("csrf cookie 不应 HttpOnly(JS 必须能读)")
	}
	if got.SameSite != http.SameSiteLaxMode {
		t.Error("csrf cookie 应 SameSite=Lax")
	}
	// 二次 GET 已带 cookie → 不重发(节省;不强求,这里只确保不破)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	req2.AddCookie(&http.Cookie{Name: CookieName, Value: got.Value})
	w2 := httptest.NewRecorder()
	mw.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("二次 GET 应 200,得 %d", w2.Code)
	}
	// 不应再 Set-Cookie(已有则跳过)
	for _, c := range w2.Result().Cookies() {
		if c.Name == CookieName {
			t.Error("二次 GET(已有 cookie)不应重发 Set-Cookie")
		}
	}
}

func TestCSRFPostMissingCookie(t *testing.T) {
	mw := Middleware(Config{})(newTestHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foo", strings.NewReader("{}"))
	req.Header.Set("X-CSRF-Token", "x")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST 无 cookie 应 403,得 %d", w.Code)
	}
}

func TestCSRFPostMissingHeader(t *testing.T) {
	mw := Middleware(Config{})(newTestHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foo", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "tok"})
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST 无 header 应 403,得 %d", w.Code)
	}
}

func TestCSRFPostMismatch(t *testing.T) {
	mw := Middleware(Config{})(newTestHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foo", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "tok-A"})
	req.Header.Set("X-CSRF-Token", "tok-B")
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST cookie≠header 应 403,得 %d", w.Code)
	}
}

func TestCSRFPostMatchSameOrigin(t *testing.T) {
	mw := Middleware(Config{})(newTestHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foo", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "tok-same"})
	req.Header.Set("X-CSRF-Token", "tok-same")
	req.Host = "admin.sase.example.com"
	req.Header.Set("Origin", "http://admin.sase.example.com")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST 同源应 200,得 %d", w.Code)
	}
}

func TestCSRFPostCrossOrigin(t *testing.T) {
	mw := Middleware(Config{})(newTestHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foo", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "tok-same"})
	req.Header.Set("X-CSRF-Token", "tok-same")
	req.Host = "admin.sase.example.com"
	req.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST 跨源应 403,得 %d", w.Code)
	}
}

func TestCSRFPostMissingOrigin(t *testing.T) {
	mw := Middleware(Config{})(newTestHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foo", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "tok-same"})
	req.Header.Set("X-CSRF-Token", "tok-same")
	// 无 Origin 无 Referer
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST 无 Origin/Referer 应 403,得 %d", w.Code)
	}
}

func TestCSRFAllowedOriginsStrict(t *testing.T) {
	// AllowedOrigins 显式 → 不走同源回退;只白名单内的 Origin 放行
	mw := Middleware(Config{AllowedOrigins: []string{"https://prod.sase.com"}})(newTestHandler())
	build := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/foo", strings.NewReader("{}"))
		r.AddCookie(&http.Cookie{Name: CookieName, Value: "tok"})
		r.Header.Set("X-CSRF-Token", "tok")
		r.Host = "prod.sase.com"
		r.Header.Set("Origin", origin)
		return r
	}
	// 白名单内 → OK
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, build("https://prod.sase.com"))
	if w.Code != http.StatusOK {
		t.Fatalf("白名单 origin 应 200,得 %d", w.Code)
	}
	// 不在白名单(虽同源 Host)→ 拒(严格模式)
	w2 := httptest.NewRecorder()
	mw.ServeHTTP(w2, build("http://prod.sase.com")) // 协议不同
	if w2.Code != http.StatusForbidden {
		t.Fatalf("严格模式下不在白名单(协议差)应 403,得 %d", w2.Code)
	}
}

func TestCSRFSkipPath(t *testing.T) {
	mw := Middleware(Config{Skip: map[string]bool{"/api/v1/enroll": true}})(newTestHandler())
	// 白名单 POST 无 cookie 也通过
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("白名单 POST 应 200,得 %d", w.Code)
	}
}

func TestCSRFAllMethodsChecked(t *testing.T) {
	mw := Middleware(Config{})(newTestHandler())
	for _, m := range []string{http.MethodPatch, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/api/v1/foo", strings.NewReader("{}"))
		// 无 cookie 无 header
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s 无 cookie 应 403,得 %d", m, w.Code)
		}
	}
}

func TestCSRFRefererFallback(t *testing.T) {
	// Origin 缺时回退 Referer
	mw := Middleware(Config{})(newTestHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foo", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "tok"})
	req.Header.Set("X-CSRF-Token", "tok")
	req.Host = "admin.sase.example.com"
	req.Header.Set("Referer", "http://admin.sase.example.com/path")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Referer 同源应 200,得 %d", w.Code)
	}
}
