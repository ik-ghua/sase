package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrap429AfterBurst(t *testing.T) {
	l := New(0, 1) // 0 补充、突发 1:首个放行,之后一律限流
	h := Wrap(l, ClientIP,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	do := func() int {
		r := httptest.NewRequest("POST", "/api/v1/enroll", nil)
		r.RemoteAddr = "10.0.0.1:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do(); c != 200 {
		t.Fatalf("首个请求应放行 200,得 %d", c)
	}
	if c := do(); c != http.StatusTooManyRequests {
		t.Fatalf("超限应 429,得 %d", c)
	}
}

func TestWrapNilLimiterPassthrough(t *testing.T) {
	called := false
	h := Wrap(nil, ClientIP, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	r := httptest.NewRequest("POST", "/x", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Fatal("nil 限流器应直通不拦截")
	}
}
