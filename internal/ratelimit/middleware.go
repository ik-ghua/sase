package ratelimit

import (
	"net"
	"net/http"
)

// Wrap 用 limiter 按 key(r) 限流包裹 h:超限返回 429。limiter 为 nil 则不限流(便于测试/dev)。
func Wrap(limiter *Limiter, key func(*http.Request) string, h http.Handler) http.Handler {
	if limiter == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(key(r)) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ClientIP 取请求来源 IP(RemoteAddr 去端口)作限流键。不解析代理头(X-Forwarded-For 可信解析属网关职责)。
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
