package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecorderAccess(t *testing.T) {
	r := NewRecorder()
	r.Access(OutcomeDeny)
	r.Access(OutcomeDeny)
	r.Access(OutcomeAllow)
	r.ObserveUpstream(5 * time.Millisecond)

	if got := r.AccessValue(OutcomeDeny); got != 2 {
		t.Errorf("deny 应 2,得 %v", got)
	}
	if got := r.AccessValue(OutcomeAllow); got != 1 {
		t.Errorf("allow 应 1,得 %v", got)
	}

	// /metrics 暴露
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "sase_pop_access_total") || !strings.Contains(body, `outcome="deny"`) {
		t.Fatalf("/metrics 应含 access_total 与 deny 序列,得:\n%s", body)
	}
	if !strings.Contains(body, "sase_pop_upstream_seconds") {
		t.Error("/metrics 应含 upstream_seconds 直方图")
	}
}

func TestNilRecorderNoop(_ *testing.T) {
	var r *Recorder                // nil
	r.Access(OutcomeDeny)          // 不应 panic
	r.ObserveUpstream(time.Second) // 不应 panic
}

// Slice60:APIRecorder 计数按 method/route/code 聚合。
func TestAPIRecorderObserve(t *testing.T) {
	rec := NewAPIRecorder()
	rt1 := "GET /api/v1/platform/tenants"
	rec.Observe("GET", rt1, 200, 5*time.Millisecond)
	rec.Observe("GET", rt1, 200, 3*time.Millisecond)
	rec.Observe("POST", "POST /api/v1/platform/pop-nodes", 403, time.Millisecond)
	if got := rec.RequestCount("GET", rt1, 200); got != 2 {
		t.Fatalf("GET 200 应 2,得 %v", got)
	}
	if got := rec.RequestCount("POST", "POST /api/v1/platform/pop-nodes", 403); got != 1 {
		t.Fatalf("POST 403 应 1,得 %v", got)
	}
	if got := rec.RequestCount("GET", rt1, 500); got != 0 {
		t.Fatalf("未发生的 500 应 0,得 %v", got)
	}
	var nilRec *APIRecorder
	nilRec.Observe("GET", rt1, 200, time.Second) // nil 不应 panic
}

// Slice60:HTTPMiddleware 经 routeOf 模板化 route + 截获状态码 + "other" 兜底 + nil 透传。
func TestHTTPMiddleware(t *testing.T) {
	rec := NewAPIRecorder()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/boom" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	routeOf := func(r *http.Request) string {
		if r.URL.Path == "/api/v1/tenants/abc/users" {
			return "GET /api/v1/tenants/{tid}/users" // 模拟 mux 模板
		}
		return "" // 未匹配 → 中间件兜底 "other"
	}
	h := HTTPMiddleware(rec, routeOf)(next)
	do := func(method, path string) {
		r := httptest.NewRequest(method, path, nil)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	do("GET", "/api/v1/tenants/abc/users") // 模板路由,200
	do("GET", "/api/v1/boom")              // routeOf 空 → "other",500

	if got := rec.RequestCount("GET", "GET /api/v1/tenants/{tid}/users", 200); got != 1 {
		t.Fatalf("模板路由 GET 200 应 1,得 %v", got)
	}
	if got := rec.RequestCount("GET", "other", 500); got != 1 {
		t.Fatalf("未匹配路由 other 500 应 1,得 %v", got)
	}

	// nil recorder:透传,不记
	rr := httptest.NewRecorder()
	HTTPMiddleware(nil, routeOf)(next).ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("nil recorder 应透传,得 %d", rr.Code)
	}
}

// Slice60 待后续②:设备面 recorder 用 sase_device_* 指标名区分管理面 sase_api_*。
func TestDeviceRecorderMetricNames(t *testing.T) {
	dev := NewDeviceRecorder()
	dev.Observe("POST", "POST /api/v1/renew", 200, 2*time.Millisecond)
	rr := httptest.NewRecorder()
	dev.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "sase_device_requests_total") {
		t.Fatalf("设备面 /metrics 应含 sase_device_requests_total,得:\n%s", body)
	}
	if !strings.Contains(body, "sase_device_request_duration_seconds") {
		t.Fatalf("设备面 /metrics 应含 sase_device_request_duration_seconds,得:\n%s", body)
	}
	// 与管理面区分:设备面 registry 不应出现 sase_api_* 序列。
	if strings.Contains(body, "sase_api_requests_total") {
		t.Fatalf("设备面 /metrics 不应含管理面 sase_api_*(指标名应区分两面),得:\n%s", body)
	}
}

// Slice60 待后续②:设备面中间件经真实 http.ServeMux 模板化 route(镜像 main.go 的 devMux.Handler(r))
// + 截获被拒请求(401/403)的状态码 + 计数。
func TestDeviceHTTPMiddleware(t *testing.T) {
	dev := NewDeviceRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/renew", func(w http.ResponseWriter, _ *http.Request) {
		// 模拟设备面:无客户端证书 → 401(被拒请求也须计量,故中间件包最外层)。
		w.WriteHeader(http.StatusUnauthorized)
	})
	// routeOf 取注册的 mux 路由模板(与 main.go 一致);未匹配的请求模板为空 → 中间件兜底 "other"。
	routeOf := func(r *http.Request) string { _, pat := mux.Handler(r); return pat }
	h := HTTPMiddleware(dev, routeOf)(mux)

	// 命中模板路由(被拒 401 仍计量)。
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/v1/renew", nil))
	if got := dev.RequestCount("POST", "POST /api/v1/renew", 401); got != 1 {
		t.Fatalf("设备面 /renew 401 应 1(被拒请求须计量),得 %v", got)
	}

	// 未注册路径:ServeMux 返 404 + 空模板 → route 兜底 "other"。
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/unknown", nil))
	if got := dev.RequestCount("GET", "other", 404); got != 1 {
		t.Fatalf("未注册路径应记为 other 404,得 %v", got)
	}
}

// Slice67:隧道丢包按 reason 计数 + nil no-op。
func TestTunnelDrop(t *testing.T) {
	r := NewRecorder()
	r.TunnelDrop("no_route")
	r.TunnelDrop("no_route")
	r.TunnelDrop("firewall_deny")
	if got := r.TunnelDropValue("no_route"); got != 2 {
		t.Fatalf("no_route 应 2,得 %v", got)
	}
	if got := r.TunnelDropValue("firewall_deny"); got != 1 {
		t.Fatalf("firewall_deny 应 1,得 %v", got)
	}
	if got := r.TunnelDropValue("never"); got != 0 {
		t.Fatalf("未发生 reason 应 0,得 %v", got)
	}
	var nilRec *Recorder
	nilRec.TunnelDrop("x") // 不应 panic
}

// Slice67:遥测丢弃 CounterFunc 经 /metrics 暴露 atomic 当前值(scrape 时读)。
func TestRegisterTelemetryDrops(t *testing.T) {
	r := NewRecorder()
	var enq, snd int64
	r.RegisterTelemetryDrops(func() int64 { return enq }, func() int64 { return snd })
	enq, snd = 3, 5 // 注册后变化,scrape 时反映
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "sase_pop_telemetry_enqueue_dropped_total 3") {
		t.Fatalf("/metrics 应含 enqueue dropped=3,得:\n%s", body)
	}
	if !strings.Contains(body, "sase_pop_telemetry_send_dropped_total 5") {
		t.Fatalf("/metrics 应含 send dropped=5,得:\n%s", body)
	}
	var nilRec *Recorder
	nilRec.RegisterTelemetryDrops(nil, nil) // 不应 panic
}
