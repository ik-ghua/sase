// Package metrics 是数据面/控制面的可观测指标(Prometheus 暴露格式,供 VM/VictoriaMetrics 抓取)。
// 上承运维/部署 L2 3.4(可观测 + SLO)、L1 3.14。起步聚焦 PoP 接入面访问决策(SLO 与访问可见性)。
//
// 基数控制(运维 L2 3.10):标签仅用低基数维度(outcome),**不打 tenant 标签**——避免高基数;
// 租户维度的聚合/采样留后续(VM recording rules / 采样)。每个 Recorder 自带独立 registry(隔离/可测)。
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// 访问结果(outcome 标签值,低基数)。
const (
	OutcomeAllow           = "allow"
	OutcomeInspect         = "inspect"
	OutcomeDeny            = "deny"
	OutcomeRevoked         = "revoked"
	OutcomeSWGBlocked      = "swg_blocked"
	OutcomeDLPBlocked      = "dlp_blocked"
	OutcomeUnauthenticated = "unauthenticated"
	OutcomeUpstreamError   = "upstream_error"
	OutcomeBadRequest      = "bad_request"
)

// Recorder 持 PoP 接入面指标。nil Recorder 的方法为 no-op(便于未接入时跑)。
type Recorder struct {
	reg      *prometheus.Registry
	access   *prometheus.CounterVec
	upstream prometheus.Histogram
}

// NewRecorder 构造带独立 registry 的指标记录器。
func NewRecorder() *Recorder {
	reg := prometheus.NewRegistry()
	access := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sase", Subsystem: "pop", Name: "access_total",
		Help: "PoP 接入面请求按结果计数",
	}, []string{"outcome"})
	upstream := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "sase", Subsystem: "pop", Name: "upstream_seconds",
		Help: "经反向通道到应用的往返耗时(秒)", Buckets: prometheus.DefBuckets,
	})
	reg.MustRegister(access, upstream)
	return &Recorder{reg: reg, access: access, upstream: upstream}
}

// Access 记一次接入结果。
func (r *Recorder) Access(outcome string) {
	if r != nil {
		r.access.WithLabelValues(outcome).Inc()
	}
}

// ObserveUpstream 记一次反向通道往返耗时。
func (r *Recorder) ObserveUpstream(d time.Duration) {
	if r != nil {
		r.upstream.Observe(d.Seconds())
	}
}

// Handler 返回 /metrics 处理器(Prometheus 暴露格式)。
func (r *Recorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// AccessValue 返回某 outcome 计数(测试/自检用;未观测过的 outcome 返回 0)。
func (r *Recorder) AccessValue(outcome string) float64 {
	c, err := r.access.GetMetricWithLabelValues(outcome)
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// ---- 控制面指标 ----

// 资源类型标签(低基数)。
const (
	ResourcePolicy     = "policy"
	ResourceRevocation = "revocation"
	ResourceSWG        = "swg"
	ResourceSite       = "site"
	ResourceFW         = "fw"
	ResourceDLP        = "dlp"
)

// ControlRecorder 持控制面指标(起步:xDS 配置下发计数,健康/版本 lag 可见性,运维 L2 3.10)。
type ControlRecorder struct {
	reg     *prometheus.Registry
	xdsPush *prometheus.CounterVec
}

// NewControlRecorder 构造带独立 registry 的控制面指标记录器。
func NewControlRecorder() *ControlRecorder {
	reg := prometheus.NewRegistry()
	xdsPush := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sase", Subsystem: "xds", Name: "pushes_total",
		Help: "xDS 资源装载/下发次数(按资源类型)",
	}, []string{"resource"})
	reg.MustRegister(xdsPush)
	return &ControlRecorder{reg: reg, xdsPush: xdsPush}
}

// XDSPush 记一次某类资源的装载/下发(nil 为 no-op)。
func (r *ControlRecorder) XDSPush(resource string) {
	if r != nil {
		r.xdsPush.WithLabelValues(resource).Inc()
	}
}

// Handler 返回 /metrics 处理器。
func (r *ControlRecorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// XDSPushValue 返回某资源类型的下发计数(测试/自检用)。
func (r *ControlRecorder) XDSPushValue(resource string) float64 {
	c, err := r.xdsPush.GetMetricWithLabelValues(resource)
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// APIRecorder 持管理面(Admin API)HTTP RED 指标(请求计数 + 时延直方图;运维 L2 3.4/3.10,L1 2.2 SLO 前置)。
// **基数控制**:route 用注册的 mux 路由模板(如 "GET /api/v1/tenants/{tid}/users",27 个,非真实路径)、
// **不打 tenant**;code 为 HTTP 状态码(有界 ~十几种)。nil 方法 no-op。
type APIRecorder struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewAPIRecorder 构造带独立 registry 的管理面 HTTP 指标记录器。
func NewAPIRecorder() *APIRecorder {
	reg := prometheus.NewRegistry()
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sase", Subsystem: "api", Name: "requests_total",
		Help: "管理面 HTTP 请求数(按方法/路由模板/状态码)",
	}, []string{"method", "route", "code"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "sase", Subsystem: "api", Name: "request_duration_seconds",
		Help:    "管理面 HTTP 请求时延秒(按方法/路由模板)",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})
	reg.MustRegister(requests, duration)
	return &APIRecorder{reg: reg, requests: requests, duration: duration}
}

// Observe 记一次 HTTP 请求(nil 为 no-op)。route=路由模板(低基数),code=HTTP 状态码,dur=耗时。
func (r *APIRecorder) Observe(method, route string, code int, dur time.Duration) {
	if r == nil {
		return
	}
	r.requests.WithLabelValues(method, route, strconv.Itoa(code)).Inc()
	r.duration.WithLabelValues(method, route).Observe(dur.Seconds())
}

// Handler 返回 /metrics 处理器。
func (r *APIRecorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// RequestCount 返回某(method,route,code)的计数(测试/自检用)。
func (r *APIRecorder) RequestCount(method, route string, code int) float64 {
	c, err := r.requests.GetMetricWithLabelValues(method, route, strconv.Itoa(code))
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// HTTPMiddleware 记录每个 HTTP 请求的 RED 指标(计数 + 时延)。routeOf(r) 返回低基数路由模板
// (调用方用 mux.Handler(r) 取注册的 pattern;空串→"other")。rec=nil 则透传(不启用)。
func HTTPMiddleware(rec *APIRecorder, routeOf func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if rec == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route := "other"
			if routeOf != nil {
				if rt := routeOf(r); rt != "" {
					route = rt
				}
			}
			sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(sw, r)
			rec.Observe(r.Method, route, sw.status, time.Since(start))
		})
	}
}

// statusRecorder 截获 HTTP 状态码(默认 200);仅记码,不动 body。
// ⚠️ 仅内嵌 ResponseWriter,不转发 http.Flusher/http.Hijacker——当前 Admin API 全是非流式
// JSON 端点,无影响;若日后加流式端点(SSE/审计实时推送/WebSocket),须在此补可选接口转发,
// 否则会静默吞掉 Flush/Hijack。
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}
