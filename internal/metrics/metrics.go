// Package metrics 是数据面/控制面的可观测指标(Prometheus 暴露格式,供 VM/VictoriaMetrics 抓取)。
// 上承运维/部署 L2 3.4(可观测 + SLO)、L1 3.14。起步聚焦 PoP 接入面访问决策(SLO 与访问可见性)。
//
// 基数控制(运维 L2 3.10):标签仅用低基数维度(outcome),**不打 tenant 标签**——避免高基数;
// 租户维度的聚合/采样留后续(VM recording rules / 采样)。每个 Recorder 自带独立 registry(隔离/可测)。
package metrics

import (
	"net/http"
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
