package pop

import (
	"log"
	"net/http"
	"time"

	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/revtunnel"
)

// SiteIngress 是 PoP 的 SD-WAN 站点 overlay 入口:CPE 把发往对端站点的流量送到这里,PoP 经反向通道
// 路由到目标站点的 CPE(L1 3.8 租户路由域内互通)。复用 revtunnel.Registry(站点以 site_key 注册为连接器)。
//
// 起步:同租户站点默认互通(路由域内),不做分段裁决——站点间分段属 FWaaS(P4),后续刀。
// CPE 身份用会话凭证(ZTP 签发,Subject=site_key);设备级 mTLS 由 server 的 gRPC/HTTPS creds 保证。
type SiteIngress struct {
	verifier *cred.Verifier
	reg      *revtunnel.Registry
	rec      *metrics.Recorder
	now      func() time.Time
}

// NewSiteIngress 构造站点 overlay 入口。
func NewSiteIngress(v *cred.Verifier, reg *revtunnel.Registry, rec *metrics.Recorder) *SiteIngress {
	return &SiteIngress{verifier: v, reg: reg, rec: rec, now: time.Now}
}

// Register 把 /site 路由挂到 mux(与 ZTNA /access 共用接入面 server)。
func (si *SiteIngress) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /site", si.send)
}

// Handler 返回独立 mux(便于单独挂载/测试)。
func (si *SiteIngress) Handler() http.Handler {
	mux := http.NewServeMux()
	si.Register(mux)
	return mux
}

// send 处理 CPE 发往对端站点的流量:GET /site?dest=<site_key>&path=<p>,头 Authorization: Bearer <cpe-cred>。
func (si *SiteIngress) send(w http.ResponseWriter, r *http.Request) {
	dest := r.URL.Query().Get("dest")
	if dest == "" {
		si.rec.Access(metrics.OutcomeBadRequest)
		http.Error(w, "missing dest site", http.StatusBadRequest)
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}
	token := bearer(r.Header.Get("Authorization"))
	if token == "" {
		si.rec.Access(metrics.OutcomeUnauthenticated)
		http.Error(w, "missing credential", http.StatusUnauthorized)
		return
	}
	claims, err := si.verifier.Verify(token, si.now())
	if err != nil {
		si.rec.Access(metrics.OutcomeUnauthenticated)
		http.Error(w, "invalid credential", http.StatusUnauthorized)
		return
	}

	// 同租户路由域内互通:经反向通道路由到目标站点的 CPE
	start := si.now()
	resp, err := si.reg.RoundTrip(claims.TenantID, dest, revtunnel.Request{Method: "GET", Path: path})
	if err != nil {
		si.rec.Access(metrics.OutcomeUpstreamError)
		http.Error(w, "dest site unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	si.rec.ObserveUpstream(si.now().Sub(start))
	si.rec.Access(metrics.OutcomeAllow)
	log.Printf("[pop] SITE tenant=%s src=%s → dest=%s path=%s", claims.TenantID, claims.Subject, dest, path)
	w.WriteHeader(resp.Status)
	_, _ = w.Write([]byte(resp.Body))
}
