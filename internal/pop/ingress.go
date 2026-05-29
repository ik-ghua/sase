package pop

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/pop/pep"
	"github.com/ikuai8/sase/internal/revtunnel"
	"github.com/ikuai8/sase/internal/swg"
)

// BundleStore 持各租户当前激活的 PolicyBundle(由 xDS 订阅回调更新,PEP 读)。
type BundleStore struct {
	mu sync.RWMutex
	m  map[string]xdsv1.PolicyBundle
}

func NewBundleStore() *BundleStore { return &BundleStore{m: map[string]xdsv1.PolicyBundle{}} }

func (bs *BundleStore) Set(b xdsv1.PolicyBundle) {
	bs.mu.Lock()
	bs.m[b.TenantID] = b
	bs.mu.Unlock()
}

// Get 返回该租户激活 bundle 的副本与是否存在。
func (bs *BundleStore) Get(tenantID string) (xdsv1.PolicyBundle, bool) {
	bs.mu.RLock()
	b, ok := bs.m[tenantID]
	bs.mu.RUnlock()
	return b, ok
}

// Ingress 是 PoP 数据面接入面:验凭证 → 查吊销 → PEP 裁决 → inspect 导入 SWG → 放行则经反向通道转发。
type Ingress struct {
	verifier  *cred.Verifier
	bundles   *BundleStore
	revoked   *RevocationStore
	swgStore  *SWGStore
	swgEngine swg.Engine
	dlpStore  *DLPStore
	dlpEngine dlp.Engine
	dlpSink   dlp.FindingSink
	reg       *revtunnel.Registry
	rec       *metrics.Recorder
	now       func() time.Time
}

// NewIngress 构造接入面。swg*/dlp* 可为 nil(则 inspect 不过对应安全栈,等同放行);rec 可为 nil(no-op 指标)。
func NewIngress(v *cred.Verifier, bs *BundleStore, rs *RevocationStore, swgStore *SWGStore, swgEngine swg.Engine, reg *revtunnel.Registry, rec *metrics.Recorder) *Ingress {
	return &Ingress{verifier: v, bundles: bs, revoked: rs, swgStore: swgStore, swgEngine: swgEngine, reg: reg, rec: rec, now: time.Now}
}

// WithDLP 挂 CASB-DLP(inspect 流量内容检测;命中 block 拒、命中任意喂 sink/风险引擎)。返回自身便于链式。
func (ig *Ingress) WithDLP(store *DLPStore, engine dlp.Engine, sink dlp.FindingSink) *Ingress {
	ig.dlpStore, ig.dlpEngine, ig.dlpSink = store, engine, sink
	return ig
}

// Register 把 ZTNA 接入路由挂到 mux(可与 SD-WAN /site 共用接入面 server)。
func (ig *Ingress) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /access", ig.access)
}

// Handler 返回接入面 HTTP 处理器(独立 mux)。Agent 请求:GET /access?app=<id>,头 Authorization: Bearer <token>。
func (ig *Ingress) Handler() http.Handler {
	mux := http.NewServeMux()
	ig.Register(mux)
	return mux
}

func (ig *Ingress) access(w http.ResponseWriter, r *http.Request) {
	app := r.URL.Query().Get("app")
	if app == "" {
		ig.rec.Access(metrics.OutcomeBadRequest)
		http.Error(w, "missing app", http.StatusBadRequest)
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	// ① 验凭证(离线、fail-closed)
	token := bearer(r.Header.Get("Authorization"))
	if token == "" {
		ig.rec.Access(metrics.OutcomeUnauthenticated)
		http.Error(w, "missing credential", http.StatusUnauthorized)
		return
	}
	claims, err := ig.verifier.Verify(token, ig.now())
	if err != nil {
		// 过期/签名/格式均 401(不泄漏细节)
		ig.rec.Access(metrics.OutcomeUnauthenticated)
		http.Error(w, "invalid credential: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// ①' 查吊销表:已撤销凭证立即拒(秒级失效;短 TTL 为不可达兜底,ZTNA 硬化 L2 3.4)
	if ig.revoked != nil && ig.revoked.IsRevoked(claims.TenantID, claims.JTI) {
		ig.rec.Access(metrics.OutcomeRevoked)
		log.Printf("[pop] REVOKED tenant=%s sub=%s jti=%s", claims.TenantID, claims.Subject, claims.JTI)
		http.Error(w, "credential revoked", http.StatusUnauthorized)
		return
	}

	// ② PEP 裁决(默认拒绝;权威在 PoP)
	bundle, ok := ig.bundles.Get(claims.TenantID)
	var bp *xdsv1.PolicyBundle
	if ok {
		bp = &bundle
	}
	effect := pep.Decide(bp, claims, app, "connect")
	if effect == xdsv1.EffectDeny {
		ig.rec.Access(metrics.OutcomeDeny)
		log.Printf("[pop] DENY tenant=%s sub=%s app=%s", claims.TenantID, claims.Subject, app)
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	// ②' inspect:导入安全栈 SWG(URL 过滤),命中阻断即拒(安全栈 L2:inspect=放行但导入安全栈)。
	// 注:SWG 缺失(engine nil)对 inspect 流量 fail-open(退化为仅放行)——与 PEP 默认拒绝(②)的
	// fail-close 不对称是有意的:该拒的已在 ② 拦下,SWG 只是 inspect 之上的附加过滤,缺失不扩大访问。
	if effect == xdsv1.EffectInspect && ig.swgEngine != nil {
		d := ig.swgEngine.Evaluate(ig.swgStore.Get(claims.TenantID), swg.Request{Host: app, Path: path})
		if !d.Allow {
			ig.rec.Access(metrics.OutcomeSWGBlocked)
			log.Printf("[pop] SWG BLOCK tenant=%s app=%s path=%s: %s", claims.TenantID, app, path, d.Reason)
			http.Error(w, "blocked by SWG: "+d.Reason, http.StatusForbidden)
			return
		}
	}
	// ②'' inspect:导入 CASB-DLP(内容敏感数据检测)。命中任意规则 → 喂风险引擎(sink);命中 block → 拒。
	// 内容源 stand-in:当前数据路径无 body,扫描可见的 URL path(生产经 Envoy ext_proc 取 body)。
	// fail-open 同 SWG:DLP 缺失/引擎缺陷不扩大访问、也不误阻断(该拒的已在 ② 拦下)。
	if effect == xdsv1.EffectInspect && ig.dlpEngine != nil && ig.dlpStore != nil {
		res := ig.dlpEngine.Evaluate(ig.dlpStore.Get(claims.TenantID), path)
		for _, f := range res.Findings {
			if ig.dlpSink != nil {
				ig.dlpSink.Report(claims.TenantID, claims.Subject, claims.JTI, f) // DLP 命中 → 风险引擎(带会话 jti)
			}
		}
		if res.Block {
			ig.rec.Access(metrics.OutcomeDLPBlocked)
			log.Printf("[pop] DLP BLOCK tenant=%s sub=%s app=%s (%d 命中)", claims.TenantID, claims.Subject, app, len(res.Findings))
			http.Error(w, "blocked by DLP", http.StatusForbidden)
			return
		}
	}
	log.Printf("[pop] %s tenant=%s sub=%s app=%s path=%s", strings.ToUpper(effect), claims.TenantID, claims.Subject, app, path)

	// ③ 经反向通道转发到应用
	start := ig.now()
	resp, err := ig.reg.RoundTrip(claims.TenantID, app, revtunnel.Request{Method: "GET", Path: path})
	if err != nil {
		ig.rec.Access(metrics.OutcomeUpstreamError)
		http.Error(w, "upstream unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	ig.rec.ObserveUpstream(ig.now().Sub(start))
	ig.rec.Access(effect) // OutcomeAllow / OutcomeInspect(effect 值与 outcome 常量一致)
	if effect == xdsv1.EffectInspect {
		w.Header().Set("X-Sase-Inspect", "1")
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write([]byte(resp.Body))
}

func bearer(h string) string {
	const p = "Bearer "
	if strings.HasPrefix(h, p) {
		return strings.TrimPrefix(h, p)
	}
	return ""
}
