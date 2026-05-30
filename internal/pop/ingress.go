package pop

import (
	"io"
	"log"
	"net/http"
	"net/textproto"
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

// maxIngressBody 是单次反向请求体的缓冲上限(本刀 body 整包缓冲,非流式)。
// 防恶意/超大上传撑爆 PoP 内存;超限 → 413。大文件/流式上传留下刀(io.Copy 流式隧道)。
const maxIngressBody = 16 << 20 // 16 MiB

// hopByHopHeaders 是 RFC 7230 §6.1 的静态逐跳头 + 反向通道控制头,转发上游前必须剥除:
//   - 逐跳头(Connection/Keep-Alive/...)只在单段连接有意义,跨段透传会破坏语义。
//   - Authorization 是 SASE 会话凭证(app 层认证),绝不能泄漏给内网上游应用。
//   - X-Sase-* 是 PoP↔Agent 控制头,不进上游。
//
// 此外 RFC 7230 §6.1 还有动态逐跳头:Connection 头值点名的字段(如 Connection: X-Foo 里的 X-Foo)
// 也是本段连接专用的逐跳头,由 connectionHopByHop 逐请求/响应解析(不进本全局 map)。
// 用 textproto.CanonicalMIMEHeaderKey 归一化比较(http.Header 键已是 canonical)。
var hopByHopHeaders = func() map[string]bool {
	keys := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"Authorization", // SASE 凭证,不透传给上游
	}
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[textproto.CanonicalMIMEHeaderKey(k)] = true
	}
	return m
}()

// connectionHopByHop 解析 src 里的 Connection 头(RFC 7230 §6.1):其值是逗号分隔的字段名列表,
// 点名的字段在本段连接里同样是逐跳头(动态逐跳头),跨段透传会破坏语义。返回 canonical 化的字段名集合
// (本次请求/响应专用的局部 set,不污染全局 hopByHopHeaders)。Connection 头本身已在 hopByHopHeaders 静态剥除。
// 注:故意不把 "Close"/"Keep-Alive" 等连接选项 token 当作字段名特殊处理——它们 canonical 化后不会命中真实业务头,
// 误加入剥除集也无害(没有名为 Close 的业务头会被透传)。
func connectionHopByHop(src http.Header) map[string]bool {
	vals, ok := src["Connection"]
	if !ok {
		return nil
	}
	var set map[string]bool
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if set == nil {
				set = make(map[string]bool)
			}
			set[textproto.CanonicalMIMEHeaderKey(tok)] = true
		}
	}
	return set
}

// filterForwardHeaders 复制 src 头到新 http.Header,剥除逐跳头与 SASE 控制头(Authorization / X-Sase-*)。
// 含 RFC 7230 §6.1 动态逐跳头:Connection 头值点名的字段一并剥除。
// 返回的是新 map,不修改入参(并发安全:不与 net/http 共享底层 map)。
func filterForwardHeaders(src http.Header) http.Header {
	dynHop := connectionHopByHop(src)
	out := make(http.Header, len(src))
	for k, vals := range src {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if hopByHopHeaders[ck] || dynHop[ck] || strings.HasPrefix(ck, "X-Sase-") {
			continue
		}
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[ck] = cp
	}
	return out
}

// writeResponse 把反向通道返回的完整响应(状态码/头/体)写回客户端。优先用 BodyBytes(全 HTTP 路径),
// 回退 Body(旧文本路径)。剥除上游响应里的逐跳头(避免破坏 PoP↔Agent 这段连接的语义)。
func writeResponse(w http.ResponseWriter, resp revtunnel.Response, inspect bool) {
	dynHop := connectionHopByHop(resp.Header)
	for k, vals := range resp.Header {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if hopByHopHeaders[ck] || dynHop[ck] {
			continue
		}
		// Content-Length 由 net/http 据实际写入字节重算,避免与缓冲体长度不一致;不透传上游声明值。
		if ck == "Content-Length" {
			continue
		}
		for _, v := range vals {
			w.Header().Add(ck, v)
		}
	}
	if inspect {
		w.Header().Set("X-Sase-Inspect", "1")
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if len(resp.BodyBytes) > 0 {
		_, _ = w.Write(resp.BodyBytes)
		return
	}
	_, _ = w.Write([]byte(resp.Body))
}

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
// 注:不限定方法(去掉旧的 "GET /access"),让 /access 承载任意 HTTP 方法(GET/POST/PUT/...);
// 客户端原始方法/头/体经反向通道透传到内网上游应用。
func (ig *Ingress) Register(mux *http.ServeMux) {
	mux.HandleFunc("/access", ig.access)
}

// Handler 返回接入面 HTTP 处理器(独立 mux)。Agent 请求:<任意方法> /access?app=<id>&path=<p>,
// 头 Authorization: Bearer <token>;请求头(除 Authorization/逐跳头)与请求体透传到内网上游。
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

	// 读请求体(限额缓冲,本刀非流式)——放在 deny 之后,被拒请求不缓冲;放在 inspect 之前,使 DLP 可扫 body。
	body, ok2 := ig.readBody(w, r)
	if !ok2 {
		return // readBody 已写 413/400 并记指标
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
	// 全 HTTP 模型下扫描 path + 请求体(本刀缓冲整包;生产经 Envoy ext_proc 取流式 body)。
	// fail-open 同 SWG:DLP 缺失/引擎缺陷不扩大访问、也不误阻断(该拒的已在 ② 拦下)。
	if effect == xdsv1.EffectInspect && ig.dlpEngine != nil && ig.dlpStore != nil {
		content := path
		if len(body) > 0 {
			content = path + "\n" + string(body)
		}
		res := ig.dlpEngine.EvaluateCompiled(ig.dlpStore.Get(claims.TenantID), content)
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
	log.Printf("[pop] %s tenant=%s sub=%s app=%s method=%s path=%s", strings.ToUpper(effect), claims.TenantID, claims.Subject, app, r.Method, path)

	// ③ 经反向通道转发到应用:透传客户端原始方法 + 头(剥 Authorization/逐跳头)+ 体。
	start := ig.now()
	resp, err := ig.reg.RoundTrip(claims.TenantID, app, revtunnel.Request{
		Method:     r.Method,
		Path:       path,
		HeaderFull: filterForwardHeaders(r.Header),
		Body:       body,
	})
	if err != nil {
		ig.rec.Access(metrics.OutcomeUpstreamError)
		http.Error(w, "upstream unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	ig.rec.ObserveUpstream(ig.now().Sub(start))
	ig.rec.Access(effect) // OutcomeAllow / OutcomeInspect(effect 值与 outcome 常量一致)
	// 写回上游完整响应(状态码 + 头 + 体);inspect 流量打 X-Sase-Inspect。
	writeResponse(w, resp, effect == xdsv1.EffectInspect)
}

// readBody 读请求体到内存(限额 maxIngressBody)。超限 → 413 并记指标,返回 ok=false;读错 → 400。
// 空 body(GET 等)返回 (nil, true)。本刀整包缓冲,非流式。
func (ig *Ingress) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}
	// limit+1 探测是否超限:读满 limit+1 字节即判定 over,避免无界读。
	limited := io.LimitReader(r.Body, maxIngressBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		ig.rec.Access(metrics.OutcomeBadRequest)
		http.Error(w, "read request body", http.StatusBadRequest)
		return nil, false
	}
	if int64(len(body)) > maxIngressBody {
		ig.rec.Access(metrics.OutcomeBadRequest)
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return body, true
}

func bearer(h string) string {
	const p = "Bearer "
	if strings.HasPrefix(h, p) {
		return strings.TrimPrefix(h, p)
	}
	return ""
}
