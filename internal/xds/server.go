// Package xds 是控制面单元②(配置分发):基于 go-control-plane 的 ADS + 增量(Delta)下发自定义资源。
//
// 实现 xDS server L2:3.1(自定义资源 PolicyBundleResource / RevocationList,按 tenant/<id> 命名)、
// 3.2(ADS+Delta)、3.3(资源由 DB 只读派生)、3.4(按租户订阅惰性读)、3.5(LISTEN/NOTIFY 触发)、
// 3.7(撤销走独立流避队头阻塞:MuxCache 按 type URL 路由到独立 LinearCache,PoP 各开一条 Delta 流)、
// 3.9(只读 app_ro;mTLS 由 cmd 的 gRPC creds 提供)、3.11(go-control-plane)。
//
// 自定义资源用 LinearCache(单 type、按资源名键控);两类资源各一个 LinearCache,MuxCache 按 type URL 路由。
// RLS 约束下不能枚举租户,故按"订阅/通知"事件惰性读该租户资源入对应缓存(单租户 InTxRO)。
package xds

import (
	"context"
	"errors"
	"log"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xdspb "github.com/ikuai8/sase/api/proto/sase/xds/v1"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/metrics"
)

var (
	policyTypeURL = xdspb.TypeURL()
	revTypeURL    = xdspb.RevocationTypeURL()
	swgTypeURL    = xdspb.SWGTypeURL()
	siteTypeURL   = xdspb.SiteConfigTypeURL()
	fwTypeURL     = xdspb.FWTypeURL()
	dlpTypeURL    = xdspb.DLPTypeURL()
)

// Server 是 xDS 下发服务:策略/撤销/SWG 各一 LinearCache,MuxCache 按 type URL 路由,惰性从 DB 读入。
type Server struct {
	ctx         context.Context
	store       data.Store
	policyCache *cachev3.LinearCache
	revCache    *cachev3.LinearCache
	swgCache    *cachev3.LinearCache
	siteCache   *cachev3.LinearCache
	fwCache     *cachev3.LinearCache
	dlpCache    *cachev3.LinearCache
	mux         *cachev3.MuxCache
	rec         *metrics.ControlRecorder

	// strictSubAuth:订阅授权严格模式(SASE_XDS_REQUIRE_CERT_SCOPE=1)。开启时 role-less / 无证书
	// 订阅被拒(生产硬化);关闭时放行(dev 兼容)。role:device 跨租户拒不受此开关影响(始终生效)。
	strictSubAuth bool

	// streams:streamID → *streamAuth。onDeltaStreamOpen 据证书登记、onDeltaStreamClosed 删除。
	streams sync.Map

	// refMu 守 tenantRefs 与各 streamAuth.tenants:某租户的活跃订阅流数;归零 → 从对账集移除 + 驱逐缓存。
	// 取代旧 subscribed sync.Map(单调增长、断连不收缩):现按订阅生命周期增减,止住膨胀 + ReconcileAll 不对死租户空转。
	refMu      sync.Mutex
	tenantRefs map[string]int
}

// SetMetrics 注入控制面指标记录器(可选;nil 为 no-op)。
func (s *Server) SetMetrics(rec *metrics.ControlRecorder) { s.rec = rec }

// SetStrictSubAuth 开启订阅授权严格模式(role-less / 无证书订阅被拒);由 cmd 经 env 门控装配。
func (s *Server) SetStrictSubAuth(strict bool) { s.strictSubAuth = strict }

// NewServer 构造 xDS server。ctx 为服务生命周期。
func NewServer(ctx context.Context, store data.Store) *Server {
	policyCache := cachev3.NewLinearCache(policyTypeURL, cachev3.WithLogger(gcpLogger{}))
	revCache := cachev3.NewLinearCache(revTypeURL, cachev3.WithLogger(gcpLogger{}))
	swgCache := cachev3.NewLinearCache(swgTypeURL, cachev3.WithLogger(gcpLogger{}))
	siteCache := cachev3.NewLinearCache(siteTypeURL, cachev3.WithLogger(gcpLogger{}))
	fwCache := cachev3.NewLinearCache(fwTypeURL, cachev3.WithLogger(gcpLogger{}))
	dlpCache := cachev3.NewLinearCache(dlpTypeURL, cachev3.WithLogger(gcpLogger{}))
	mux := &cachev3.MuxCache{
		Classify:      func(r *cachev3.Request) string { return r.GetTypeUrl() },
		ClassifyDelta: func(r *cachev3.DeltaRequest) string { return r.GetTypeUrl() },
		Caches: map[string]cachev3.Cache{
			policyTypeURL: policyCache, revTypeURL: revCache, swgTypeURL: swgCache, siteTypeURL: siteCache, fwTypeURL: fwCache, dlpTypeURL: dlpCache,
		},
	}
	return &Server{ctx: ctx, store: store, policyCache: policyCache, revCache: revCache, swgCache: swgCache, siteCache: siteCache, fwCache: fwCache, dlpCache: dlpCache, mux: mux, tenantRefs: map[string]int{}}
}

// Register 把 ADS 服务注册到 gRPC server(mTLS creds 由调用方在 grpc.NewServer 时提供,L2 3.9)。
func (s *Server) Register(gs *grpc.Server) {
	srv := serverv3.NewServer(s.ctx, s.mux, serverv3.CallbackFuncs{
		DeltaStreamOpenFunc:    s.onDeltaStreamOpen,   // 开流取证书登记身份(每流一次,带 ctx)
		DeltaStreamClosedFunc:  s.onDeltaStreamClosed, // 关流退订计数 + 驱逐无订阅者租户缓存
		StreamDeltaRequestFunc: s.onDeltaRequest,      // 每订阅请求复查租户授权
	})
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, srv)
}

// onDeltaStreamOpen 在每条 Delta 流开流时(go-control-plane 保证每流一次且带 ctx)从已验证 mTLS
// 叶证书提取身份并按 streamID 登记,供后续 onDeltaRequest 复查订阅授权。无证书 → hasCert=false。
func (s *Server) onDeltaStreamOpen(ctx context.Context, streamID int64, _ string) error {
	role, certTenant, hasCert := peerCertIdentity(ctx)
	s.streams.Store(streamID, &streamAuth{role: role, certTenant: certTenant, hasCert: hasCert, tenants: map[string]bool{}, namedTypes: map[string]bool{}})
	return nil
}

// onDeltaStreamClosed 在 Delta 流关闭时退订:本流订阅过的租户引用计数 -1,归零的租户从对账集移除
// 并驱逐其 6 类缓存资源(止住 tenantRefs 单调增长 + ReconcileAll 不对死租户空转;下个订阅者连上时
// 由 onDeltaRequest 惰性重载,xDS server L2 §3.4 降量)。驱逐持 refMu 与 recordRef 串行,
// 避免「驱逐 vs 新订阅惰性重载」竞态(归零只发生在最后一个订阅者离开、此时无并发 load)。
func (s *Server) onDeltaStreamClosed(streamID int64, _ *corev3.Node) {
	v, ok := s.streams.LoadAndDelete(streamID)
	if !ok {
		return
	}
	sa := v.(*streamAuth)
	s.refMu.Lock()
	defer s.refMu.Unlock()
	for tid := range sa.tenants {
		if n := s.tenantRefs[tid] - 1; n <= 0 {
			delete(s.tenantRefs, tid)
			s.evictTenant(tid)
		} else {
			s.tenantRefs[tid] = n
		}
	}
}

// authFor 取 streamID 的身份;未经 onDeltaStreamOpen(如直接单测调用 / 异常路径)→ 视作无证书 role-less
// 惰性建一份(LoadOrStore 防并发重复)。
func (s *Server) authFor(streamID int64) *streamAuth {
	if v, ok := s.streams.Load(streamID); ok {
		return v.(*streamAuth)
	}
	actual, _ := s.streams.LoadOrStore(streamID, &streamAuth{tenants: map[string]bool{}, namedTypes: map[string]bool{}})
	return actual.(*streamAuth)
}

// recordRef 登记本流对 typeURL 的具名订阅:① 标记 namedTypes[typeURL](后续空 ACK 据此放行,防 wildcard);
// ② 首次订阅 tid → tenantRefs[tid]++(进 ReconcileAll 集);重复订阅同租户不重复计数。
func (s *Server) recordRef(sa *streamAuth, tid, typeURL string) {
	s.refMu.Lock()
	defer s.refMu.Unlock()
	sa.namedTypes[typeURL] = true
	if !sa.tenants[tid] {
		sa.tenants[tid] = true
		s.tenantRefs[tid]++
	}
}

// evictTenant 从全 6 类缓存删除该租户资源(无活跃订阅者后降量)。调用方须持 refMu。
// DeleteResource 对不存在的名返非致命错误,忽略。
func (s *Server) evictTenant(tid string) {
	name := xdspb.ResourceName(tid)
	for _, c := range []*cachev3.LinearCache{s.policyCache, s.revCache, s.swgCache, s.siteCache, s.fwCache, s.dlpCache} {
		_ = c.DeleteResource(name)
	}
	log.Printf("[xds] 驱逐 tenant=%s(无活跃订阅,缓存降量)", tid)
}

// onDeltaRequest:按 type URL 区分,复查订阅租户授权后读对应租户资源入缓存(go-control-plane 据订阅推送)。
// **授权(本刀核心)**:每个订阅的 tenant/<id> 经 authorizeSubscription 比对本流证书 role/绑定租户;
// 未授权(role:device 跨租户 / 严格模式 role-less)返 PermissionDenied —— go-control-plane 据此终止该流
// (delta server.go:180 `return err`),拒绝把他租户资源下发给越权订阅者。
//
// **防 wildcard 旁路(评审 H1)**:go-control-plane 对「首个请求 ResourceNamesSubscribe 为空」的流置为
// wildcard watch,会从共享缓存返回**所有租户**资源(绕过逐租户授权)。SASE 客户端一律具名订阅
// tenant/<id>(internal/pop/client.go),从不用 wildcard;故:① 流尚未具名订阅过即发空订阅(=wildcard
// 触发)→ 拒;② 已具名订阅后的空请求 = ACK(client.go 收响应后回 ResponseNonce + 空订阅)→ 放行;
// ③ 资源名非 tenant/<id>(含显式 "*")→ tenantFromName 返空 → 拒(此前 continue 静默放过是泄漏口)。
func (s *Server) onDeltaRequest(streamID int64, req *discoveryv3.DeltaDiscoveryRequest) error {
	sa := s.authFor(streamID)
	subs := req.GetResourceNamesSubscribe()
	typeURL := req.GetTypeUrl()

	if len(subs) == 0 {
		// 空订阅:仅当本流已为该 typeURL 具名订阅过(=后续 ACK)才放行;否则即 wildcard 首请求 → 拒
		// (go-control-plane 按 (流,typeURL) 首请求空订阅置 wildcard watch,会回该类全部租户资源)。
		s.refMu.Lock()
		acked := sa.namedTypes[typeURL]
		s.refMu.Unlock()
		if !acked {
			log.Printf("[xds] 拒绝 wildcard 订阅 stream=%d type=%q role=%q certTenant=%q(SASE 客户端须具名订阅 tenant/<id>)", streamID, typeURL, sa.role, sa.certTenant)
			return status.Error(codes.PermissionDenied, "wildcard 订阅被拒:须具名订阅 tenant/<id>")
		}
		return nil // 已具名订阅该 typeURL 后的空请求 = ACK,放行
	}

	for _, name := range subs {
		tid := tenantFromName(name)
		if tid == "" { // 非 tenant/<id>(含 wildcard 资源名 "*")→ 拒,绝不静默放过
			log.Printf("[xds] 拒绝非法订阅资源名 stream=%d name=%q(须 tenant/<id>)", streamID, name)
			return status.Errorf(codes.PermissionDenied, "非法订阅资源名 %q:须 tenant/<id>", name)
		}
		if ok, reason := authorizeSubscription(sa.role, sa.hasCert, sa.certTenant, tid, s.strictSubAuth); !ok {
			log.Printf("[xds] 拒绝订阅 stream=%d role=%q certTenant=%q → tenant=%s:%s", streamID, sa.role, sa.certTenant, tid, reason)
			return status.Errorf(codes.PermissionDenied, "订阅租户 %s 被拒:%s", tid, reason)
		}
		s.recordRef(sa, tid, typeURL) // 退订计数 + 维护 tenantRefs(供 ReconcileAll + 驱逐)+ 记该 typeURL 已具名
		switch req.GetTypeUrl() {
		case policyTypeURL:
			s.loadTenant(tid)
		case revTypeURL:
			s.loadRevocations(tid)
		case swgTypeURL:
			s.loadSWG(tid)
		case siteTypeURL:
			s.loadSites(tid)
		case fwTypeURL:
			s.loadFW(tid)
		case dlpTypeURL:
			s.loadDLP(tid)
		}
	}
	return nil
}

// OnNotify 由策略变更 LISTEN/NOTIFY 回调:重读该租户 bundle 入缓存(L2 3.5)。
func (s *Server) OnNotify(tenantID string) { s.loadTenant(tenantID) }

// OnRevocationNotify 由撤销变更 LISTEN/NOTIFY 回调:重读该租户吊销清单入缓存(独立流秒级下发,L2 3.7)。
func (s *Server) OnRevocationNotify(tenantID string) { s.loadRevocations(tenantID) }

// OnSWGNotify 由 SWG 规则变更 LISTEN/NOTIFY 回调:重读该租户 SWG 规则入缓存(独立流下发)。
func (s *Server) OnSWGNotify(tenantID string) { s.loadSWG(tenantID) }

// OnSiteNotify 由站点变更 LISTEN/NOTIFY 回调:重读该租户站点清单入缓存(下发各 CPE)。
func (s *Server) OnSiteNotify(tenantID string) { s.loadSites(tenantID) }

// OnFWNotify 由 FWaaS 规则变更 LISTEN/NOTIFY 回调:重读该租户防火墙规则入缓存(独立流下发)。
func (s *Server) OnFWNotify(tenantID string) { s.loadFW(tenantID) }

// OnDLPNotify 由 DLP 规则变更 LISTEN/NOTIFY 回调:重读该租户 DLP 规则入缓存(独立流下发)。
func (s *Server) OnDLPNotify(tenantID string) { s.loadDLP(tenantID) }

// ReconcileAll 对所有**有活跃订阅**的租户重读全部 6 类资源入缓存,**兜底断连期间丢失的 LISTEN/NOTIFY**
// (listen.go 注:NOTIFY 不持久,断连期间通知会丢;xDS server L2 3.5 须重连后/周期全量对账)。
// 由 cmd 在 LISTEN 重连后(撤销通道,秒级安全)+ 周期 ticker(兜底,默认 30s)调用。
// 全 6 个 load* 幂等(UpdateResource 覆盖),重复调用安全;无激活 bundle 的租户 loadTenant 自跳过。
// 在锁外做 DB I/O:先持 refMu 快照活跃租户集,释放后再 load(避免持锁 I/O;无订阅者的租户不空转,
// 因关流已驱逐 + 从 tenantRefs 移除)。
func (s *Server) ReconcileAll() {
	s.refMu.Lock()
	tids := make([]string, 0, len(s.tenantRefs))
	for tid := range s.tenantRefs {
		tids = append(tids, tid)
	}
	s.refMu.Unlock()

	for _, tid := range tids {
		s.loadTenant(tid)
		s.loadRevocations(tid)
		s.loadSWG(tid)
		s.loadSites(tid)
		s.loadFW(tid)
		s.loadDLP(tid)
	}
	if len(tids) > 0 {
		log.Printf("[xds] 全量对账:%d 租户 × 6 资源(兜底丢失的 NOTIFY)", len(tids))
	}
}

// loadTenant 读租户激活 bundle 并 UpdateResource(无激活 bundle 则跳过)。
func (s *Server) loadTenant(tenantID string) {
	compiled, ver, ok, err := s.readBundle(tenantID)
	if err != nil {
		log.Printf("[xds] 读 tenant=%s bundle: %v", tenantID, err)
		return
	}
	if !ok {
		return
	}
	res := &xdspb.PolicyBundleResource{TenantId: tenantID, Version: ver, Compiled: compiled}
	if err := s.policyCache.UpdateResource(xdspb.ResourceName(tenantID), res); err != nil {
		log.Printf("[xds] UpdateResource(policy) tenant=%s: %v", tenantID, err)
		return
	}
	s.rec.XDSPush(metrics.ResourcePolicy)
	log.Printf("[xds] 装载 tenant=%s bundle v%d", tenantID, ver)
}

// loadRevocations 读租户未过期吊销清单并 UpdateResource(空清单也下发,使订阅可响应)。
func (s *Server) loadRevocations(tenantID string) {
	jtis, err := s.readRevocations(tenantID)
	if err != nil {
		log.Printf("[xds] 读 tenant=%s 吊销表: %v", tenantID, err)
		return
	}
	rl := &xdspb.RevocationList{TenantId: tenantID, Version: int64(len(jtis)), Jtis: jtis}
	if err := s.revCache.UpdateResource(xdspb.ResourceName(tenantID), rl); err != nil {
		log.Printf("[xds] UpdateResource(revocation) tenant=%s: %v", tenantID, err)
		return
	}
	s.rec.XDSPush(metrics.ResourceRevocation)
	log.Printf("[xds] 装载 tenant=%s 吊销 %d 条", tenantID, len(jtis))
}

// loadSWG 读租户 SWG 规则并 UpdateResource(空规则也下发,使订阅可响应)。
func (s *Server) loadSWG(tenantID string) {
	rules, err := s.readSWG(tenantID)
	if err != nil {
		log.Printf("[xds] 读 tenant=%s SWG 规则: %v", tenantID, err)
		return
	}
	rs := &xdspb.SWGRuleSet{TenantId: tenantID, Version: int64(len(rules)), Rules: rules}
	if err := s.swgCache.UpdateResource(xdspb.ResourceName(tenantID), rs); err != nil {
		log.Printf("[xds] UpdateResource(swg) tenant=%s: %v", tenantID, err)
		return
	}
	s.rec.XDSPush(metrics.ResourceSWG)
	log.Printf("[xds] 装载 tenant=%s SWG %d 条", tenantID, len(rules))
}

// readSWG 经只读事务读租户 SWG 规则。
func (s *Server) readSWG(tenantID string) ([]*xdspb.SWGRule, error) {
	var rules []*xdspb.SWGRule
	err := s.store.InTxRO(s.ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(s.ctx, `SELECT kind, pattern, action FROM swg_rules ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r xdspb.SWGRule
			if err := rows.Scan(&r.Kind, &r.Pattern, &r.Action); err != nil {
				return err
			}
			rules = append(rules, &r)
		}
		return rows.Err()
	})
	return rules, err
}

// loadFW 读租户 FWaaS 规则并 UpdateResource(空规则也下发,使订阅可响应)。
func (s *Server) loadFW(tenantID string) {
	rules, err := s.readFW(tenantID)
	if err != nil {
		log.Printf("[xds] 读 tenant=%s FW 规则: %v", tenantID, err)
		return
	}
	rs := &xdspb.FWRuleSet{TenantId: tenantID, Version: int64(len(rules)), Rules: rules}
	if err := s.fwCache.UpdateResource(xdspb.ResourceName(tenantID), rs); err != nil {
		log.Printf("[xds] UpdateResource(fw) tenant=%s: %v", tenantID, err)
		return
	}
	s.rec.XDSPush(metrics.ResourceFW)
	log.Printf("[xds] 装载 tenant=%s FW %d 条", tenantID, len(rules))
}

// readFW 经只读事务读租户 FWaaS 规则(按 priority 升序,引擎据此首次匹配)。
func (s *Server) readFW(tenantID string) ([]*xdspb.FWRule, error) {
	var rules []*xdspb.FWRule
	err := s.store.InTxRO(s.ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(s.ctx,
			`SELECT priority, action, protocol, src_cidr, dst_cidr, dst_port_min, dst_port_max
			 FROM fw_rules ORDER BY priority, created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r xdspb.FWRule
			var lo, hi int
			if err := rows.Scan(&r.Priority, &r.Action, &r.Protocol, &r.SrcCidr, &r.DstCidr, &lo, &hi); err != nil {
				return err
			}
			r.DstPortMin, r.DstPortMax = uint32(lo), uint32(hi)
			rules = append(rules, &r)
		}
		return rows.Err()
	})
	return rules, err
}

// loadDLP 读租户 DLP 规则并 UpdateResource(空规则也下发,使订阅可响应)。
func (s *Server) loadDLP(tenantID string) {
	rules, err := s.readDLP(tenantID)
	if err != nil {
		log.Printf("[xds] 读 tenant=%s DLP 规则: %v", tenantID, err)
		return
	}
	rs := &xdspb.DLPRuleSet{TenantId: tenantID, Version: int64(len(rules)), Rules: rules}
	if err := s.dlpCache.UpdateResource(xdspb.ResourceName(tenantID), rs); err != nil {
		log.Printf("[xds] UpdateResource(dlp) tenant=%s: %v", tenantID, err)
		return
	}
	s.rec.XDSPush(metrics.ResourceDLP)
	log.Printf("[xds] 装载 tenant=%s DLP %d 条", tenantID, len(rules))
}

// readDLP 经只读事务读租户 DLP 规则。
func (s *Server) readDLP(tenantID string) ([]*xdspb.DLPRule, error) {
	var rules []*xdspb.DLPRule
	err := s.store.InTxRO(s.ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(s.ctx,
			`SELECT name, match_type, pattern, action, severity FROM dlp_rules ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r xdspb.DLPRule
			if err := rows.Scan(&r.Name, &r.MatchType, &r.Pattern, &r.Action, &r.Severity); err != nil {
				return err
			}
			rules = append(rules, &r)
		}
		return rows.Err()
	})
	return rules, err
}

// loadSites 读租户站点清单并 UpdateResource(空清单也下发,使订阅可响应)。
func (s *Server) loadSites(tenantID string) {
	sites, err := s.readSites(tenantID)
	if err != nil {
		log.Printf("[xds] 读 tenant=%s 站点: %v", tenantID, err)
		return
	}
	sc := &xdspb.SiteConfig{TenantId: tenantID, Version: int64(len(sites)), Sites: sites}
	if err := s.siteCache.UpdateResource(xdspb.ResourceName(tenantID), sc); err != nil {
		log.Printf("[xds] UpdateResource(site) tenant=%s: %v", tenantID, err)
		return
	}
	s.rec.XDSPush(metrics.ResourceSite)
	log.Printf("[xds] 装载 tenant=%s 站点 %d 个", tenantID, len(sites))
}

func (s *Server) readSites(tenantID string) ([]*xdspb.Site, error) {
	var sites []*xdspb.Site
	err := s.store.InTxRO(s.ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(s.ctx, `SELECT site_key, cidr, name FROM sites ORDER BY site_key`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var st xdspb.Site
			if err := rows.Scan(&st.SiteKey, &st.Cidr, &st.Name); err != nil {
				return err
			}
			sites = append(sites, &st)
		}
		return rows.Err()
	})
	return sites, err
}

// readBundle 经只读事务读租户激活 bundle 的 compiled/version(无则 ok=false)。
func (s *Server) readBundle(tenantID string) (compiled []byte, version int64, ok bool, err error) {
	err = s.store.InTxRO(s.ctx, tenantID, func(q data.Queries) error {
		scanErr := q.QueryRow(s.ctx,
			`SELECT compiled, version FROM policy_bundles WHERE status = 'active'`).Scan(&compiled, &version)
		if errors.Is(scanErr, data.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		ok = true
		return nil
	})
	return compiled, version, ok, err
}

// readRevocations 经只读事务读租户未过期的吊销 jti 集。
func (s *Server) readRevocations(tenantID string) ([]string, error) {
	var jtis []string
	err := s.store.InTxRO(s.ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(s.ctx, `SELECT jti FROM revocations WHERE expire_at > now() ORDER BY jti`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var j string
			if err := rows.Scan(&j); err != nil {
				return err
			}
			jtis = append(jtis, j)
		}
		return rows.Err()
	})
	return jtis, err
}

func tenantFromName(name string) string {
	const p = "tenant/"
	if len(name) > len(p) && name[:len(p)] == p {
		return name[len(p):]
	}
	return ""
}

// gcpLogger 适配 go-control-plane 的 log.Logger(静默 debug/info,警告/错误转标准 log)。
type gcpLogger struct{}

func (gcpLogger) Debugf(string, ...interface{})    {}
func (gcpLogger) Infof(string, ...interface{})     {}
func (gcpLogger) Warnf(f string, a ...interface{}) { log.Printf("[xds][warn] "+f, a...) }
func (gcpLogger) Errorf(f string, a ...interface{}) {
	log.Printf("[xds][err] "+f, a...)
}
