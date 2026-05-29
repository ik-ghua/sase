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

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"

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
}

// SetMetrics 注入控制面指标记录器(可选;nil 为 no-op)。
func (s *Server) SetMetrics(rec *metrics.ControlRecorder) { s.rec = rec }

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
	return &Server{ctx: ctx, store: store, policyCache: policyCache, revCache: revCache, swgCache: swgCache, siteCache: siteCache, fwCache: fwCache, dlpCache: dlpCache, mux: mux}
}

// Register 把 ADS 服务注册到 gRPC server(mTLS creds 由调用方在 grpc.NewServer 时提供,L2 3.9)。
func (s *Server) Register(gs *grpc.Server) {
	srv := serverv3.NewServer(s.ctx, s.mux, serverv3.CallbackFuncs{
		StreamDeltaRequestFunc: s.onDeltaRequest,
	})
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, srv)
}

// onDeltaRequest:按 type URL 区分,读对应租户资源入缓存(go-control-plane 据订阅推送)。
func (s *Server) onDeltaRequest(_ int64, req *discoveryv3.DeltaDiscoveryRequest) error {
	for _, name := range req.GetResourceNamesSubscribe() {
		tid := tenantFromName(name)
		if tid == "" {
			continue
		}
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
