// Package pop 的 xDS 客户端:经 ADS 增量(Delta)+ mTLS 订阅控制面下发的自定义资源。
// 策略(PolicyBundleResource)与撤销(RevocationList)各开独立的 mTLS 连接与 Delta 流(xDS server
// L2 3.7:撤销不被大 bundle 推送队头阻塞)。
package pop

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/anypb"

	xdspb "github.com/ikuai8/sase/api/proto/sase/xds/v1"
	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/fw"
	"github.com/ikuai8/sase/internal/swg"
)

// SubscribeXDS 订阅策略 bundle(PolicyBundleResource),每收到一版回调 onBundle。
func SubscribeXDS(ctx context.Context, addr string, tlsConf *tls.Config, tenantID, node string, onBundle func(xdsv1.PolicyBundle)) error {
	return subscribeStream(ctx, addr, tlsConf, xdspb.TypeURL(), tenantID, node, func(name string, any *anypb.Any) {
		var pbres xdspb.PolicyBundleResource
		if err := any.UnmarshalTo(&pbres); err != nil {
			log.Printf("[pop] 跳过坏资源 %s(解 Any 失败): %v", name, err)
			return
		}
		var bundle xdsv1.PolicyBundle
		if err := json.Unmarshal(pbres.GetCompiled(), &bundle); err != nil {
			log.Printf("[pop] 跳过坏资源 %s(解 payload 失败): %v", name, err)
			return
		}
		onBundle(bundle)
	})
}

// SubscribeRevocations 订阅撤销清单(RevocationList),每收到一版回调 onRevoked(全量 jti 清单)。
func SubscribeRevocations(ctx context.Context, addr string, tlsConf *tls.Config, tenantID, node string, onRevoked func(jtis []string)) error {
	return subscribeStream(ctx, addr, tlsConf, xdspb.RevocationTypeURL(), tenantID, node, func(name string, any *anypb.Any) {
		var rl xdspb.RevocationList
		if err := any.UnmarshalTo(&rl); err != nil {
			log.Printf("[pop] 跳过坏撤销资源 %s: %v", name, err)
			return
		}
		onRevoked(rl.GetJtis())
	})
}

// SubscribeSWG 订阅 SWG 规则集(SWGRuleSet),每收到一版回调 onRules。
func SubscribeSWG(ctx context.Context, addr string, tlsConf *tls.Config, tenantID, node string, onRules func(rules []swg.Rule)) error {
	return subscribeStream(ctx, addr, tlsConf, xdspb.SWGTypeURL(), tenantID, node, func(name string, any *anypb.Any) {
		var rs xdspb.SWGRuleSet
		if err := any.UnmarshalTo(&rs); err != nil {
			log.Printf("[pop] 跳过坏 SWG 资源 %s: %v", name, err)
			return
		}
		out := make([]swg.Rule, 0, len(rs.GetRules()))
		for _, r := range rs.GetRules() {
			out = append(out, swg.Rule{Kind: r.GetKind(), Pattern: r.GetPattern(), Action: r.GetAction()})
		}
		onRules(out)
	})
}

// SubscribeFW 订阅 FWaaS 规则集(FWRuleSet),每收到一版回调 onRules(已按 priority 升序)。
func SubscribeFW(ctx context.Context, addr string, tlsConf *tls.Config, tenantID, node string, onRules func(rules []fw.Rule)) error {
	return subscribeStream(ctx, addr, tlsConf, xdspb.FWTypeURL(), tenantID, node, func(name string, any *anypb.Any) {
		var rs xdspb.FWRuleSet
		if err := any.UnmarshalTo(&rs); err != nil {
			log.Printf("[pop] 跳过坏 FW 资源 %s: %v", name, err)
			return
		}
		out := make([]fw.Rule, 0, len(rs.GetRules()))
		for _, r := range rs.GetRules() {
			out = append(out, fw.Rule{
				Priority: int(r.GetPriority()), Action: r.GetAction(), Protocol: r.GetProtocol(),
				SrcCIDR: r.GetSrcCidr(), DstCIDR: r.GetDstCidr(),
				DstPortMin: uint16(r.GetDstPortMin()), DstPortMax: uint16(r.GetDstPortMax()),
			})
		}
		onRules(out)
	})
}

// SubscribeDLP 订阅 DLP 规则集(DLPRuleSet),每收到一版回调 onRules。
func SubscribeDLP(ctx context.Context, addr string, tlsConf *tls.Config, tenantID, node string, onRules func(rules []dlp.Rule)) error {
	return subscribeStream(ctx, addr, tlsConf, xdspb.DLPTypeURL(), tenantID, node, func(name string, any *anypb.Any) {
		var rs xdspb.DLPRuleSet
		if err := any.UnmarshalTo(&rs); err != nil {
			log.Printf("[pop] 跳过坏 DLP 资源 %s: %v", name, err)
			return
		}
		out := make([]dlp.Rule, 0, len(rs.GetRules()))
		for _, r := range rs.GetRules() {
			out = append(out, dlp.Rule{
				Name: r.GetName(), MatchType: r.GetMatchType(), Pattern: r.GetPattern(),
				Action: r.GetAction(), Severity: r.GetSeverity(),
			})
		}
		onRules(out)
	})
}

// SiteInfo 是下发给 CPE 的对端站点信息(SD-WAN 路由域)。
type SiteInfo struct {
	SiteKey string
	CIDR    string
	Name    string
}

// SubscribeSites 订阅 SD-WAN 站点清单(SiteConfig),每收到一版回调 onSites(同租户路由域全部站点)。
func SubscribeSites(ctx context.Context, addr string, tlsConf *tls.Config, tenantID, node string, onSites func(sites []SiteInfo)) error {
	return subscribeStream(ctx, addr, tlsConf, xdspb.SiteConfigTypeURL(), tenantID, node, func(name string, any *anypb.Any) {
		var sc xdspb.SiteConfig
		if err := any.UnmarshalTo(&sc); err != nil {
			log.Printf("[cpe] 跳过坏 Site 资源 %s: %v", name, err)
			return
		}
		out := make([]SiteInfo, 0, len(sc.GetSites()))
		for _, s := range sc.GetSites() {
			out = append(out, SiteInfo{SiteKey: s.GetSiteKey(), CIDR: s.GetCidr(), Name: s.GetName()})
		}
		onSites(out)
	})
}

// subscribeStream 开一条 Delta ADS 流订阅 typeURL 的 tenant/<id> 资源,逐版回调 onResource 并回 ACK。
func subscribeStream(ctx context.Context, addr string, tlsConf *tls.Config, typeURL, tenantID, node string, onResource func(name string, any *anypb.Any)) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	if err != nil {
		return fmt.Errorf("pop: 建 xds 连接: %w", err)
	}
	defer conn.Close()

	stream, err := discoveryv3.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	if err != nil {
		return fmt.Errorf("pop: 开 Delta ADS 流(%s): %w", typeURL, err)
	}
	if err := stream.Send(&discoveryv3.DeltaDiscoveryRequest{
		Node:                   &corev3.Node{Id: node},
		TypeUrl:                typeURL,
		ResourceNamesSubscribe: []string{xdspb.ResourceName(tenantID)},
	}); err != nil {
		return fmt.Errorf("pop: 发订阅(%s): %w", typeURL, err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("pop: 收 Delta 响应(%s): %w", typeURL, err)
		}
		for _, r := range resp.GetResources() {
			onResource(r.GetName(), r.GetResource())
		}
		if err := stream.Send(&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:       typeURL,
			ResponseNonce: resp.GetNonce(),
		}); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("pop: 发 ACK(%s): %w", typeURL, err)
		}
	}
}
