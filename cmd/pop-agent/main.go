// Command pop-agent 是 PoP 本机编排器(数据面边缘)。
// Slice 3:① 经 xDS 订阅租户 PolicyBundle 入 BundleStore;② 接受 Connector 出站反向注册;
// ③ 接入面:验凭证(用从控制面取的 TrustBundle 公钥离线验证)→ PEP 裁决 → 放行则反向转发到应用。
//
//	用法:XDS_ADDR=127.0.0.1:9090 TRUST_URL=http://127.0.0.1:8080 SASE_TLS_DIR=./certs TENANT=<uuid> \
//	      INGRESS_ADDR=:8081 CONNECTOR_ADDR=:7000 NODE=pop-dev pop-agent
//
// **生产必设 SASE_REQUIRE_CERT_TENANT=1**(W9 fail-closed):反向通道注册要求连接证书携租户
// (ZTP 签发),拒绝无租户共享证书冒名注册。dev 默认关,便于本地联调用共享证书。
//
// 下发链走 mTLS gRPC(xDS ADS/Delta);数据面隧道加密(WireGuard/TLS、国密)待 PoC-G。
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	telemetrypb "github.com/ikuai8/sase/api/proto/sase/telemetry/v1"
	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/fw"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/pop"
	"github.com/ikuai8/sase/internal/revtunnel"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/telemetry"
	"github.com/ikuai8/sase/internal/tunhandshake"
)

// siteCIDRs 是 site_key → 子网 的并发安全注册表(由站点 xDS 订阅更新,供 SD-WAN Router 选路目的)。
type siteCIDRs struct {
	mu       sync.Mutex
	m        map[string][]*net.IPNet
	onUpdate func() // 可选:每次 set 后调(供已握手站点用新 CIDR 重登记 Router,解 xDS 晚到的竞态)
}

func newSiteCIDRs() *siteCIDRs { return &siteCIDRs{m: map[string][]*net.IPNet{}} }

// setOnUpdate 设站点清单更新后的回调(SD-WAN 隧道启用时挂,用于 xDS 晚于握手到达时补登路由)。
func (s *siteCIDRs) setOnUpdate(fn func()) {
	s.mu.Lock()
	s.onUpdate = fn
	s.mu.Unlock()
}

// set 整体替换站点清单(解析 SiteInfo.CIDR;非法 CIDR 跳过并记日志)。
func (s *siteCIDRs) set(sites []pop.SiteInfo) {
	m := make(map[string][]*net.IPNet, len(sites))
	for _, si := range sites {
		if si.CIDR == "" {
			continue
		}
		_, n, err := net.ParseCIDR(si.CIDR)
		if err != nil {
			log.Printf("[pop-agent] 站点 %s CIDR %q 非法,跳过: %v", si.SiteKey, si.CIDR, err)
			continue
		}
		m[si.SiteKey] = append(m[si.SiteKey], n)
	}
	s.mu.Lock()
	s.m = m
	fn := s.onUpdate
	s.mu.Unlock()
	if fn != nil {
		fn() // 锁外调,避免回调里再访问 siteReg(get)自锁死锁
	}
}

func (s *siteCIDRs) get(site string) []*net.IPNet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[site]
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("pop-agent: %v", err)
	}
}

func run() error {
	xdsAddr := envOr("XDS_ADDR", "127.0.0.1:9090")
	trustURL := envOr("TRUST_URL", "https://127.0.0.1:8443")
	tlsDir := envOr("SASE_TLS_DIR", "./certs")
	tenantID := envMust("TENANT")
	node := envOr("NODE", "pop-dev")
	ingressAddr := envOr("INGRESS_ADDR", ":8081")
	connectorAddr := envOr("CONNECTOR_ADDR", ":7000")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TrustBundle:经管理面 HTTPS 取控制面签发公钥(算法无关),离线验证凭证(stand-in;生产经 xDS TrustBundle)。
	pub, err := fetchPubkey(ctx, trustURL, tlsDir)
	if err != nil {
		return err
	}
	verifier, err := cred.NewVerifier(pub)
	if err != nil {
		return fmt.Errorf("构造验证器: %w", err)
	}

	bundles := pop.NewBundleStore()
	revoked := pop.NewRevocationStore()
	swgStore := pop.NewSWGStore()
	dlpStore := pop.NewDLPStore()

	// W9 fail-closed:SASE_REQUIRE_CERT_TENANT=1 时,反向通道注册要求连接证书携租户(ZTP 签发),
	// 拒绝无租户的共享证书冒名注册。**生产必开**;dev 默认关(容忍共享证书,便于本地联调)。
	var regOpts []revtunnel.Option
	if truthy(os.Getenv("SASE_REQUIRE_CERT_TENANT")) {
		regOpts = append(regOpts, revtunnel.WithRequireCertTenant())
		log.Printf("[pop-agent] 反向通道注册:require-cert-tenant 已开启(仅接受 ZTP 租户绑定证书)")
	} else {
		log.Printf("[pop-agent] 反向通道注册:require-cert-tenant 未开启(dev:容忍共享证书);生产须设 SASE_REQUIRE_CERT_TENANT=1")
	}
	registry := revtunnel.NewRegistry(regOpts...)
	rec := metrics.NewRecorder()

	// DLP 命中出口:设 TELEMETRY_ADDR 则经遥测上报跨进程喂控制面风险引擎(DLP→风险闭环);否则 LogFindingSink 兜底。
	var dlpSink dlp.FindingSink = pop.LogFindingSink{}
	if telAddr := os.Getenv("TELEMETRY_ADDR"); telAddr != "" {
		// W11:遥测用 PoP 角色证书(role:pop),控制面 require-pop-role 开启时据此授权;无 pop.crt 则退回共享证书
		// (此时若控制面已开门控会被拒——dev 重生成证书 cmd/devpki 即得 pop.crt)。
		telTLS, terr := devpki.LoadPoPClientTLS(tlsDir, "xds-server")
		if terr != nil {
			log.Printf("[pop-agent] 无 PoP 角色证书(%v),遥测退回共享证书(require-pop-role 开启会被拒)", terr)
			telTLS, terr = devpki.LoadClientTLS(tlsDir, "xds-server")
		}
		if terr != nil {
			return fmt.Errorf("加载遥测 mTLS: %w", terr)
		}
		telConn, terr := grpc.NewClient(telAddr, grpc.WithTransportCredentials(credentials.NewTLS(telTLS)))
		if terr != nil {
			return fmt.Errorf("连遥测 %s: %w", telAddr, terr)
		}
		defer telConn.Close()
		reporter := telemetry.NewReporter(telemetrypb.NewTelemetryClient(telConn), 1024)
		go reporter.Run(ctx)
		rec.RegisterTelemetryDrops(reporter.Dropped, reporter.DroppedSend) // /metrics 暴露遥测丢弃(背压/发送失败,Slice67)
		dlpSink = reporter
		log.Printf("[pop-agent] 遥测上报启用 → %s(DLP 命中跨进程喂风险引擎)", telAddr)
	} else {
		log.Printf("[pop-agent] 未设 TELEMETRY_ADDR,DLP 命中仅本地记日志(不喂风险引擎)")
	}

	ingress := pop.NewIngress(verifier, bundles, revoked, swgStore, swg.NewRuleEngine(), registry, rec).
		WithDLP(dlpStore, dlp.NewRuleEngine(), dlpSink) // CASB-DLP 挂 inspect;命中喂 sink(遥测→风险 或 兜底日志)
	siteIngress := pop.NewSiteIngress(verifier, registry, rec) // SD-WAN 站点 overlay(复用同一连接器 registry)

	// 可观测:/metrics(明文,内部抓取;Prometheus/VictoriaMetrics 拉取,运维 L2 3.4)
	metricsAddr := envOr("METRICS_ADDR", ":9101")
	go func() {
		mmux := http.NewServeMux()
		mmux.Handle("/metrics", rec.Handler())
		msrv := &http.Server{Addr: metricsAddr, Handler: mmux, ReadHeaderTimeout: 5 * time.Second}
		go func() { <-ctx.Done(); _ = msrv.Close() }()
		if err := msrv.ListenAndServe(); err != nil && ctx.Err() == nil {
			log.Printf("[pop-agent] /metrics 退出: %v", err)
		}
	}()
	log.Printf("[pop-agent] /metrics 监听 %s", metricsAddr)

	xdsTLS, err := devpki.LoadPoPClientTLS(tlsDir, "xds-server") // PoP 角色证书(role:pop);无则下方退回共享证书
	if err != nil {
		log.Printf("[pop-agent] 无 PoP 角色证书(%v),xDS 退回共享证书", err)
		xdsTLS, err = devpki.LoadClientTLS(tlsDir, "xds-server")
	}
	if err != nil {
		return fmt.Errorf("加载 mTLS client(%s): %w", tlsDir, err)
	}
	// PoP 作为服务端的 mTLS(连接器反向注册口 + Agent 接入面均要求并校验对端证书)
	serverTLS, err := devpki.LoadServerTLS(tlsDir)
	if err != nil {
		return fmt.Errorf("加载 mTLS server(%s): %w", tlsDir, err)
	}
	// ① 策略 xDS 订阅(mTLS gRPC ADS/Delta):更新 BundleStore。重连循环:server 重启/抖动后自动重订阅。
	go subscribeLoop(ctx, "policy", func() error {
		return pop.SubscribeXDS(ctx, xdsAddr, xdsTLS, tenantID, node, func(b xdsv1.PolicyBundle) {
			bundles.Set(b)
			log.Printf("[pop-agent] 装载 bundle tenant=%s version=%d (%d 条 L7)", b.TenantID, b.Version, len(b.L7Rules))
		})
	})
	// ①' 撤销 xDS 订阅(独立流):更新 RevocationStore(秒级失效)。
	go subscribeLoop(ctx, "revocation", func() error {
		return pop.SubscribeRevocations(ctx, xdsAddr, xdsTLS, tenantID, node, func(jtis []string) {
			revoked.Set(tenantID, jtis)
			log.Printf("[pop-agent] 装载吊销清单 tenant=%s %d 条", tenantID, len(jtis))
		})
	})
	// ①'' SWG 规则 xDS 订阅(独立流):更新 SWGStore(inspect 流量过 URL 过滤)。
	go subscribeLoop(ctx, "swg", func() error {
		return pop.SubscribeSWG(ctx, xdsAddr, xdsTLS, tenantID, node, func(rules []swg.Rule) {
			swgStore.Set(tenantID, rules)
			log.Printf("[pop-agent] 装载 SWG 规则 tenant=%s %d 条", tenantID, len(rules))
		})
	})
	// ①''' DLP 规则 xDS 订阅(独立流):更新 DLPStore(inspect 流量过敏感数据检测,命中喂风险引擎)。
	go subscribeLoop(ctx, "dlp", func() error {
		return pop.SubscribeDLP(ctx, xdsAddr, xdsTLS, tenantID, node, func(rules []dlp.Rule) {
			dlpStore.Set(tenantID, rules)
			log.Printf("[pop-agent] 装载 DLP 规则 tenant=%s %d 条", tenantID, len(rules))
		})
	})
	// ①'''' 站点 xDS 订阅(独立流):SD-WAN 路由域站点清单 → 更新 site CIDR 注册表(供下方 Router 选路目的)。
	siteReg := newSiteCIDRs()
	go subscribeLoop(ctx, "site", func() error {
		return pop.SubscribeSites(ctx, xdsAddr, xdsTLS, tenantID, node, func(sites []pop.SiteInfo) {
			siteReg.set(sites)
			log.Printf("[pop-agent] 装载站点清单 tenant=%s %d 个", tenantID, len(sites))
		})
	})

	// ① SD-WAN 数据面隧道(可选,gated):握手(mutual TLS1.3 + RFC5705 密钥导出,tunhandshake L2 形态 A)
	//    → dptunnel.Router 站点间转发 + **FWaaS L3/L4 真数据面裁决**。设 SDWAN_TUNNEL_ADDR(握手 TCP)
	//    + SDWAN_DATA_ADDR(数据 UDP)启用;不设则不启(保持原行为)。身份权威=证书(tenant/site),非 srcAddr。
	if hsAddr := os.Getenv("SDWAN_TUNNEL_ADDR"); hsAddr != "" {
		if err := startSDWANTunnel(ctx, hsAddr, xdsAddr, tenantID, node, xdsTLS, serverTLS, siteReg, rec); err != nil {
			return err
		}
	}

	// ② Connector 反向注册监听(mTLS:校验连接器设备证书)
	rawLis, err := net.Listen("tcp", connectorAddr)
	if err != nil {
		return fmt.Errorf("监听连接器端口 %s: %w", connectorAddr, err)
	}
	lis := tls.NewListener(rawLis, serverTLS)
	go func() {
		if acceptErr := registry.Accept(ctx, lis); acceptErr != nil && ctx.Err() == nil {
			log.Printf("[pop-agent] 连接器监听结束: %v", acceptErr)
		}
	}()
	log.Printf("[pop-agent] node=%s 连接器注册口 %s(mTLS),接入面 %s(mTLS)", node, connectorAddr, ingressAddr)

	// ③ 接入面 HTTPS(mTLS:校验 Agent 设备证书;凭证为 app 层认证)
	ilis, err := net.Listen("tcp", ingressAddr)
	if err != nil {
		return fmt.Errorf("监听接入面 %s: %w", ingressAddr, err)
	}
	imux := http.NewServeMux()
	ingress.Register(imux)     // ZTNA /access
	siteIngress.Register(imux) // SD-WAN /site(同接入面 server)
	srv := &http.Server{Handler: imux, TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err := srv.ServeTLS(ilis, "", ""); err != nil && ctx.Err() == nil {
		return fmt.Errorf("接入面退出: %w", err)
	}
	return nil
}

// startSDWANTunnel 起 SD-WAN 数据面隧道:FWStore + FW xDS 订阅 + dptunnel.Router(挂 FWaaS)+ UDP 数据面 +
// tunhandshake 握手服务。握手成功(证书认证 → tenant/site)→ 建会话 → Router.Register(身份来自证书)。
func startSDWANTunnel(ctx context.Context, hsAddr, xdsAddr, tenantID, node string, xdsTLS, serverTLS *tls.Config, siteReg *siteCIDRs, rec *metrics.Recorder) error {
	dataAddr := envOr("SDWAN_DATA_ADDR", ":7100")
	alg := envOr("SDWAN_TUNNEL_ALG", dptunnel.AlgChaCha20Poly1305)

	// FWaaS L3/L4 规则经独立 xDS 流加载;无规则集时 FWStore fail-closed(拒转发),故须订阅。
	fwStore := pop.NewFWStore(fw.NewRuleEngine())
	go subscribeLoop(ctx, "fw", func() error {
		return pop.SubscribeFW(ctx, xdsAddr, xdsTLS, tenantID, node, func(rules []fw.Rule) {
			fwStore.Set(tenantID, rules)
			log.Printf("[pop-agent] 装载 FWaaS 规则 tenant=%s %d 条", tenantID, len(rules))
		})
	})

	router := dptunnel.NewRouter()
	router.SetFirewall(fwStore)        // FWaaS L3/L4 在站点间转发前裁决(须在 Serve 前设)
	router.SetDropHook(rec.TunnelDrop) // 数据面隧道丢包计数 → /metrics(按原因,Slice67;须在 Serve 前设)
	dataConn, err := net.ListenPacket("udp", dataAddr)
	if err != nil {
		return fmt.Errorf("监听 SD-WAN 数据面 %s: %w", dataAddr, err)
	}
	go router.Serve(ctx, dataConn)

	// 已握手站点跟踪:site → established(供站点 CIDR(xDS)晚于握手到达时,用新 CIDR 重登记 Router)。
	// 否则握手时 siteReg.get 取到空 CIDR(站点 xDS 尚未到)→ 该站点永无路由(握手只一次)。
	var estMu sync.Mutex
	established := map[string]tunhandshake.Established{}
	reRegister := func() {
		estMu.Lock()
		snapshot := make([]tunhandshake.Established, 0, len(established))
		for _, e := range established {
			snapshot = append(snapshot, e)
		}
		estMu.Unlock()
		for _, e := range snapshot {
			// 只更新该站点的 CIDR 路由,**保留握手时建立的原会话**(AEAD 密钥与计数器连续)。
			// 绝不在此重建会话:重建会复用旧密钥但把发送计数器归零 → nonce 复用(同密钥+同 nonce
			// 加密不同明文),破坏隧道机密性/认证(Slice75 H1)。CIDR 与会话密钥无关,故只更路由。
			// UpdateCIDRs 对未登记站点返 false(握手未完成,握手时会带当时 CIDR 登记),此处忽略返回值。
			router.UpdateCIDRs(e.Tenant, e.Site, siteReg.get(e.Site))
		}
	}
	siteReg.setOnUpdate(reRegister) // 站点 CIDR 每次更新后,已握手站点用新 CIDR 更新路由(不重建会话)

	// 通告给 CPE 的数据面地址:NAT/多址下须经 SDWAN_DATA_ADV 显式设公网可达地址(默认取本地监听地址)。
	advAddr := envOr("SDWAN_DATA_ADV", dataConn.LocalAddr().String())
	srv := tunhandshake.NewServer(advAddr, alg, func(e tunhandshake.Established) {
		if e.Tenant != tenantID { // 本 cmd 单租户:拒绝他租户证书(PoP 多租户由部署多实例/后续多租户化承载)
			log.Printf("[pop-agent] 拒绝 SD-WAN 握手:证书租户 %s 与本 PoP 租户 %s 不符", e.Tenant, tenantID)
			return
		}
		sess, serr := e.Session()
		if serr != nil {
			log.Printf("[pop-agent] 建 SD-WAN 会话失败 site=%s: %v", e.Site, serr)
			return
		}
		estMu.Lock()
		established[e.Site] = e // 记下,供 CIDR 晚到时重登记
		estMu.Unlock()
		router.Register(e.Tenant, e.Site, sess, e.CPEDataAddr, siteReg.get(e.Site))
		log.Printf("[pop-agent] SD-WAN 站点接入 tenant=%s site=%s data=%s cidrs=%d",
			e.Tenant, e.Site, e.CPEDataAddr, len(siteReg.get(e.Site)))
	})

	rawHs, err := net.Listen("tcp", hsAddr)
	if err != nil {
		return fmt.Errorf("监听 SD-WAN 握手 %s: %w", hsAddr, err)
	}
	hsLn := tls.NewListener(rawHs, serverTLS) // mutual TLS(校验 CPE ZTP 证书)
	go func() {
		if e := srv.Serve(ctx, hsLn); e != nil && ctx.Err() == nil {
			log.Printf("[pop-agent] SD-WAN 握手监听结束: %v", e)
		}
	}()
	log.Printf("[pop-agent] SD-WAN 隧道启用:握手 %s(mTLS)/ 数据面 %s(通告 %s)/ 档 %s / FWaaS L4 生效",
		hsAddr, dataConn.LocalAddr(), advAddr, alg)
	return nil
}

// fetchPubkey 经管理面 HTTPS 取签发公钥(GET /api/v1/trust/pubkey → {"alg":..,"pubkey": base64url})。
func fetchPubkey(ctx context.Context, trustURL, tlsDir string) (cred.PublicKey, error) {
	tlsConf, err := devpki.LoadClientTLS(tlsDir, "localhost") // 验管理面服务端证书(SAN localhost)
	if err != nil {
		return cred.PublicKey{}, fmt.Errorf("加载管理面 TLS: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trustURL+"/api/v1/trust/pubkey", nil)
	if err != nil {
		return cred.PublicKey{}, fmt.Errorf("构造 TrustBundle 请求: %w", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}
	resp, err := client.Do(req)
	if err != nil {
		return cred.PublicKey{}, fmt.Errorf("取 TrustBundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cred.PublicKey{}, fmt.Errorf("取 TrustBundle 返回 %s", resp.Status)
	}
	var body struct {
		Alg    string `json:"alg"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return cred.PublicKey{}, fmt.Errorf("解析 TrustBundle: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.Pubkey)
	if err != nil || len(raw) == 0 {
		return cred.PublicKey{}, fmt.Errorf("TrustBundle 公钥非法")
	}
	return cred.PublicKey{Alg: body.Alg, Bytes: raw}, nil
}

// subscribeLoop 带重连地跑一个 xDS 订阅(server 重启/抖动后自动重订阅)。
func subscribeLoop(ctx context.Context, name string, sub func() error) {
	for ctx.Err() == nil {
		if err := sub(); err != nil && ctx.Err() == nil {
			log.Printf("[pop-agent] %s 订阅断开,2s 后重连: %v", name, err)
			time.Sleep(2 * time.Second)
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envMust(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("pop-agent: 须设环境变量 %s", k)
	}
	return v
}

// truthy 判定布尔型环境变量(1/true/yes/on,大小写不敏感)。
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
