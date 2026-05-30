// Command cpe 是 SD-WAN 软件 CPE(客户分支站点边缘,跑客户硬件/虚机)。
// Slice:① 以 site_key 注册为 PoP 反向连接器(终结侧:收对端站点流量交本地 LAN/上游)②订阅 SiteConfig(知对端站点)。
// 发起侧(本站 LAN → 对端站点)由 internal/cpe.SendToSite 触发(真实 CPE 据路由表,本 slice 由上层/测试驱动)。
// FEC/包级冗余(需 L3 包路径)、隧道国密加密待后续刀;当前用 mTLS stand-in。
//
// WAN 多链路(可选):设 WAN_LINKS="wan0=host:port,wan1=host:port,…"(按序优先级,首条最高)启用多上联
// 健康探测+选路+亚秒故障切换(linkmon);不设则单链路用 POP_CONNECTOR_ADDR。
//
// ZTP 入网(推荐):设 ZTP_CODE=<激活码>(+ MGMT_URL),本地生成密钥+CSR 换取租户绑定证书(身份=site_key,
// 私钥永不离开);该证书同时用于注册 PoP 反向通道与订阅 SiteConfig;不设则回退 dev 共享证书。
//
//	用法:POP_CONNECTOR_ADDR=127.0.0.1:7000 XDS_ADDR=127.0.0.1:9090 SASE_TLS_DIR=./certs \
//	      TENANT=<uuid> SITE=site-bj UPSTREAM_URL=http://127.0.0.1:9000 TOKEN=<cpe-cred> [ZTP_CODE=...] [WAN_LINKS=...] cpe
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"net"

	"github.com/ikuai8/sase/internal/cpe"
	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/linkmon"
	"github.com/ikuai8/sase/internal/pop"
	"github.com/ikuai8/sase/internal/revtunnel"
	"github.com/ikuai8/sase/internal/tunhandshake"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("cpe: %v", err)
	}
}

func run() error {
	popConnAddr := envMust("POP_CONNECTOR_ADDR")
	xdsAddr := envOr("XDS_ADDR", "127.0.0.1:9090")
	tlsDir := envOr("SASE_TLS_DIR", "./certs")
	tenant := envMust("TENANT")
	siteKey := envMust("SITE")
	upstream := envMust("UPSTREAM_URL")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ZTP_CODE 非空走 ZTP 取租户绑定证书(身份=site_key),否则回退 dev 共享证书;证书供注册+订阅两用
	ztpCode := os.Getenv("ZTP_CODE")
	mgmtURL := envOr("MGMT_URL", "https://localhost:8443")
	tlsConf, rotator, err := enroll.DeviceTLS(ctx, tlsDir, mgmtURL, "localhost", ztpCode, siteKey)
	if err != nil {
		return err
	}
	if rotator != nil {
		log.Printf("[cpe] site=%s 已 ZTP 取证书(租户绑定),启动自动续期", siteKey)
		renewURL := envOr("DEVICE_URL", "https://localhost:8444")
		go enroll.RunRenewLoop(ctx, rotator, renewURL, tlsDir, "localhost", siteKey, 8*time.Hour)
	}

	// SD-WAN 真隧道模式(可选,gated):设 SDWAN_TUNNEL=1 → 走 dptunnel 数据面(握手 + TUN + UDP),
	// 而非默认的 revtunnel(L7 HTTP stand-in)。需 SDWAN_TUNNEL_ADDR(PoP 握手地址)+ TUN(CAP_NET_ADMIN)。
	if truthy(os.Getenv("SDWAN_TUNNEL")) {
		return runTunnel(ctx, tlsConf, tenant, siteKey)
	}

	store := cpe.NewSiteStore()
	// ②订阅 SiteConfig(对端站点)
	go func() {
		for ctx.Err() == nil {
			subErr := pop.SubscribeSites(ctx, xdsAddr, tlsConf, tenant, "cpe-"+siteKey, func(sites []pop.SiteInfo) {
				store.Set(sites)
				log.Printf("[cpe] site=%s 路由域站点 %d 个", siteKey, len(sites))
			})
			if subErr != nil && ctx.Err() == nil {
				log.Printf("[cpe] 站点订阅断开,重连: %v", subErr)
			}
		}
	}()

	// ①终结侧:以 site_key 注册为 PoP 反向连接器,把对端流量代理到本地上游
	handler := func(req revtunnel.Request) revtunnel.Response { return proxy(ctx, upstream, req) }
	hello := revtunnel.Hello{Tenant: tenant, App: siteKey}

	// WAN_LINKS 启用多上联健康探测+选路+亚秒切换;否则单链路(POP_CONNECTOR_ADDR)。
	// 注:linkmon 选路用于数据面反向隧道;xDS 控制面订阅仍走 XDS_ADDR(控制面多归属另议)。
	if wanLinks := os.Getenv("WAN_LINKS"); wanLinks != "" {
		links, perr := parseLinks(wanLinks)
		if perr != nil {
			return perr
		}
		mon := linkmon.New(links, linkmon.NewTCPProber(), linkmon.Config{Interval: 200 * time.Millisecond, Window: 3})
		go mon.Run(ctx)
		log.Printf("[cpe] site=%s WAN 多链路监测启动(%d 条),本地上游 %s", siteKey, len(links), upstream)
		multiLinkServe(ctx, mon, connMaxAge(), tlsConf, hello, handler)
		return nil
	}

	log.Printf("[cpe] site=%s 注册到 PoP %s(mTLS,单链路),本地上游 %s", siteKey, popConnAddr, upstream)
	// 重连循环 + 每连接最长存活(< 证书有效期):周期重握手,使续期新证书生效、撤销在有界时间内生效
	serveLoop(ctx, connMaxAge(), func(connCtx context.Context) error {
		return revtunnel.Serve(connCtx, popConnAddr, tlsConf, hello, handler)
	})
	return nil
}

// parseLinks 解析 WAN_LINKS="wan0=host:port,wan1=host:port"(按序赋优先级,首条最高=0)。
// 名字须唯一——重名会致 linkmon 内 health 表覆盖、选路错乱,故 fail-closed 报错。
func parseLinks(spec string) ([]linkmon.Link, error) {
	parts := strings.Split(spec, ",")
	links := make([]linkmon.Link, 0, len(parts))
	seen := map[string]bool{}
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, addr, ok := strings.Cut(part, "=")
		name, addr = strings.TrimSpace(name), strings.TrimSpace(addr)
		if !ok || name == "" || addr == "" {
			return nil, fmt.Errorf("WAN_LINKS 项 %q 非法,应为 name=host:port", part)
		}
		if seen[name] {
			return nil, fmt.Errorf("WAN_LINKS 链路名 %q 重复", name)
		}
		seen[name] = true
		links = append(links, linkmon.Link{Name: name, Addr: addr, Priority: i})
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("WAN_LINKS 为空")
	}
	return links, nil
}

// multiLinkServe 按 monitor 选最优链路拨号注册;活动链路失效即取消重选(故障切换),并周期重握手。
// 切换时延(探测层):活动链路失效后,探测窗判 down(Window=3、Interval=200ms → ~2 次失败约 400ms)
// + watchFailover 100ms 轮询发现 + ~250ms 退避 ≈ 700ms,端到端再加一次 mTLS 握手 RTT。称"亚秒"指探测层。
func multiLinkServe(ctx context.Context, mon *linkmon.Monitor, maxAge time.Duration, tlsConf *tls.Config, hello revtunnel.Hello, handler func(revtunnel.Request) revtunnel.Response) {
	var active string
	for ctx.Err() == nil {
		link, ok := mon.Best()
		if !ok {
			log.Printf("[cpe] 无健康 WAN 链路,等待…")
			if sleepCtx(ctx, 200*time.Millisecond) { // 短等(含冷启动首轮探测),避免首连长延迟
				return
			}
			continue
		}
		if link.Name != active {
			log.Printf("[cpe] 活动 WAN 链路 → %s(%s,prio=%d)", link.Name, link.Addr, link.Priority)
			active = link.Name
		}
		connCtx, cancel := context.WithTimeout(ctx, maxAge)
		go watchFailover(connCtx, mon, link, cancel)
		err := revtunnel.Serve(connCtx, link.Addr, tlsConf, hello, handler)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("[cpe] 链路 %s 断开,重选: %v", link.Name, err)
		}
		if sleepCtx(ctx, 250*time.Millisecond) {
			return
		}
	}
}

// 回切滞后:更高优先级链路须连续稳定 dwellChecks 次(×100ms)才回切,抑制边缘抖动(flapping)造成的重连风暴。
const dwellChecks = 20 // ~2s

// watchFailover 监视活动链路:① 活动链路失效 → 立即取消(故障切换,亚秒);② 仅当严格更高优先级链路稳定可用
// 达 dwell 才取消(回切)。不为"边缘抖动/同优先级"抢断正常连接——避免反复拆建 mTLS 连接。
func watchFailover(ctx context.Context, mon *linkmon.Monitor, active linkmon.Link, cancel context.CancelFunc) {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	betterStreak := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !mon.IsUp(active.Name) {
				cancel() // 活动链路失效 → 立即故障切换
				return
			}
			if best, ok := mon.Best(); ok && best.Priority < active.Priority {
				betterStreak++
				if betterStreak >= dwellChecks {
					cancel() // 更高优先级链路稳定 → 回切
					return
				}
			} else {
				betterStreak = 0
			}
		}
	}
}

// sleepCtx 睡 d 或 ctx 取消;返回 true 表示 ctx 已取消。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(d):
		return false
	}
}

func serveLoop(ctx context.Context, maxAge time.Duration, serve func(context.Context) error) {
	for ctx.Err() == nil {
		connCtx, cancel := context.WithTimeout(ctx, maxAge)
		err := serve(connCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("[cpe] 连接断开,重连: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func connMaxAge() time.Duration {
	if v := os.Getenv("CONN_MAX_AGE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

func proxy(ctx context.Context, upstream string, req revtunnel.Request) revtunnel.Response {
	r, err := http.NewRequestWithContext(ctx, req.Method, upstream+req.Path, nil)
	if err != nil {
		return revtunnel.Response{Status: http.StatusBadGateway, Err: err.Error()}
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return revtunnel.Response{Status: http.StatusBadGateway, Err: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return revtunnel.Response{Status: resp.StatusCode, Body: string(body)}
}

// runTunnel 走 SD-WAN 真数据面隧道:握手(mutual TLS + 密钥导出,用 ZTP 证书)→ dptunnel 会话 → TUN↔UDP pump。
// 身份(tenant/site)绑在 ZTP 证书,PoP 据此登记 Router。NAT 下回程依赖 receiver-index(待握手 L2 §4.4,本刀非 NAT)。
func runTunnel(ctx context.Context, tlsConf *tls.Config, tenant, site string) error {
	hsAddr := envMust("SDWAN_TUNNEL_ADDR")
	// 算法档:dev 取 env 默认;**生产应取自控制面下发的租户档(xDS),非本地 env**——否则"防降级"只防到本地配置层。
	alg := envOr("SDWAN_TUNNEL_ALG", dptunnel.AlgChaCha20Poly1305)

	dataConn, err := net.ListenPacket("udp", envOr("SDWAN_DATA_ADDR", "127.0.0.1:0"))
	if err != nil {
		return fmt.Errorf("监听本地数据面 UDP: %w", err)
	}
	defer dataConn.Close()

	// 通告给 PoP 的本端数据面地址(PoP 回程目的 + 入向解复用 bySrc 键)。
	// 默认取本地监听地址,但 0.0.0.0/ephemeral 绑定下 LocalAddr 不是对端可达地址——
	// 容器/多址部署须经 SDWAN_DATA_ADV 显式设为 PoP 可达且与实际 UDP 源地址一致的地址
	// (如 "cpe-site-a:7101";Docker 嵌入式 DNS 解析为容器 IP,与 PoP 看到的源 IP+端口一致)。
	// 否则 PoP 的 bySrc 解复用命中失败(no_session 丢包)且回程会被发往不可达的环回地址。
	advAddr := envOr("SDWAN_DATA_ADV", dataConn.LocalAddr().String())

	res, err := tunhandshake.Dial(ctx, hsAddr, tlsConf, alg, advAddr, tenant, site)
	if err != nil {
		return err
	}
	sess, err := res.Session()
	if err != nil {
		return err
	}
	tun, name, err := dptunnel.OpenTUN(os.Getenv("SDWAN_TUN"))
	if err != nil {
		return fmt.Errorf("打开 TUN(需 CAP_NET_ADMIN): %w", err)
	}
	log.Printf("[cpe] SD-WAN 真隧道:site=%s TUN=%s 本端通告=%s PoP数据面=%s 档=%s", site, name, advAddr, res.PoPDataAddr, res.Alg)
	log.Printf("[cpe] 提示:须为 %s 配 IP/路由(本站子网→%s),使本地 L3 包进隧道", name, name)
	dptunnel.NewEndpoint(sess, tun, dataConn, res.PoPDataAddr).Run(ctx) // 阻塞到 ctx 取消或 pump 出错
	return nil
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
		log.Fatalf("cpe: 须设环境变量 %s", k)
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
