package cpe_test

// SD-WAN 第一刀端到端:注册站点 → xDS 下发 SiteConfig 给 CPE(配置底座复用)→ 站点 A 经 PoP overlay
// 抵达站点 B 的本地 echo(隧道底座 revtunnel 复用)。证「地基统一」对第二轨道成立。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:已应用 migrations/0001-0006。-run TestSDWAN。

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ikuai8/sase/internal/cpe"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/echo"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/pop"
	"github.com/ikuai8/sase/internal/revtunnel"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/tenant"
	"github.com/ikuai8/sase/internal/xds"
)

func TestSDWANSiteMeshEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 SD-WAN 端到端测试")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	signer, _ := cred.GenerateSigner()
	pub := signer.Public()
	tenantSvc := tenant.NewService(store)
	identitySvc := identity.NewService(store, identity.WithSigner(signer))
	siteSvc := site.NewService(store)

	tid := uuid.NewString()
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "TSDWAN"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}
	// 注册两站点(同租户路由域)
	mustSite(t, siteSvc, tid, "site-a", "10.0.0.0/24")
	mustSite(t, siteSvc, tid, "site-b", "10.0.1.0/24")

	// devpki / TLS
	ca, _ := devpki.NewCA()
	srvTLS, _ := ca.ServerTLS("xds-server")
	cliTLS, _ := ca.ClientTLS("xds-server")
	dataSrvTLS, _ := ca.ServerTLS("localhost")
	dataCliTLS, _ := ca.ClientTLS("localhost")

	// xDS server(下发 SiteConfig)+ LISTEN/NOTIFY
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
	xsrv := xds.NewServer(subCtx, store)
	xsrv.Register(gs)
	xlis, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = gs.Serve(xlis) }()
	defer gs.Stop()
	go func() {
		_ = data.ListenNotify(subCtx, cfg.RWConnString, data.NotifyChannelSite, xsrv.OnSiteNotify, nil)
	}()
	xdsAddr := xlis.Addr().String()

	// CPE_A 订阅 SiteConfig(验证配置下发底座复用)
	storeA := cpe.NewSiteStore()
	go func() {
		_ = pop.SubscribeSites(subCtx, xdsAddr, cliTLS, tid, "cpe-a", func(s []pop.SiteInfo) { storeA.Set(s) })
	}()
	waitUntil(t, 5*time.Second, "CPE_A 收到 SiteConfig(含 site-b)", func() bool {
		for _, s := range storeA.Sites() {
			if s.SiteKey == "site-b" && s.CIDR == "10.0.1.0/24" {
				return true
			}
		}
		return false
	})

	// PoP:连接器 registry + 站点 overlay 入口(复用隧道底座)
	reg := revtunnel.NewRegistry()
	connRaw, _ := net.Listen("tcp", "127.0.0.1:0")
	connLis := tls.NewListener(connRaw, dataSrvTLS)
	go func() { _ = reg.Accept(ctx, connLis) }()

	verifier, _ := cred.NewVerifier(pub)
	siteIngress := pop.NewSiteIngress(verifier, reg, metrics.NewRecorder())
	ilis, _ := net.Listen("tcp", "127.0.0.1:0")
	isrv := &http.Server{Handler: siteIngress.Handler(), TLSConfig: dataSrvTLS}
	go func() { _ = isrv.ServeTLS(ilis, "", "") }()
	defer isrv.Close()
	popSiteURL := "https://" + ilis.Addr().String()

	// CPE_B 终结侧:注册 site-b,把对端流量代理到本地 echo(站点 B 的 LAN 应用)
	echoB := httptest.NewServer(echo.Handler("site-b"))
	defer echoB.Close()
	go func() {
		_ = revtunnel.Serve(ctx, connRaw.Addr().String(), dataCliTLS,
			revtunnel.Hello{Tenant: tid, App: "site-b"},
			func(req revtunnel.Request) revtunnel.Response { return proxyTo(ctx, echoB.URL, req) })
	}()

	// CPE_A 凭证(ZTP 签发,标识 site-a)
	tokA, _, err := identitySvc.IssueCredential(ctx, tid, "site-a", nil, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("签发 CPE_A 凭证: %v", err)
	}

	// 等 CPE_B 注册就绪,再发:站点 A → PoP overlay → 站点 B
	waitUntil(t, 5*time.Second, "site-b 连接器注册", func() bool {
		st, _, _ := cpe.SendToSite(ctx, popSiteURL, dataCliTLS, tokA, "site-b", "/")
		return st != http.StatusBadGateway
	})
	st, body, err := cpe.SendToSite(ctx, popSiteURL, dataCliTLS, tokA, "site-b", "/app")
	if err != nil {
		t.Fatalf("站点A→站点B: %v", err)
	}
	if st != http.StatusOK || !strings.Contains(body, "echo[site-b]") {
		t.Fatalf("站点A 应经 PoP 抵达站点B 的应用,得 %d: %q", st, body)
	}
}

func mustSite(t *testing.T, svc site.Service, tid, key, cidr string) {
	t.Helper()
	if err := svc.CreateSite(context.Background(), tid, &site.Site{SiteKey: key, Name: key, CIDR: cidr}); err != nil {
		t.Fatalf("建站点 %s: %v", key, err)
	}
}

func proxyTo(ctx context.Context, upstream string, req revtunnel.Request) revtunnel.Response {
	r, err := http.NewRequestWithContext(ctx, req.Method, upstream+req.Path, nil)
	if err != nil {
		return revtunnel.Response{Status: http.StatusBadGateway, Err: err.Error()}
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return revtunnel.Response{Status: http.StatusBadGateway, Err: err.Error()}
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return revtunnel.Response{Status: resp.StatusCode, Body: string(buf[:n])}
}

func waitUntil(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("超时等待:%s", what)
}
