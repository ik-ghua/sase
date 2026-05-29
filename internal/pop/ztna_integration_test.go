package pop_test

// Slice 3 端到端:编译策略 → xDS 下发 → PoP 装载 → Agent 携凭证访问 → PoP 验凭证 + PEP 裁决
// → 放行经 Connector 出站反向通道抵达 echo 应用;拒绝/过期/默认拒绝均验证。
// 需 SASE_DB_RW_DSN(+可选 RO);未设则 SKIP。前置:已应用 migrations/0001+0002。-run TestZTNA。

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/agent"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/echo"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/pop"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/revtunnel"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
	"github.com/ikuai8/sase/internal/xds"
)

func TestZTNADataPathEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 ZTNA 端到端测试")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	// 控制面:签发器 + 服务
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("生成签发器: %v", err)
	}
	tenantSvc := tenant.NewService(store)
	identitySvc := identity.NewService(store, identity.WithSigner(signer))
	resourceSvc := resource.NewService(store)
	policySvc := policy.NewService(store, policy.WithAppRegistry(resourceSvc)) // 编译校验应用引用
	swgSvc := swg.NewService(store)
	dlpSvc := dlp.NewService(store)

	tid := uuid.NewString()
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "TZTNA"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}
	// 资源注册:app1/app2(策略引用,编译校验存在性)
	mustApp(t, resourceSvc, tid, "app1")
	mustApp(t, resourceSvc, tid, "app2")
	// 策略:g1 inspect app1(放行但导入 SWG);g1 拒绝 app2;app3 无规则(默认拒绝)
	mustPol(t, policySvc, tid, &policy.Policy{Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectInspect})
	mustPol(t, policySvc, tid, &policy.Policy{Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app2", Action: "connect", Effect: xdsv1.EffectDeny})
	if _, err := policySvc.Compile(ctx, tid); err != nil {
		t.Fatalf("编译: %v", err)
	}
	// SWG 规则:阻断 path 前缀 /admin(inspect 流量过此过滤)
	if err := swgSvc.CreateRule(ctx, tid, &swg.Rule{Kind: swg.KindPathPrefix, Pattern: "/admin", Action: swg.ActionBlock}); err != nil {
		t.Fatalf("建 SWG 规则: %v", err)
	}
	// DLP 规则:内容含关键词 "secret" → block(inspect 流量过 DLP 检测,命中喂风险)
	if err := dlpSvc.CreateRule(ctx, tid, &dlp.Rule{Name: "机密关键词", MatchType: dlp.MatchKeyword, Pattern: "secret", Action: dlp.ActionBlock, Severity: dlp.SeverityHigh}); err != nil {
		t.Fatalf("建 DLP 规则: %v", err)
	}

	// xDS server(mTLS gRPC ADS/Delta)+ PoP 订阅装载 bundle
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("建 CA: %v", err)
	}
	srvTLS, err := ca.ServerTLS("xds-server")
	if err != nil {
		t.Fatalf("server TLS: %v", err)
	}
	cliTLS, err := ca.ClientTLS("xds-server")
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	// 数据面 mTLS(连接器反向隧道 + Agent 接入面);同一 CA,SAN/ServerName 用 localhost
	dataSrvTLS, err := ca.ServerTLS("localhost")
	if err != nil {
		t.Fatalf("data server TLS: %v", err)
	}
	dataCliTLS, err := ca.ClientTLS("localhost")
	if err != nil {
		t.Fatalf("data client TLS: %v", err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
	xsrv := xds.NewServer(subCtx, store)
	xsrv.Register(gs)
	xlis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("xds 监听: %v", err)
	}
	go func() { _ = gs.Serve(xlis) }()
	defer gs.Stop()
	// LISTEN/NOTIFY:策略 + 撤销变更触发推送(撤销走独立流)
	cfgDSN := cfg.RWConnString
	go func() { _ = data.ListenNotify(subCtx, cfgDSN, data.NotifyChannelPolicyBundle, xsrv.OnNotify) }()
	go func() { _ = data.ListenNotify(subCtx, cfgDSN, data.NotifyChannelRevocation, xsrv.OnRevocationNotify) }()

	go func() { _ = data.ListenNotify(subCtx, cfgDSN, data.NotifyChannelSWG, xsrv.OnSWGNotify) }()
	go func() { _ = data.ListenNotify(subCtx, cfgDSN, data.NotifyChannelDLP, xsrv.OnDLPNotify) }()

	bundles := pop.NewBundleStore()
	revoked := pop.NewRevocationStore()
	swgStore := pop.NewSWGStore()
	dlpStore := pop.NewDLPStore()
	addr := xlis.Addr().String()
	go func() {
		_ = pop.SubscribeXDS(subCtx, addr, cliTLS, tid, "pop-test", func(b xdsv1.PolicyBundle) { bundles.Set(b) })
	}()
	go func() {
		_ = pop.SubscribeRevocations(subCtx, addr, cliTLS, tid, "pop-test", func(jtis []string) { revoked.Set(tid, jtis) })
	}()
	go func() {
		_ = pop.SubscribeSWG(subCtx, addr, cliTLS, tid, "pop-test", func(rules []swg.Rule) { swgStore.Set(tid, rules) })
	}()
	go func() {
		_ = pop.SubscribeDLP(subCtx, addr, cliTLS, tid, "pop-test", func(rules []dlp.Rule) { dlpStore.Set(tid, rules) })
	}()
	waitUntil(t, 5*time.Second, "PoP 装载 bundle", func() bool {
		_, ok := bundles.Get(tid)
		return ok
	})
	waitUntil(t, 5*time.Second, "PoP 装载 SWG 规则", func() bool { return len(swgStore.Get(tid)) > 0 })
	waitUntil(t, 5*time.Second, "PoP 装载 DLP 规则", func() bool { return len(dlpStore.Get(tid)) > 0 })

	// Connector 反向通道(mTLS)+ echo 应用(仅 app1 有连接器)
	reg := revtunnel.NewRegistry()
	rawLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("连接器监听: %v", err)
	}
	connLis := tls.NewListener(rawLis, dataSrvTLS)
	go func() { _ = reg.Accept(ctx, connLis) }()
	echoSrv := httptest.NewServer(echo.Handler("app1"))
	defer echoSrv.Close()
	go func() {
		_ = revtunnel.Serve(ctx, rawLis.Addr().String(), dataCliTLS, revtunnel.Hello{Tenant: tid, App: "app1"},
			func(req revtunnel.Request) revtunnel.Response { return proxyTo(ctx, echoSrv.URL, req) })
	}()

	// PoP 接入面(HTTPS / mTLS)
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("构造验证器: %v", err)
	}
	rec := metrics.NewRecorder()
	dlpSink := &captureSink{}
	ingress := pop.NewIngress(verifier, bundles, revoked, swgStore, swg.NewRuleEngine(), reg, rec).
		WithDLP(dlpStore, dlp.NewRuleEngine(), dlpSink)
	ilis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("接入面监听: %v", err)
	}
	isrv := &http.Server{Handler: ingress.Handler(), TLSConfig: dataSrvTLS}
	go func() { _ = isrv.ServeTLS(ilis, "", "") }()
	defer isrv.Close()
	popURL := "https://" + ilis.Addr().String()

	// 经 identity 模块签发(走真实令牌交换路径,L1 3.4);多数断言不关心 jti
	tok := func(groups []string, ttl time.Duration) string {
		s, _, err := identitySvc.IssueCredential(ctx, tid, "u1", groups, "", ttl)
		if err != nil {
			t.Fatalf("签发: %v", err)
		}
		return s
	}

	// 等连接器注册就绪(放行后不再是 502)
	allowTok := tok([]string{"g1"}, 5*time.Minute)
	waitUntil(t, 5*time.Second, "连接器注册", func() bool {
		st, _, _ := agent.Access(ctx, popURL, dataCliTLS, allowTok, "app1", "/")
		return st != http.StatusBadGateway
	})

	// ① 放行:g1 → app1 → 200 + echo
	st, body, err := agent.Access(ctx, popURL, dataCliTLS, allowTok, "app1", "/")
	if err != nil {
		t.Fatalf("访问 app1: %v", err)
	}
	if st != http.StatusOK || !strings.Contains(body, "echo[app1]") {
		t.Fatalf("g1 访问 app1 应放行+抵达应用,得 %d: %q", st, body)
	}

	// ② 显式拒绝:g1 → app2 → 403
	if st, _, _ := agent.Access(ctx, popURL, dataCliTLS, allowTok, "app2", "/"); st != http.StatusForbidden {
		t.Fatalf("g1 访问 app2 应 403(显式 deny),得 %d", st)
	}

	// ③ 默认拒绝:app3 无规则 → 403
	if st, _, _ := agent.Access(ctx, popURL, dataCliTLS, allowTok, "app3", "/"); st != http.StatusForbidden {
		t.Fatalf("访问无规则 app3 应默认拒绝 403,得 %d", st)
	}

	// ④ subject 不匹配:g2 → app1 → 403
	if st, _, _ := agent.Access(ctx, popURL, dataCliTLS, tok([]string{"g2"}, 5*time.Minute), "app1", "/"); st != http.StatusForbidden {
		t.Fatalf("g2 访问 app1 应 403(组不匹配),得 %d", st)
	}

	// ⑤ 过期凭证 → 401
	if st, _, _ := agent.Access(ctx, popURL, dataCliTLS, tok([]string{"g1"}, -time.Second), "app1", "/"); st != http.StatusUnauthorized {
		t.Fatalf("过期凭证应 401,得 %d", st)
	}

	// ⑥ 无凭证 → 401
	if st, _, _ := agent.Access(ctx, popURL, dataCliTLS, "garbage.token", "app1", "/"); st != http.StatusUnauthorized {
		t.Fatalf("非法凭证应 401,得 %d", st)
	}

	// ⑦ 秒级失效:签发→放行→撤销→(经撤销独立流)秒级拒,无需等 TTL
	revTok, revJTI, err := identitySvc.IssueCredential(ctx, tid, "u-rev", []string{"g1"}, "", 5*time.Minute)
	if err != nil {
		t.Fatalf("签发待撤销凭证: %v", err)
	}
	if st, _, _ := agent.Access(ctx, popURL, dataCliTLS, revTok, "app1", "/"); st != http.StatusOK {
		t.Fatalf("撤销前应放行,得 %d", st)
	}
	if err := identitySvc.RevokeCredential(ctx, tid, revJTI, "u-rev", "test"); err != nil {
		t.Fatalf("撤销: %v", err)
	}
	// 撤销经 NOTIFY → xDS 独立流 → PoP 吊销集,应在秒级内拒(401)
	waitUntil(t, 8*time.Second, "撤销秒级生效", func() bool {
		st, _, _ := agent.Access(ctx, popURL, dataCliTLS, revTok, "app1", "/")
		return st == http.StatusUnauthorized
	})

	// ⑧ 安全能力 SWG:app1 为 inspect 效果,流量过 SWG URL 过滤
	swgTok := tok([]string{"g1"}, 5*time.Minute)
	// ⑧a 正常 path → SWG 放行 → 抵达应用
	if st, body, _ := agent.Access(ctx, popURL, dataCliTLS, swgTok, "app1", "/ok"); st != http.StatusOK || !strings.Contains(body, "echo[app1]") {
		t.Fatalf("SWG 应放行 /ok 并抵达应用,得 %d: %q", st, body)
	}
	// ⑧b 命中阻断前缀 /admin → SWG 拒(403)
	if st, _, _ := agent.Access(ctx, popURL, dataCliTLS, swgTok, "app1", "/admin/x"); st != http.StatusForbidden {
		t.Fatalf("SWG 应阻断 /admin,得 %d", st)
	}

	// ⑧c 安全能力 CASB-DLP:inspect 流量过内容检测。path 含 "secret" → DLP block(403)+ 喂风险(finding)
	if st, _, _ := agent.Access(ctx, popURL, dataCliTLS, swgTok, "app1", "/data?q=secret"); st != http.StatusForbidden {
		t.Fatalf("DLP 应阻断含 secret 的内容,得 %d", st)
	}
	if dlpSink.count() < 1 {
		t.Error("DLP 命中应喂到 finding sink(待风险引擎)")
	}
	if rec.AccessValue(metrics.OutcomeDLPBlocked) < 1 {
		t.Error("应记录到 dlp_blocked")
	}

	// ⑨ 可观测:接入面决策已计入指标(运维 L2 3.4)
	if rec.AccessValue(metrics.OutcomeInspect) < 1 {
		t.Error("应记录到 inspect 放行")
	}
	if rec.AccessValue(metrics.OutcomeDeny) < 1 {
		t.Error("应记录到 deny")
	}
	if rec.AccessValue(metrics.OutcomeSWGBlocked) < 1 {
		t.Error("应记录到 swg_blocked")
	}
	if rec.AccessValue(metrics.OutcomeRevoked) < 1 {
		t.Error("应记录到 revoked")
	}
}

// captureSink 是测试用 dlp.FindingSink:计数命中(验 DLP 命中喂风险引擎这条路被走到)。
type captureSink struct {
	mu sync.Mutex
	n  int
}

func (s *captureSink) Report(_, _, _ string, _ dlp.Finding) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
}
func (s *captureSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func mustApp(t *testing.T, svc resource.Service, tid, appKey string) {
	t.Helper()
	if err := svc.CreateApp(context.Background(), tid, &resource.App{AppKey: appKey, Name: appKey}); err != nil {
		t.Fatalf("注册应用 %s: %v", appKey, err)
	}
}

func mustPol(t *testing.T, svc policy.Service, tid string, p *policy.Policy) {
	t.Helper()
	if err := svc.CreatePolicy(context.Background(), tid, p); err != nil {
		t.Fatalf("建策略: %v", err)
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
