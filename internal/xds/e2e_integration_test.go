package xds_test

// 端到端切片测试(Slice 2):policy 编译 → 落库激活 → xds-server 下发 → pop 客户端收到。
// 需 SASE_DB_RW_DSN(+可选 RO);未设则 SKIP。前置:已应用 migrations/0001+0002。
//
// 跑法(VM,PG 在本机,容器化 Go):见 internal/data/rls_integration_test.go 注释,-run TestE2E。

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/pop"
	"github.com/ikuai8/sase/internal/tenant"
	"github.com/ikuai8/sase/internal/xds"
)

// startXDS 起一个 mTLS gRPC 的 xds-server(localhost 随机端口),返回拨号地址与客户端 TLS 配置。
func startXDS(ctx context.Context, t *testing.T, store data.Store) (string, *tls.Config, *metrics.ControlRecorder) {
	t.Helper()
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
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
	srv := xds.NewServer(ctx, store)
	rec := metrics.NewControlRecorder()
	srv.SetMetrics(rec)
	srv.Register(gs)
	// 接 LISTEN/NOTIFY:租户 bundle 变更触发增量重载(xDS server L2 3.5)
	if cfg, ok := data.ConfigFromEnv(); ok {
		go func() { _ = data.ListenNotify(ctx, cfg.RWConnString, data.NotifyChannelPolicyBundle, srv.OnNotify) }()
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String(), cliTLS, rec
}

func newStore(t *testing.T) data.Store {
	t.Helper()
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过端到端切片测试")
	}
	store, err := data.NewPgxStore(context.Background(), cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

// TestE2ECompileServeReceive:编译→下发→PoP 收到,验证版本/规则/hash 与幂等、fail-closed。
func TestE2ECompileServeReceive(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	tenantSvc := tenant.NewService(store)
	policySvc := policy.NewService(store)

	tid := uuid.NewString()
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "TE2E"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}
	// 两条策略(乱序优先级)
	mustPolicy(t, policySvc, tid, &policy.Policy{Priority: 200, SubjectKind: "group", SubjectValue: "g2", Resource: "app2", Action: "connect", Effect: xdsv1.EffectDeny})
	mustPolicy(t, policySvc, tid, &policy.Policy{Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow})

	// 首次编译:产新版
	res, err := policySvc.Compile(ctx, tid)
	if err != nil {
		t.Fatalf("编译: %v", err)
	}
	if !res.Changed || res.Version < 1 {
		t.Fatalf("首次编译应产新版,得 %+v", res)
	}

	// 幂等:再编译同策略 → 不产新版
	res2, err := policySvc.Compile(ctx, tid)
	if err != nil {
		t.Fatalf("再编译: %v", err)
	}
	if res2.Changed || res2.Version != res.Version || res2.ContentHash != res.ContentHash {
		t.Fatalf("同策略再编译应幂等,得 %+v(首次 %+v)", res2, res)
	}

	// 起 xds-server(mTLS gRPC ADS)+ pop 订阅,收第一个 bundle
	subCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addr, cliTLS, rec := startXDS(subCtx, t, store)
	got := make(chan xdsv1.PolicyBundle, 1)
	go func() {
		_ = pop.SubscribeXDS(subCtx, addr, cliTLS, tid, "pop-test", func(b xdsv1.PolicyBundle) {
			select {
			case got <- b:
			default:
			}
			cancel() // 收到第一个即收尾
		})
	}()

	var b xdsv1.PolicyBundle
	select {
	case b = <-got:
	case <-time.After(8 * time.Second):
		t.Fatal("超时:pop 未收到 bundle")
	}

	if b.TenantID != tid {
		t.Fatalf("bundle 租户错:%s", b.TenantID)
	}
	if b.Version != res.Version || b.ContentHash != res.ContentHash {
		t.Fatalf("下发 bundle 版本/hash 与编译不符:下发 v%d/%s,编译 v%d/%s", b.Version, b.ContentHash, res.Version, res.ContentHash)
	}
	if len(b.L7Rules) != 2 || b.L7Rules[0].Priority != 10 || b.L7Rules[1].Priority != 200 {
		t.Fatalf("下发规则数/排序错:%+v", b.L7Rules)
	}
	// 可观测:xDS 下发已计入指标(运维 L2 3.10)
	if rec.XDSPushValue(metrics.ResourcePolicy) < 1 {
		t.Error("应记录到 policy 资源下发计数")
	}

	// fail-closed:加冲突策略 → 编译失败 → 激活版不变
	mustPolicy(t, policySvc, tid, &policy.Policy{Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectDeny})
	if _, err := policySvc.Compile(ctx, tid); err == nil {
		t.Fatal("冲突策略应编译失败")
	}
	active, err := policySvc.ActiveBundle(ctx, tid)
	if err != nil {
		t.Fatalf("读激活版: %v", err)
	}
	if active.Version != res.Version {
		t.Fatalf("编译失败后激活版不应变:期望 v%d,得 v%d", res.Version, active.Version)
	}
}

func mustPolicy(t *testing.T, svc policy.Service, tid string, p *policy.Policy) {
	t.Helper()
	if err := svc.CreatePolicy(context.Background(), tid, p); err != nil {
		t.Fatalf("建策略: %v", err)
	}
}

// TestXDSNotifyPushesUpdate:订阅后再编译新版 → 经 LISTEN/NOTIFY 增量推送,PoP 无需重订阅即收到新版。
func TestXDSNotifyPushesUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newStore(t)
	tenantSvc := tenant.NewService(store)
	policySvc := policy.NewService(store)

	tid := uuid.NewString()
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "TNotify"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}
	mustPolicy(t, policySvc, tid, &policy.Policy{Priority: 10, SubjectKind: "group", SubjectValue: "g1", Resource: "app1", Action: "connect", Effect: xdsv1.EffectAllow})
	v1, err := policySvc.Compile(ctx, tid)
	if err != nil {
		t.Fatalf("编译 v1: %v", err)
	}

	addr, cliTLS, _ := startXDS(ctx, t, store)
	versions := make(chan int64, 8)
	go func() {
		_ = pop.SubscribeXDS(ctx, addr, cliTLS, tid, "pop-notify", func(b xdsv1.PolicyBundle) {
			versions <- b.Version
		})
	}()

	// 先收到 v1
	if got := waitVersion(t, versions, 5*time.Second); got != v1.Version {
		t.Fatalf("首版应为 v%d,得 v%d", v1.Version, got)
	}

	// 再加策略并编译 v2 → 应经 NOTIFY 自动推到 PoP
	mustPolicy(t, policySvc, tid, &policy.Policy{Priority: 20, SubjectKind: "group", SubjectValue: "g2", Resource: "app2", Action: "connect", Effect: xdsv1.EffectDeny})
	v2, err := policySvc.Compile(ctx, tid)
	if err != nil {
		t.Fatalf("编译 v2: %v", err)
	}
	if !v2.Changed || v2.Version <= v1.Version {
		t.Fatalf("v2 应为新版,得 %+v", v2)
	}
	deadline := time.After(8 * time.Second)
	for {
		select {
		case got := <-versions:
			if got == v2.Version {
				return // 收到新版,成功
			}
		case <-deadline:
			t.Fatalf("超时:未经 NOTIFY 收到 v%d", v2.Version)
		}
	}
}

func waitVersion(t *testing.T, ch <-chan int64, timeout time.Duration) int64 {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(timeout):
		t.Fatal("超时:未收到任何 bundle 版本")
		return 0
	}
}
