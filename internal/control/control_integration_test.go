package control_test

// Slice 6 端到端:Agent 接入控制面实时通道 → 控制面下推 revoke(端提速)→ Agent 秒级本地弃用凭证。
// 含持续自适应:推 recheck_posture → Agent 上报非合规 → 控制面自适应撤销 → 下推 revoke → Agent 弃用。
// 需 SASE_DB_RW_DSN(RevokeCredential 写吊销表);未设则 SKIP。前置:已应用 migrations/0001-0003。-run TestControl。

import (
	"context"
	"net"
	"testing"
	"time"

	"crypto/tls"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	controlpb "github.com/ikuai8/sase/api/proto/sase/control/v1"
	"github.com/ikuai8/sase/internal/agent"
	"github.com/ikuai8/sase/internal/control"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/identity"
)

// setup 起一个控制面:identity(签发/撤销)+ hub(实时通道,mTLS)+ gRPC server,返回 svc、hub、地址、客户端 TLS。
func setup(ctx context.Context, t *testing.T) (identity.Service, *control.Hub, string, *tls.Config) {
	t.Helper()
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过控制通道端到端测试")
	}
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	t.Cleanup(store.Close)

	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("签发器: %v", err)
	}
	credVerifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("验证器: %v", err)
	}
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	srvTLS, err := ca.ServerTLS("localhost")
	if err != nil {
		t.Fatalf("server TLS: %v", err)
	}
	cliTLS, err := ca.ClientTLS("localhost")
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}

	hub := control.NewHub(credVerifier)
	identitySvc := identity.NewService(store, identity.WithSigner(signer), identity.WithRevocationNotifier(hub))
	// 持续自适应:非合规姿态 → 撤销
	//nolint:contextcheck // 撤销是异步事件反应,用独立 background ctx(不绑 Agent 流/测试 ctx 生命周期)
	hub.SetPostureHandler(func(tenantID, subject, jti, posture string) {
		if posture != "compliant" {
			_ = identitySvc.RevokeCredential(context.Background(), tenantID, jti, subject, "posture:"+posture)
		}
	})

	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
	controlpb.RegisterAgentControlServer(gs, hub)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return identitySvc, hub, lis.Addr().String(), cliTLS
}

// TestControlChannelRevokePush:撤销经实时通道秒级推到 Agent(端提速)。
func TestControlChannelRevokePush(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identitySvc, hub, addr, cliTLS := setup(ctx, t)

	tid := uuid.NewString()
	token, jti, err := identitySvc.IssueCredential(ctx, tid, "u1", []string{"g1"}, "compliant", 5*time.Minute)
	if err != nil {
		t.Fatalf("签发: %v", err)
	}

	sess := agent.NewSession(jti, "compliant")
	go func() { _ = sess.RunControlChannel(ctx, addr, cliTLS, token) }()
	waitUntil(t, 5*time.Second, "Agent 接入", func() bool { return hub.ConnCount(tid) == 1 })

	if sess.Revoked() {
		t.Fatal("撤销前不应为已撤销")
	}
	if err := identitySvc.RevokeCredential(ctx, tid, jti, "u1", "test"); err != nil {
		t.Fatalf("撤销: %v", err)
	}
	// 端提速:Agent 经实时通道秒级感知撤销
	waitUntil(t, 5*time.Second, "Agent 秒级感知撤销", sess.Revoked)
}

// TestControlChannelAdaptivePosture:推重采姿态 → Agent 报非合规 → 自适应撤销 → 下推 revoke → Agent 弃用。
func TestControlChannelAdaptivePosture(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identitySvc, hub, addr, cliTLS := setup(ctx, t)

	tid := uuid.NewString()
	token, jti, err := identitySvc.IssueCredential(ctx, tid, "u2", []string{"g1"}, "compliant", 5*time.Minute)
	if err != nil {
		t.Fatalf("签发: %v", err)
	}

	sess := agent.NewSession(jti, "compliant")
	go func() { _ = sess.RunControlChannel(ctx, addr, cliTLS, token) }()
	waitUntil(t, 5*time.Second, "Agent 接入", func() bool { return hub.ConnCount(tid) == 1 })

	// 设备转为非合规 → 控制面推重采 → Agent 上报非合规 → 自适应撤销
	sess.SetPosture("non-compliant")
	hub.PushRecheckPosture(tid)
	waitUntil(t, 6*time.Second, "自适应撤销经实时通道生效", sess.Revoked)
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
