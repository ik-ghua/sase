package telemetry_test

// 遥测管道端到端:PoP Reporter → gRPC(回环)→ 控制面 Ingest → Sink。重点验**DLP 命中跨进程闭环到风险引擎**:
// Reporter.Report(DLP finding) → … → risk.Service.Report → 升 critical → 撤销回调触发。

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	telemetrypb "github.com/ikuai8/sase/api/proto/sase/telemetry/v1"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/risk"
	"github.com/ikuai8/sase/internal/telemetry"
)

// 起一个回环 gRPC server 承载 Ingest(sinks),返回连到它的 client + 关闭函数。
func dialIngest(t *testing.T, sinks ...telemetry.Sink) (telemetrypb.TelemetryClient, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	telemetrypb.RegisterTelemetryServer(gs, telemetry.NewIngest(false, sinks...))
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return telemetrypb.NewTelemetryClient(conn), func() { conn.Close(); gs.Stop() }
}

// 全链路闭环:Reporter(DLP 命中)→ gRPC → Ingest → risk-sink → risk.Service → critical → 撤销。
func TestDLPClosureThroughTelemetry(t *testing.T) {
	var mu sync.Mutex
	var revokedJTI string
	rs := risk.NewService(func(_, _, jti string, _ risk.Assessment) {
		mu.Lock()
		revokedJTI = jti
		mu.Unlock()
	})
	// 控制面 sink:dlp_finding 事件 → risk.Report(等价 api-server 的 riskTelemetrySink)
	sink := telemetry.SinkFunc(func(e telemetry.Event) {
		if e.Kind != telemetry.KindDLPFinding {
			return
		}
		rs.Report(e.TenantID, e.Subject, e.JTI, dlp.Finding{
			RuleName: e.Attrs[telemetry.AttrDLPRule],
			Severity: e.Attrs[telemetry.AttrDLPSeverity],
			Action:   e.Attrs[telemetry.AttrDLPAction],
		})
	})
	client, stop := dialIngest(t, sink)
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reporter := telemetry.NewReporter(client, 64)
	go reporter.Run(ctx)

	// PoP 侧:同一会话 jti-x 两条 high DLP 命中(累积 → critical)
	reporter.Report("t1", "alice", "jti-x", dlp.Finding{RuleName: "身份证", Severity: dlp.SeverityHigh})
	reporter.Report("t1", "alice", "jti-x", dlp.Finding{RuleName: "银行卡", Severity: dlp.SeverityHigh})

	// 异步:等闭环把撤销触发到 jti-x
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		got := revokedJTI
		mu.Unlock()
		if got == "jti-x" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("DLP 命中应经遥测闭环触发撤销 jti-x,得 %q", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Ingest 同步派发:一批事件分发给所有 sink。
func TestIngestDispatch(t *testing.T) {
	var n int
	client, stop := dialIngest(t, telemetry.SinkFunc(func(telemetry.Event) { n++ }))
	defer stop()
	resp, err := client.Report(context.Background(), &telemetrypb.ReportRequest{
		Events: []*telemetrypb.Event{{Kind: telemetry.KindDLPFinding}, {Kind: "other"}},
	})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if resp.GetAccepted() != 2 || n != 2 {
		t.Fatalf("应接收并派发 2 事件,得 accepted=%d n=%d", resp.GetAccepted(), n)
	}
}

// Reporter 缓冲满即丢(非阻塞,best-effort,不阻塞数据面)。
func TestReporterDropsWhenFull(t *testing.T) {
	r := telemetry.NewReporter(nil, 2) // 不 Run(不消费)→ 缓冲很快满
	for i := 0; i < 100; i++ {
		r.Report("t1", "s", "j", dlp.Finding{RuleName: "x", Severity: dlp.SeverityLow})
	}
	if r.Dropped() == 0 {
		t.Fatal("缓冲满应有丢弃计数")
	}
}
