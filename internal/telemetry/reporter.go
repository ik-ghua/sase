package telemetry

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	telemetrypb "github.com/ikuai8/sase/api/proto/sase/telemetry/v1"
	"github.com/ikuai8/sase/internal/dlp"
)

func unixNano(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// Reporter 是 PoP 侧异步事件上报器:入队非阻塞(满即丢,计数),后台批量经 gRPC 上报控制面。
// **不阻塞数据面热路径**——DLP inspect 等只入队即返回(best-effort,丢失不影响安全:权威在 PoP)。
type Reporter struct {
	client      telemetrypb.TelemetryClient
	ch          chan Event
	dropped     atomic.Int64 // 入队满丢弃
	droppedSend atomic.Int64 // 发送失败丢弃(网络抖动/控制面不可达)
	now         func() time.Time
}

// NewReporter 构造上报器,buf 为入队缓冲深度(满即丢)。Start 后台发送。
func NewReporter(client telemetrypb.TelemetryClient, buf int) *Reporter {
	if buf <= 0 {
		buf = 1024
	}
	return &Reporter{client: client, ch: make(chan Event, buf), now: time.Now}
}

// Enqueue 非阻塞入队;缓冲满即丢弃并计数(背压兜底,绝不阻塞调用方)。
func (r *Reporter) Enqueue(e Event) {
	select {
	case r.ch <- e:
	default:
		r.dropped.Add(1)
	}
}

// Dropped 返回入队满丢弃数(背压观测)。
func (r *Reporter) Dropped() int64 { return r.dropped.Load() }

// DroppedSend 返回发送失败丢弃数(控制面不可达等;运维需知丢了多少风险信号)。
func (r *Reporter) DroppedSend() int64 { return r.droppedSend.Load() }

// Run 后台批量发送,直到 ctx 取消。小批 + 短间隔(风险信号要快到控制面);批失败丢弃(best-effort)。
func (r *Reporter) Run(ctx context.Context) {
	const maxBatch = 64
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	var batch []Event
	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.send(ctx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-r.ch:
			batch = append(batch, e)
			if len(batch) >= maxBatch {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (r *Reporter) send(ctx context.Context, batch []Event) {
	pes := make([]*telemetrypb.Event, 0, len(batch))
	for _, e := range batch {
		ts := int64(0)
		if !e.Ts.IsZero() {
			ts = e.Ts.UnixNano()
		}
		pes = append(pes, &telemetrypb.Event{
			TenantId: e.TenantID, Subject: e.Subject, Jti: e.JTI, Kind: e.Kind, Attrs: e.Attrs, TsUnixNano: ts,
		})
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := r.client.Report(cctx, &telemetrypb.ReportRequest{Events: pes}); err != nil {
		r.droppedSend.Add(int64(len(batch)))
		if ctx.Err() == nil {
			log.Printf("[telemetry] 上报 %d 事件失败(丢弃,best-effort): %v", len(batch), err)
		}
	}
}

// Report 实现 dlp.FindingSink:DLP 命中 → 入队 dlp_finding 事件(经遥测上报控制面风险引擎)。
// 这是 DLP 命中跨进程闭环到风险引擎的 PoP 侧接入点(替代 LogFindingSink)。
func (r *Reporter) Report(tenantID, subject, jti string, f dlp.Finding) {
	r.Enqueue(Event{
		TenantID: tenantID, Subject: subject, JTI: jti, Kind: KindDLPFinding, Ts: r.now(),
		Attrs: map[string]string{
			AttrDLPRule: f.RuleName, AttrDLPSeverity: f.Severity, AttrDLPAction: f.Action,
		},
	})
}

var _ dlp.FindingSink = (*Reporter)(nil)
