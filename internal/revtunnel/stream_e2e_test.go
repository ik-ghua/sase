package revtunnel_test

// Slice78 stream-mode 端到端 + Mode 分流回归(无 mTLS,纯 TCP 回环):
//   - connector ServeStream(stream 模式)→ PoP Registry.OpenStream → 经 connector dial 到本地上游 echo。
//   - Mode 分流:同一 Registry 上 http 连接器(routes)与 stream 连接器(streamRoutes)互不影响。
//   - OpenStream key 含 tenant:A 租户查不到 B 租户 connector(跨租户隔离)。

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/revtunnel"
)

// startStreamConnector 起一个 stream-mode connector(无 TLS)拨向 popAddr,dial 固定连到 upstreamAddr。
func startStreamConnector(t *testing.T, ctx context.Context, popAddr, tenant, app, upstreamAddr string) {
	t.Helper()
	dial := func(_ string) (net.Conn, error) {
		return net.Dial("tcp", upstreamAddr)
	}
	go func() {
		_ = revtunnel.ServeStream(ctx, popAddr, nil, revtunnel.Hello{Tenant: tenant, App: app}, dial)
	}()
}

// startEchoTCP 起一个回环 TCP echo 上游,返回其地址。
func startEchoTCP(t *testing.T, ctx context.Context) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { <-ctx.Done(); lis.Close() }()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return lis.Addr().String()
}

func TestStreamModeEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	upstream := startEchoTCP(t, ctx)

	// PoP 注册口(无 TLS;register 在无 mTLS 证书时取不到租户,非 require-cert-tenant 模式下放行)。
	reg := revtunnel.NewRegistry()
	popLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = reg.Accept(ctx, popLis) }()

	const tenant = "11111111-1111-1111-1111-111111111111"
	startStreamConnector(t, ctx, popLis.Addr().String(), tenant, "internal-app", upstream)

	// 等 stream connector 注册(OpenStream 成功即注册完成)。
	stream := waitOpenStream(t, reg, tenant, "internal-app", "10.123.0.50:9000")
	defer stream.Close()

	// 经流写,echo 回原样。
	msg := []byte("zero-exposure-stream")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readExactly(t, stream, len(msg))
	if string(got) != string(msg) {
		t.Fatalf("echo 不符:got %q want %q", got, msg)
	}
}

func TestStreamModeCrossTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstream := startEchoTCP(t, ctx)

	reg := revtunnel.NewRegistry()
	popLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = reg.Accept(ctx, popLis) }()

	const tenantA = "aaaaaaaa-1111-1111-1111-111111111111"
	const tenantB = "bbbbbbbb-2222-2222-2222-222222222222"
	startStreamConnector(t, ctx, popLis.Addr().String(), tenantA, "app1", upstream)

	// A 租户能开流。
	s := waitOpenStream(t, reg, tenantA, "app1", "x:1")
	s.Close()
	// B 租户(同 app 名)查不到 connector(key 含 tenant)→ ErrNoConnector。
	if _, err := reg.OpenStream(tenantB, "app1", "x:1"); err != revtunnel.ErrNoConnector {
		t.Fatalf("跨租户应 ErrNoConnector,得 %v", err)
	}
}

func TestModeDispatchHTTPUnaffected(t *testing.T) {
	// 同一 Registry 上,先注册一个 http connector,再注册一个 stream connector;两者各走各表互不影响。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstream := startEchoTCP(t, ctx)

	reg := revtunnel.NewRegistry()
	popLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = reg.Accept(ctx, popLis) }()

	const tenant = "11111111-1111-1111-1111-111111111111"

	// http connector(W1):RoundTrip 走 routes 表。
	go func() {
		_ = revtunnel.Serve(ctx, popLis.Addr().String(), nil, revtunnel.Hello{Tenant: tenant, App: "http-app"}, echoOK)
	}()
	// stream connector(Slice78):OpenStream 走 streamRoutes 表。
	startStreamConnector(t, ctx, popLis.Addr().String(), tenant, "stream-app", upstream)

	// http RoundTrip 仍工作(W1 字节级不动)。
	resp, err := waitRoundTrip(t, reg, tenant, "http-app", "/hi")
	if err != nil {
		t.Fatalf("http RoundTrip: %v", err)
	}
	if resp.Status != 200 || resp.Body != "ok:/hi" {
		t.Fatalf("http 响应不符:%+v", resp)
	}
	// stream OpenStream 同时工作。
	s := waitOpenStream(t, reg, tenant, "stream-app", "x:1")
	defer s.Close()
	if _, err := s.Write([]byte("ping")); err != nil {
		t.Fatalf("stream Write: %v", err)
	}
	got := readExactly(t, s, 4)
	if string(got) != "ping" {
		t.Fatalf("stream echo 不符:%q", got)
	}

	// http connector 不应出现在 stream 路径(查不到 stream connector)。
	if _, err := reg.OpenStream(tenant, "http-app", "x:1"); err != revtunnel.ErrNoConnector {
		t.Fatalf("http-app 不应在 stream 路径,得 %v", err)
	}
}

// ---- helpers ----

func waitOpenStream(t *testing.T, reg *revtunnel.Registry, tenant, app, dst string) io.ReadWriteCloser {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s, err := reg.OpenStream(tenant, app, dst)
		if err == nil {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("OpenStream 注册超时:%v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitRoundTrip(t *testing.T, reg *revtunnel.Registry, tenant, app, path string) (revtunnel.Response, error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := reg.RoundTrip(tenant, app, revtunnel.Request{Method: "GET", Path: path})
		if err == nil {
			return resp, nil
		}
		if time.Now().After(deadline) {
			return revtunnel.Response{}, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readExactly(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	out := make([]byte, 0, n)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for len(out) < n {
		if time.Now().After(deadline) {
			t.Fatalf("readExactly 超时:已读 %d/%d", len(out), n)
		}
		type rr struct {
			n   int
			err error
		}
		ch := make(chan rr, 1)
		go func() { rn, rerr := r.Read(buf); ch <- rr{rn, rerr} }()
		select {
		case got := <-ch:
			if got.n > 0 {
				out = append(out, buf[:got.n]...)
			}
			if got.err != nil && len(out) < n {
				t.Fatalf("readExactly 出错:%v(已读 %d/%d)", got.err, len(out), n)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("readExactly 单次 Read 阻塞:已读 %d/%d", len(out), n)
		}
	}
	return out
}
