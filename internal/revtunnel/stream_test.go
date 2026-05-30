package revtunnel

// Slice78 stream mux 单测(-race):并发多流不串、半关 EOF、RST、streamID 隔离、分片重组、mux 关闭唤醒。
// 用 net.Pipe() 造一对内存连接,两端各起一个 muxConn(PoP server=true / connector server=false)。

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// muxPair 造一对经 net.Pipe 连接的 muxConn:srv(PoP 侧,主动 openStream)+ cli(connector 侧,响应 OPEN)。
// onOpen 在 cli 侧对每条 OPEN 调(测试用:dst → handler)。返回两端 + 清理函数。
func muxPair(t *testing.T, onOpen func(s *stream, dst string)) (srv, cli *muxConn, cleanup func()) {
	t.Helper()
	a, b := net.Pipe()
	srv = newMuxConn(a, true)
	cli = newMuxConn(b, false)
	cli.onOpen = func(s *stream, dst string) {
		// 流条目已在 readLoop 内同步 acceptStream 建好;go 起 handler(勿阻塞读循环)。
		go onOpen(s, dst)
	}
	go srv.readLoop()
	go cli.readLoop()
	return srv, cli, func() {
		srv.Close()
		cli.Close()
	}
}

// echoStream 读对端 DATA 原样回写,直到 EOF(对端 CLOSE)→ 回 CLOSE。
func echoStream(s *stream, _ string) {
	defer s.Close()
	buf := make([]byte, 4096)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			if _, werr := s.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func TestStreamOpenEchoRoundtrip(t *testing.T) {
	srv, _, cleanup := muxPair(t, echoStream)
	defer cleanup()

	s, err := srv.openStream("10.0.0.1:80")
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	defer s.Close()

	msg := []byte("hello-stream-mux")
	if _, err := s.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readN(t, s, len(msg))
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo 不符:got %q want %q", got, msg)
	}
}

func TestStreamHalfCloseEOF(t *testing.T) {
	// connector 侧收到 OPEN 后,写一段数据然后 Close(半关);PoP 侧 Read 应读到数据再得 io.EOF。
	srv, _, cleanup := muxPair(t, func(s *stream, _ string) {
		_, _ = s.Write([]byte("partial"))
		_ = s.Close() // 半关:发 CLOSE
	})
	defer cleanup()

	s, err := srv.openStream("x:1")
	if err != nil {
		t.Fatal(err)
	}
	got := readN(t, s, len("partial"))
	if string(got) != "partial" {
		t.Fatalf("半关前数据应送达,got %q", got)
	}
	// 再读应得 EOF(对端已 CLOSE 且读尽)。带超时防挂死。
	type rr struct {
		n   int
		err error
	}
	ch := make(chan rr, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := s.Read(buf)
		ch <- rr{n, err}
	}()
	select {
	case got := <-ch:
		if got.n != 0 || !errors.Is(got.err, io.EOF) {
			t.Fatalf("半关后应 EOF,得 n=%d err=%v", got.n, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("半关后 Read 未返回 EOF(挂死)")
	}
}

func TestStreamRST(t *testing.T) {
	// connector 侧 reset 流(模拟 dial 失败);PoP 侧 Read/Write 应得 errStreamReset。
	srv, _, cleanup := muxPair(t, func(s *stream, _ string) {
		s.reset()
	})
	defer cleanup()

	s, err := srv.openStream("x:1")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	deadline := time.After(2 * time.Second)
	done := make(chan error, 1)
	go func() {
		_, rerr := s.Read(buf)
		done <- rerr
	}()
	select {
	case rerr := <-done:
		if !errors.Is(rerr, errStreamReset) {
			t.Fatalf("RST 后 Read 应得 errStreamReset,得 %v", rerr)
		}
	case <-deadline:
		t.Fatal("RST 后 Read 应立即返回,超时")
	}
}

func TestStreamConcurrentNoCrosstalk(t *testing.T) {
	// 并发 N 条流,每条 echo 一个含自身编号的 payload;验证不串话(streamID 隔离)+ -race 无竞争。
	srv, _, cleanup := muxPair(t, echoStream)
	defer cleanup()

	const N = 32
	var wg sync.WaitGroup
	wg.Add(N)
	errCh := make(chan error, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			s, err := srv.openStream("dst:1")
			if err != nil {
				errCh <- err
				return
			}
			defer s.Close()
			// 每条流写独有 payload(含编号);echo 回来必须原样(不串到别的流)。
			payload := bytes.Repeat([]byte{byte('A' + i%26)}, 100+i)
			payload[0] = byte(i) // 标记
			if _, err := s.Write(payload); err != nil {
				errCh <- err
				return
			}
			got := readN(t, s, len(payload))
			if !bytes.Equal(got, payload) {
				errCh <- errors.New("stream 串话:echo 与发送不符")
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamFragmentReassembly(t *testing.T) {
	// 写一个 > maxFramePayload 的大 payload,验证分片后对端重组完整(echo 回原样)。
	srv, _, cleanup := muxPair(t, echoStream)
	defer cleanup()

	s, err := srv.openStream("dst:1")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	big := make([]byte, maxFramePayload*2+12345) // 跨多帧
	for i := range big {
		big[i] = byte(i * 7)
	}
	go func() { _, _ = s.Write(big) }()
	got := readN(t, s, len(big))
	if !bytes.Equal(got, big) {
		t.Fatalf("大 payload 分片重组不符:len got=%d want=%d", len(got), len(big))
	}
}

func TestStreamMuxCloseWakesReaders(t *testing.T) {
	// mux 关闭应唤醒阻塞在 Read 的流(返 errMuxClosed,不挂死)。
	srv, _, cleanup := muxPair(t, func(_ *stream, _ string) { /* 不回写,让 PoP 侧 Read 阻塞 */ })
	defer cleanup()

	s, err := srv.openStream("dst:1")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, rerr := s.Read(buf)
		done <- rerr
	}()
	time.Sleep(50 * time.Millisecond) // 让 Read 进入阻塞
	srv.Close()                       // 关 mux
	select {
	case rerr := <-done:
		if rerr == nil {
			t.Fatal("mux 关闭后 Read 应返回错误")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mux 关闭未唤醒阻塞的 Read")
	}
}

func TestOpenStreamOnClosedMux(t *testing.T) {
	srv, _, cleanup := muxPair(t, echoStream)
	cleanup() // 立刻关
	if _, err := srv.openStream("x:1"); !errors.Is(err, errMuxClosed) {
		t.Fatalf("已关 mux 上 openStream 应得 errMuxClosed,得 %v", err)
	}
}

// ---- helpers ----

// readN 读满 n 字节(stream 可能分多次 Read 返回)。
func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	out := make([]byte, 0, n)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for len(out) < n {
		if time.Now().After(deadline) {
			t.Fatalf("readN 超时:已读 %d / %d", len(out), n)
		}
		got := make(chan struct{}, 1)
		var rn int
		var rerr error
		go func() {
			rn, rerr = r.Read(buf)
			got <- struct{}{}
		}()
		select {
		case <-got:
		case <-time.After(2 * time.Second):
			t.Fatalf("readN 单次 Read 阻塞:已读 %d / %d", len(out), n)
		}
		if rn > 0 {
			out = append(out, buf[:rn]...)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) && len(out) >= n {
				break
			}
			t.Fatalf("readN 出错:%v(已读 %d / %d)", rerr, len(out), n)
		}
	}
	return out
}
