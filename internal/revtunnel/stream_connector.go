package revtunnel

// stream_connector.go 是 connector 侧的 stream-mode 承载(Slice78):拨出连到 PoP 注册 Hello{Mode:stream},
// 然后在 mux 上响应 PoP 发来的 OPEN——dial 本地上游 → 双向泵(mux 流 ↔ 上游 TCP)。私网无入站开口。

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// ServeStream 是 connector 侧 stream-mode 入口:拨出连到 addr 注册 hello(Mode 应为 stream),
// 然后处理 PoP 发来的 OPEN 帧——对每条 OPEN 调 dial(dst) 连本地上游,双向泵到 mux 流。
// 阻塞到 ctx 取消或连接断开。tlsConf 非 nil 走 mTLS(connector 设备级认证,与 Serve 一致)。
//
// dial 由调用方提供(通常 net.Dial("tcp", upstream));dst 是 PoP 经 OPEN 透传的原始目的 host:port。
// 第一刀:dial 多忽略 dst 直连固定 UPSTREAM(connector 绑定单一上游),dst 仅作可观测/未来多上游路由。
func ServeStream(ctx context.Context, addr string, tlsConf *tls.Config, hello Hello, dial func(dst string) (net.Conn, error)) error {
	conn, err := dial0(ctx, addr, tlsConf)
	if err != nil {
		return fmt.Errorf("revtunnel: stream 拨出 PoP %s: %w", addr, err)
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }() // ctx 取消即断连,解除阻塞读

	// 注册:发 Hello(Mode 强制 stream)。
	hello.Mode = ModeStream
	if err := writeHello(conn, hello); err != nil {
		return fmt.Errorf("revtunnel: stream 注册: %w", err)
	}

	mc := newMuxConn(conn, false) // connector 侧:server=false(被动响应 OPEN)
	var wg sync.WaitGroup
	mc.onOpen = func(s *stream, dst string) {
		// 流条目已在 readLoop 内同步 acceptStream 建好;此处 go 起 dial+泵(勿阻塞读循环)。
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleConnectorOpen(ctx, s, dst, dial)
		}()
	}
	mc.readLoop() // 阻塞到 PoP 断开/ctx 取消
	wg.Wait()     // 等所有在途流泵收尾(各自 mux 已关 → io.Copy 解除)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// handleConnectorOpen 对一条已 accept 的流:dial 本地上游 → 双向泵(mux 流 ↔ 上游 TCP)。
// dial 失败 → RST 该流(PoP 侧 OpenStream 的流读到 errStreamReset)。
func handleConnectorOpen(ctx context.Context, s *stream, dst string, dial func(dst string) (net.Conn, error)) {
	up, err := dial(dst)
	if err != nil {
		log.Printf("[revtunnel] stream dial 上游失败 dst=%q: %v", dst, err)
		s.reset()
		return
	}
	defer up.Close()
	go func() { <-ctx.Done(); _ = up.Close() }()

	// 双向泵:上游→mux 流(s.Write 发 DATA);mux 流→上游(s.Read 收 DATA 写上游)。
	// 任一向结束 → 关另一向(关 up 解除上游读;Close s 发 CLOSE / 上游 EOF 后 reset 解除 mux 读)。
	var pumpWG sync.WaitGroup
	pumpWG.Add(2)
	go func() {
		defer pumpWG.Done()
		_, _ = io.Copy(s, up) // 上游 → mux 流
		_ = s.Close()         // 上游 EOF/出错:半关流(发 CLOSE)
	}()
	go func() {
		defer pumpWG.Done()
		_, _ = io.Copy(up, s) // mux 流 → 上游
		// mux 流 EOF/RST:关上游写端(解除上游另一向的 io.Copy 读)。
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = up.Close()
		}
	}()
	pumpWG.Wait()
}

// dial0 按 tlsConf 选择明文/mTLS 拨号(与既有 dial 同实现,独立名避免与连接器侧 dial 入参混淆)。
func dial0(ctx context.Context, addr string, tlsConf *tls.Config) (net.Conn, error) {
	return dial(ctx, addr, tlsConf)
}

// writeHello 用裸 JSON 编码发 Hello(与 Serve 一致;mux readLoop 接管后续帧)。
// json.Encoder.Encode 写一个 JSON 对象 + 换行,无读端缓冲问题(发送侧)。
func writeHello(conn net.Conn, hello Hello) error {
	return json.NewEncoder(conn).Encode(hello)
}
