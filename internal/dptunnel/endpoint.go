package dptunnel

import (
	"context"
	"errors"
	"log"
	"net"
)

var errClosed = errors.New("dptunnel: 已关闭")

// maxDatagram 单次 UDP 读缓冲上限。封装开销 = 帧头 8B + body 前缀 10B(Counter|PayloadLen)+ AEAD tag 16B
// ≈ 34B;内层 MTU 1500 时封装后约 1534B,远小于此 64KB 缓冲(取 UDP 单报理论上限以容大包/IPv6)。
const maxDatagram = 1 << 16

// Endpoint 是 CPE 侧隧道端点:TUN 出向包 → Session.Seal → UDP 发往 PoP;UDP 收 → Session.Open → 写回 TUN。
// 会话密钥由握手层(Noise+ZTP,待审查)注入到 sess——本结构不做握手。
type Endpoint struct {
	sess *Session
	io   PacketIO
	conn net.PacketConn
	pop  net.Addr
}

// NewEndpoint 构造端点:io=TUN(或测试 MemIO),conn=本地 UDP socket,pop=PoP UDP 地址。
func NewEndpoint(sess *Session, io PacketIO, conn net.PacketConn, pop net.Addr) *Endpoint {
	return &Endpoint{sess: sess, io: io, conn: conn, pop: pop}
}

// Run 启动收发两个 pump,阻塞到 ctx 取消或任一 pump 出错。
func (e *Endpoint) Run(ctx context.Context) {
	go func() { <-ctx.Done(); _ = e.conn.Close(); _ = e.io.Close() }()
	// 任一 pump 退出即关闭 conn+io,使另一 pump 的阻塞读(TUN.ReadPacket / conn.ReadFrom)立即返回退出,
	// 不泄漏 goroutine/fd(评审 B1:单向出错时另一向不会自行收尾)。
	defer func() { _ = e.conn.Close(); _ = e.io.Close() }()
	done := make(chan struct{}, 2)
	go func() { e.pumpOut(); done <- struct{}{} }()
	go func() { e.pumpIn(); done <- struct{}{} }()
	<-done
}

// pumpOut:TUN 出向包 → Seal → UDP 发往 PoP(含 FEC parity 帧)。
func (e *Endpoint) pumpOut() {
	for {
		pkt, err := e.io.ReadPacket()
		if err != nil {
			return
		}
		frames, err := e.sess.Seal(pkt)
		if err != nil {
			log.Printf("[dptunnel] seal 失败(可能需 rekey): %v", err)
			return // ErrRekeyRequired 等 → 停发(fail-closed)
		}
		for _, f := range frames {
			if _, err := e.conn.WriteTo(f, e.pop); err != nil {
				return
			}
		}
	}
}

// pumpIn:UDP 收 → Open → 写回 TUN(含 FEC 恢复出的包)。
func (e *Endpoint) pumpIn() {
	buf := make([]byte, maxDatagram)
	for {
		n, _, err := e.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkts, err := e.sess.Open(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue // 坏帧丢弃,继续
		}
		for _, p := range pkts {
			if err := e.io.WritePacket(p); err != nil {
				return
			}
		}
	}
}
