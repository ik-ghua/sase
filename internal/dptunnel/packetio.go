package dptunnel

import "sync"

// PacketIO 是隧道的本地 L3 包源/汇抽象:CPE 侧即 TUN 设备(读站点出向包、写入向包)。
// 抽象出来使 Endpoint 逻辑可不依赖 TUN(需 CAP_NET_ADMIN)单测——测试用 MemIO,生产用 tunIO(linux)。
type PacketIO interface {
	ReadPacket() ([]byte, error) // 读一个 L3 包(阻塞);返回 err 即结束
	WritePacket(p []byte) error  // 写一个 L3 包到本地协议栈
	Close() error
}

// MemIO 是内存 PacketIO(测试用):in 为待读队列,out 收已写包。
type MemIO struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
}

// NewMemIO 构造内存 PacketIO,缓冲 buf 个包。
func NewMemIO(buf int) *MemIO {
	return &MemIO{in: make(chan []byte, buf), out: make(chan []byte, buf), closed: make(chan struct{})}
}

// Inject 注入一个待 ReadPacket 读出的本地出向包(模拟 TUN 收到站点 LAN 包)。
func (m *MemIO) Inject(p []byte) {
	select {
	case m.in <- p:
	case <-m.closed:
	}
}

// Out 返回已写入本地栈(模拟到达站点 LAN)的包通道。
func (m *MemIO) Out() <-chan []byte { return m.out }

func (m *MemIO) ReadPacket() ([]byte, error) {
	select {
	case p := <-m.in:
		return p, nil
	case <-m.closed:
		return nil, errClosed
	}
}

func (m *MemIO) WritePacket(p []byte) error {
	cp := append([]byte(nil), p...)
	select {
	case m.out <- cp:
		return nil
	case <-m.closed:
		return errClosed
	}
}

func (m *MemIO) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}
