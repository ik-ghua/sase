package linkmon

import (
	"context"
	"net"
	"time"
)

// TCPProber 以"建立 TCP 连接的耗时"作链路 RTT、连接成功与否作可达性。软件 CPE/dev 用:
// 探到 PoP 连接器端点(revtunnel mTLS 监听)的 TCP 层即可判活,不做 TLS 握手(更轻)。
// 真实 CPE 应按上联绑定本地源接口、用 ICMP/BFD/探测包分别度量各物理链路(此处不绑源,以 Addr 区分路径)。
type TCPProber struct {
	dialer *net.Dialer
}

// NewTCPProber 构造 TCP 探测器。
func NewTCPProber() *TCPProber { return &TCPProber{dialer: &net.Dialer{}} }

// Probe 拨 link.Addr 测连接 RTT;失败(超时/拒绝)即该次探测失败。
func (p *TCPProber) Probe(ctx context.Context, link Link) (time.Duration, error) {
	start := time.Now()
	conn, err := p.dialer.DialContext(ctx, "tcp", link.Addr)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}
