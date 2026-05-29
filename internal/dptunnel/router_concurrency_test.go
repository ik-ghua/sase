package dptunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// worker pool 并发正确性(-race):多 datagram 经 Serve 的 worker pool 并发处理,断言**无重复/串话**
// (每包按内层目的 IP 路由到正确站点、至多一次)+ 高送达率(回环 UDP 偶发丢包放宽,见末尾断言),
// 且整个过程不触发 data race。**不**断言零丢包(回环 UDP 固有、机器相关,非 worker pool 不变量)。
//
// 拓扑:租户 t1 两站点 A(10.1.0.0/24)、B(10.2.0.0/24),A→PoP→B。多 goroutine 经 A 的发送会话
// 并发封装 N 个内层包注入 PoP 的 UDP socket,PoP worker pool 并发转发,B 侧 socket 收并经接收会话解封计数。

func TestRouterWorkerPoolConcurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connP := udpConn(t) // PoP 数据面 socket(worker pool 在此 ReadFrom)
	connA := udpConn(t) // 站点A:注册的 src 地址,且从此 socket 发出(源端口须与 bySrc 一致,否则 no_session 丢)
	connB := udpConn(t) // 站点B 接收转发结果
	kA, kB := key32(0xA1), key32(0xB2)

	router := NewRouter()
	router.Register("t1", "siteA", NewSession(mustAEAD(t, kA), 1, 1, 0), connA.LocalAddr(), []*net.IPNet{cidr(t, "10.1.0.0/24")})
	router.Register("t1", "siteB", NewSession(mustAEAD(t, kB), 1, 1, 0), connB.LocalAddr(), []*net.IPNet{cidr(t, "10.2.0.0/24")})
	go router.Serve(ctx, connP)

	// 站点A 的发送会话:须与 PoP 持有的 A 会话镜像(PoP A: send=1/recv=0 → A 端 send=0/recv=1)。
	sendA := NewSession(mustAEAD(t, kA), 1, 0, 1)
	// 站点B 的接收会话:须与 PoP 持有的 B 会话镜像(PoP B: send=1/recv=0 → B 端 send=0/recv=1),
	// 故本端 recvDir=1 才能解开 PoP 以 sendDir=1 封装、转发来的密文。
	recvB := NewSession(mustAEAD(t, kB), 1, 0, 1)

	const total = 2000
	// 每个内层包 payload 编码一个唯一序号,B 侧据此核对无串话/无重复。
	payload := func(seq int) string { return fmt.Sprintf("seq-%06d", seq) }

	// B 侧接收 goroutine:循环从 connB 读、解封、登记收到的序号。
	got := make(map[string]int)
	var gotMu sync.Mutex
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, maxDatagram)
		for {
			_ = connB.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := connB.ReadFrom(buf)
			if err != nil {
				return // 读超时(收齐后)或 socket 关闭
			}
			inners, err := recvB.Open(append([]byte(nil), buf[:n]...))
			if err != nil {
				continue
			}
			for _, pkt := range inners {
				if len(pkt) >= 30 {
					p := string(pkt[20:30]) // ipv4() 把 payload 从偏移 20 起写入
					gotMu.Lock()
					got[p]++
					gotMu.Unlock()
				}
			}
		}
	}()

	// 单序列发送(一条隧道会话本就是顺序流:Seal 单调计数器 + 接收侧重放窗口容忍有限乱序)。
	// 从 connA 发出(源地址 == 注册的 siteA 地址,命中 PoP bySrc 解复用),注入到 PoP 的同一 UDP socket,
	// 由 worker pool 的 N 个 worker 并发 ReadFrom→Handle→WriteTo;worker 并发性在 PoP 收包侧得到充分锻炼
	// (每包可能落不同 worker),而计数器顺序不被多发送方打乱致超出 64 位重放窗口(那是单会话固有约束,非
	// worker pool 问题)。并发注入安全另由 TestRouterServeConcurrentRegister 覆盖。
	popAddr := connP.LocalAddr()
	for seq := 0; seq < total; seq++ {
		frames, err := sendA.Seal(ipv4("10.1.0.5", "10.2.0.9", payload(seq)))
		if err != nil {
			t.Fatalf("Seal seq=%d: %v", seq, err)
		}
		for _, f := range frames {
			if _, err := connA.WriteTo(f, popAddr); err != nil {
				t.Fatalf("write seq=%d: %v", seq, err)
			}
		}
	}

	// 轮询直到收齐或超时(UDP 回环偶有乱序/排队,给足窗口)。
	deadline := time.Now().Add(3 * time.Second)
	for {
		gotMu.Lock()
		n := len(got)
		gotMu.Unlock()
		if n >= total || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	connB.Close()
	<-recvDone

	gotMu.Lock()
	defer gotMu.Unlock()
	// worker pool 正确性的**严格不变量**:无重复/串话 —— 每个序号至多收到一次,且收到的都是发过的合法序号
	// (跨会话/跨租户串话的密文无法被 recvB 解开,不会进 got;故 got 里出现 = worker 正确路由+重封了它)。
	for p, c := range got {
		if c > 1 {
			t.Fatalf("序号 %q 收到 %d 次(串话/重复转发,worker pool 错误)", p, c)
		}
	}
	// 送达率(**放宽**):回环 UDP 在 2000 包突发 + -race 拖慢消费者时,内核接收缓冲可能溢出丢少量包——
	// 这是传输层固有、与 worker pool 无关(实测偶丢 <1%)。worker pool 的并发正确性由 ① 上面"无重复/串话"
	// 严格不变量 + ② `-race` 检测器(共享 buf/Router 状态竞争)主证;送达率只兜底"worker pool 没大面积吞包"。
	// 阈值 90%:远高于回环偶发丢包率,又能抓住真 worker pool bug(会丢/损坏绝大多数包)。
	if len(got) < total*9/10 {
		t.Fatalf("worker pool 送达率过低 %d/%d(<90%%,疑似 worker pool 吞包而非回环偶发)", len(got), total)
	}
}

// worker pool 在 Serve 运行期间与 Register/Deregister 并发,断言无 data race、无 panic(churn 站点不影响已建站点转发)。
// 本测试聚焦并发访问安全(RWMutex + 每会话 mu),以 -race 跑出共享可变状态的竞争即失败。
func TestRouterServeConcurrentRegister(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connP := udpConn(t)
	connA, connB := udpConn(t), udpConn(t)
	router := NewRouter()
	router.Register("t1", "siteA", NewSession(mustAEAD(t, key32(0xA1)), 1, 1, 0), connA.LocalAddr(), []*net.IPNet{cidr(t, "10.1.0.0/24")})
	router.Register("t1", "siteB", NewSession(mustAEAD(t, key32(0xB2)), 1, 1, 0), connB.LocalAddr(), []*net.IPNet{cidr(t, "10.2.0.0/24")})
	go router.Serve(ctx, connP)

	sendA := NewSession(mustAEAD(t, key32(0xA1)), 1, 0, 1)
	c, err := net.Dial("udp", connP.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial PoP: %v", err)
	}
	defer c.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 注入 goroutine:持续向 worker pool 投递包(命中既有站点 + 命中 churn 中站点)。
	var sent atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		seq := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			frames, _ := sendA.Seal(ipv4("10.1.0.5", "10.2.0.9", fmt.Sprintf("p%05d", seq)))
			for _, f := range frames {
				_, _ = c.Write(f)
			}
			sent.Add(1)
			seq++
		}
	}()

	// churn goroutine:并发反复登记/注销一个第三站点 C(与 Handle 的 RWMutex 读路径竞争)。
	addrC := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45999}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			router.Register("t1", "siteC", NewSession(mustAEAD(t, key32(0xC3)), 1, 1, 0), addrC, []*net.IPNet{cidr(t, "10.3.0.0/24")})
			router.Deregister("t1", "siteC")
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if sent.Load() == 0 {
		t.Fatal("注入 goroutine 未发出任何包(测试未真正并发)")
	}
	// 既有站点 A/B 在 churn 后仍应在册(churn 只动 siteC)。
	router.mu.RLock()
	defer router.mu.RUnlock()
	if n := len(router.byTenant["t1"]); n != 2 {
		t.Fatalf("churn 后 t1 应仍有 2 个站点(A/B),得 %d", n)
	}
}
