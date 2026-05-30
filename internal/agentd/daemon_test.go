package agentd

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/dptunnel"
)

// stubNetCapture 是测试用接管壳:OpenAdapter 返回 MemIO(无需 TUN/root)。
type stubNetCapture struct {
	mu        sync.Mutex
	opened    int
	routesCfg int
	openErr   error
}

func (s *stubNetCapture) OpenAdapter() (dptunnel.PacketIO, IfInfo, error) {
	s.mu.Lock()
	s.opened++
	err := s.openErr
	s.mu.Unlock()
	if err != nil {
		return nil, IfInfo{}, err
	}
	return dptunnel.NewMemIO(4), IfInfo{Name: "stub0", MTU: 1400}, nil
}
func (s *stubNetCapture) ConfigureRoutes([]*net.IPNet) error {
	s.mu.Lock()
	s.routesCfg++
	s.mu.Unlock()
	return nil
}
func (s *stubNetCapture) ConfigureDNS(DNSRules) error { return nil }
func (s *stubNetCapture) Close() error                { return nil }

// TestDaemonInitialState 验证构造后初态为 enrolling、候选注入 selector。
func TestDaemonInitialState(t *testing.T) {
	d := New(Config{
		Tenant:     "t1",
		Identity:   "dev1",
		Candidates: []PoPCandidate{{Name: "bj", HandshakeAddr: "bj:1"}},
	}, &stubNetCapture{}, &fakeProbe{}, nil, fakeProber{})
	if d.State() != StateEnrolling {
		t.Fatalf("初态应 enrolling,得 %s", d.State())
	}
	if len(d.Selector().Candidates()) != 1 {
		t.Fatalf("候选应注入 selector,得 %v", d.Selector().Candidates())
	}
}

// TestDaemonRunNoShellFails 验证未提供 NetCapture 壳 → Run 立即返错(非崩溃)。
func TestDaemonRunNoShellFails(t *testing.T) {
	d := New(Config{Tenant: "t1", Identity: "dev1"}, nil, nil, nil, nil)
	if err := d.Run(context.Background()); err == nil {
		t.Fatal("无壳应返错")
	}
}

// TestDaemonStateTransitions 验证状态机流转可观测(setState 去重日志、State 读)。
func TestDaemonStateTransitions(t *testing.T) {
	d := New(Config{Tenant: "t1", Identity: "dev1"}, &stubNetCapture{}, &fakeProbe{}, nil, fakeProber{})
	for _, s := range []State{StateSessionUp, StateTunnelUp, StateRunning, StateDegraded, StateStopped} {
		d.setState(s)
		if d.State() != s {
			t.Fatalf("setState(%s) 后 State 应为 %s,得 %s", s, s, d.State())
		}
	}
}

// TestRetryLoopDegradesAndStops 验证 retryLoop:fn 失败 → 进 degraded → 退避 → ctx 取消干净退出(不崩、不死循环)。
func TestRetryLoopDegradesAndStops(t *testing.T) {
	d := New(Config{Tenant: "t1", Identity: "dev1"}, &stubNetCapture{}, &fakeProbe{}, nil, fakeProber{})
	d.retryBackoff = 5 * time.Millisecond // 加速

	var calls int
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- d.retryLoop(ctx, func(_ context.Context) error {
			mu.Lock()
			calls++
			n := calls
			mu.Unlock()
			if n >= 3 {
				cancel() // 第 3 次后取消,验证干净退出
			}
			return errors.New("tunnel down")
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("retryLoop ctx 取消应返 nil,得 %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retryLoop 应在 ctx 取消后退出(疑似死循环)")
	}
	if d.State() != StateStopped {
		t.Fatalf("退出后应 stopped,得 %s", d.State())
	}
	mu.Lock()
	c := calls
	mu.Unlock()
	if c < 3 {
		t.Fatalf("fn 应被重试多次,得 %d", c)
	}
}

// TestRunTunnelOnceSelectFails 验证选址失败(无候选)→ runTunnelOnce 返错(交 retryLoop 降级),不崩。
func TestRunTunnelOnceSelectFails(t *testing.T) {
	d := New(Config{Tenant: "t1", Identity: "dev1"}, &stubNetCapture{}, &fakeProbe{}, nil, fakeProber{})
	// 无候选 → Select → ErrNoCandidates。
	err := d.runTunnelOnce(context.Background(), nil)
	if err == nil {
		t.Fatal("无候选应返错")
	}
	if !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("应包装 ErrNoCandidates,得 %v", err)
	}
}
