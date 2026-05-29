package linkmon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

var twoLinks = []Link{
	{Name: "wan1", Addr: "10.0.1.1:7000", Priority: 1}, // 故意乱序传入,New 应按 Priority 排
	{Name: "wan0", Addr: "10.0.0.1:7000", Priority: 0},
}

type nopProber struct{}

func (nopProber) Probe(context.Context, Link) (time.Duration, error) { return time.Millisecond, nil }

// 直接驱动 record(确定性):验选路/失效切换/恢复回切。
func TestSelectFailoverRecover(t *testing.T) {
	m := New(twoLinks, nopProber{}, Config{Window: 3, LossThreshold: 0.5})

	// 初始无探测数据 → 无健康链路
	if _, ok := m.Best(); ok {
		t.Fatal("初始应无健康链路")
	}

	// 两链路均通 → 选优先级最高(wan0,prio0)
	m.record("wan0", true, 5*time.Millisecond)
	m.record("wan1", true, 9*time.Millisecond)
	if l, ok := m.Best(); !ok || l.Name != "wan0" {
		t.Fatalf("两链路均通应选 wan0,得 %v(ok=%v)", l.Name, ok)
	}

	// 主链路 wan0 连续失败 2 次(窗口 [ok,fail,fail] 丢包 67%>50% → down),wan1 仍通 → 切到 wan1
	m.record("wan0", false, 0)
	m.record("wan0", false, 0)
	m.record("wan1", true, 9*time.Millisecond)
	if l, ok := m.Best(); !ok || l.Name != "wan1" {
		t.Fatalf("主链路劣化应切到 wan1,得 %v(ok=%v)", l.Name, ok)
	}

	// wan0 恢复(连 3 次成功,窗口全 ok)→ 回切 wan0
	m.record("wan0", true, 5*time.Millisecond)
	m.record("wan0", true, 5*time.Millisecond)
	m.record("wan0", true, 5*time.Millisecond)
	if l, ok := m.Best(); !ok || l.Name != "wan0" {
		t.Fatalf("主链路恢复应回切 wan0,得 %v(ok=%v)", l.Name, ok)
	}

	// 两链路全挂 → 无健康链路
	for i := 0; i < 3; i++ {
		m.record("wan0", false, 0)
		m.record("wan1", false, 0)
	}
	if _, ok := m.Best(); ok {
		t.Fatal("两链路全挂应无健康链路")
	}
}

// 可切换的假探测器:fail 置位时该轮探测失败。
type toggleProber struct{ fail atomic.Bool }

func (p *toggleProber) Probe(context.Context, Link) (time.Duration, error) {
	if p.fail.Load() {
		return 0, context.DeadlineExceeded
	}
	return 2 * time.Millisecond, nil
}

// Run 循环 + Best 联动:主链路探测开始失败后,Best 在有界时间内切走。
func TestRunLoopFailover(t *testing.T) {
	p0 := &toggleProber{}
	// 让 wan0 用 p0(可切换),wan1 恒通 —— 用按 Addr 选 prober 的复合探测器
	prober := perLink{probers: map[string]Prober{"10.0.0.1:7000": p0}, def: nopProber{}}
	m := New(twoLinks, prober, Config{Interval: 10 * time.Millisecond, Window: 3, LossThreshold: 0.5})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	if !eventually(t, 500*time.Millisecond, func() bool { l, ok := m.Best(); return ok && l.Name == "wan0" }) {
		t.Fatal("初始应稳定选 wan0")
	}
	p0.fail.Store(true) // wan0 链路失效
	if !eventually(t, time.Second, func() bool { l, ok := m.Best(); return ok && l.Name == "wan1" }) {
		t.Fatal("wan0 失效后应切到 wan1")
	}
	p0.fail.Store(false) // wan0 恢复
	if !eventually(t, time.Second, func() bool { l, ok := m.Best(); return ok && l.Name == "wan0" }) {
		t.Fatal("wan0 恢复后应回切 wan0")
	}
}

type perLink struct {
	probers map[string]Prober
	def     Prober
}

func (p perLink) Probe(ctx context.Context, l Link) (time.Duration, error) {
	if pr, ok := p.probers[l.Addr]; ok {
		return pr.Probe(ctx, l)
	}
	return p.def.Probe(ctx, l)
}

func eventually(t *testing.T, within time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}
