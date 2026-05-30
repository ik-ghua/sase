package agentd

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProbe 注入采集结果/错误(单测)。callN 计采集次数。
type fakeProbe struct {
	mu    sync.Mutex
	facts PostureFacts
	err   error
	calls int
}

func (p *fakeProbe) Collect() (PostureFacts, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.facts, p.err
}

func (p *fakeProbe) count() int { p.mu.Lock(); defer p.mu.Unlock(); return p.calls }

// TestPostureSchedulerStampsVersionAndOnUpdate 验证:核心盖 AgentVersion(单一来源)、onUpdate 收到事实、Latest 可读。
func TestPostureSchedulerStampsVersion(t *testing.T) {
	pr := &fakeProbe{facts: PostureFacts{OS: "linux", OSVersion: "22.04", Firewall: FactPresent}}
	var gotVer string
	var mu sync.Mutex
	s := NewPostureScheduler(pr, time.Hour, "v1.2.3", func(f PostureFacts) {
		mu.Lock()
		gotVer = f.AgentVersion
		mu.Unlock()
	})
	s.Recheck() // 同步采一次

	f, ok := s.Latest()
	if !ok {
		t.Fatal("应已采到")
	}
	if f.AgentVersion != "v1.2.3" {
		t.Fatalf("核心应盖 AgentVersion=v1.2.3,得 %q", f.AgentVersion)
	}
	mu.Lock()
	gv := gotVer
	mu.Unlock()
	if gv != "v1.2.3" {
		t.Fatalf("onUpdate 应收到盖版本后的事实,得 %q", gv)
	}
}

// TestPostureSchedulerCollectErrorNoPanic 验证采集失败不崩、保留上次成功结果、Latest 不被坏结果污染。
func TestPostureSchedulerCollectErrorNoPanic(t *testing.T) {
	pr := &fakeProbe{facts: PostureFacts{OS: "linux"}}
	s := NewPostureScheduler(pr, time.Hour, "v1", nil)
	s.Recheck() // 成功一次
	if _, ok := s.Latest(); !ok {
		t.Fatal("应有成功结果")
	}

	// 转为失败,再采:不崩,保留上次成功结果。
	pr.mu.Lock()
	pr.err = errors.New("collect failed")
	pr.mu.Unlock()
	s.Recheck()
	f, ok := s.Latest()
	if !ok || f.OS != "linux" {
		t.Fatalf("采集失败应保留上次成功结果,得 ok=%v os=%q", ok, f.OS)
	}
}

// TestPostureSchedulerNilProbe 验证 nil probe 不崩(壳缺失降级)。
func TestPostureSchedulerNilProbe(t *testing.T) {
	s := NewPostureScheduler(nil, time.Hour, "v1", nil)
	s.Recheck() // 不应 panic
	if _, ok := s.Latest(); ok {
		t.Fatal("nil probe 不应有结果")
	}
}

// TestPostureSchedulerRunStopsOnCtx 验证 Run 启动即采一次、ctx 取消干净退出。
func TestPostureSchedulerRunStopsOnCtx(t *testing.T) {
	pr := &fakeProbe{facts: PostureFacts{OS: "linux"}}
	s := NewPostureScheduler(pr, time.Hour, "v1", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// Run 启动即采一次。
	deadline := time.After(2 * time.Second)
	for pr.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("Run 启动应立即采一次")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后 Run 应退出")
	}
}

// TestPostureFactsSummary 验证摘要含关键字段(过渡填 cred.Claims.Posture / 实时通道上报)。
func TestPostureFactsSummary(t *testing.T) {
	f := PostureFacts{OS: "linux", OSVersion: "22.04", DiskEncryption: FactHealthy, Firewall: FactPresent}
	sum := f.Summary()
	for _, want := range []string{"os=linux", "ver=22.04", "disk=healthy", "fw=present"} {
		if !strings.Contains(sum, want) {
			t.Errorf("摘要应含 %q,得 %q", want, sum)
		}
	}
	// 空字段归一为 unknown(fail-closed 语义可见)。
	empty := PostureFacts{}.Summary()
	if !strings.Contains(empty, "os=unknown") || !strings.Contains(empty, "av=unknown") {
		t.Errorf("空姿态应显 unknown,得 %q", empty)
	}
}
