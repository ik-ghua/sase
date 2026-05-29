package ratelimit

import (
	"testing"
	"time"
)

func TestAllowBurstThenRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 3) // 1 令牌/秒,突发 3
	l.now = func() time.Time { return now }

	// 突发 3 个放行,第 4 个拒
	for i := 0; i < 3; i++ {
		if !l.Allow("ip-a") {
			t.Fatalf("突发第 %d 个应放行", i+1)
		}
	}
	if l.Allow("ip-a") {
		t.Fatal("超突发应被限流")
	}
	// 不同键独立
	if !l.Allow("ip-b") {
		t.Fatal("不同键应有独立桶")
	}
	// 过 2 秒补 2 令牌
	now = now.Add(2 * time.Second)
	// 分两次调用(各消耗一个令牌;不可写成 `!Allow() || !Allow()`——|| 短路会漏调第二次)
	ok1 := l.Allow("ip-a")
	ok2 := l.Allow("ip-a")
	if !ok1 || !ok2 {
		t.Fatal("补充后应放行 2 个")
	}
	if l.Allow("ip-a") {
		t.Fatal("补充耗尽后应再次限流")
	}
}

func TestCleanupEvictsIdle(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 1)
	l.now = func() time.Time { return now }
	l.Allow("ip-a")
	if len(l.buckets) != 1 {
		t.Fatalf("应有 1 个桶,得 %d", len(l.buckets))
	}
	now = now.Add(10 * time.Minute)
	l.cleanup(time.Minute)
	if len(l.buckets) != 0 {
		t.Fatalf("空闲桶应被淘汰,仍剩 %d", len(l.buckets))
	}
}
