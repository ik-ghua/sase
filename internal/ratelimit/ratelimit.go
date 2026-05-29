// Package ratelimit 是按键(如客户端 IP)的令牌桶限流,用于 ZTP 公开/设备端点(/enroll、/renew)防枚举/暴力。
// 进程内、无外部依赖;janitor 周期淘汰空闲桶以约束内存(公开端点 IP 键不可无界增长)。
//
// 局限(设计取舍):单实例内存计数,多副本不共享(生产应在网关/L7 入口做分布式限流,本限流为纵深兜底);
// 键由调用方提供(IP 取自 RemoteAddr,X-Forwarded-For 等代理头的可信解析属网关职责,此处不解析)。
package ratelimit

import (
	"context"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter 是按键令牌桶:每键独立桶,速率 rate(令牌/秒)、上限 burst。
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   float64
	now     func() time.Time
}

// New 构造限流器:ratePerSec 稳态速率,burst 突发上限(也是初始令牌)。
func New(ratePerSec, burst float64) *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, rate: ratePerSec, burst: burst, now: time.Now}
}

// Allow 判定 key 是否放行(消耗一个令牌)。key 为空亦计入(归一到空键桶)。
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	// 按流逝时间补充令牌(上限 burst)
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// cleanup 淘汰空闲超过 idle 的桶(空闲=久未访问,届时已补满令牌、无状态可丢)。
func (l *Limiter) cleanup(idle time.Duration) {
	cutoff := l.now().Add(-idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// StartJanitor 起后台 goroutine,每 every 淘汰空闲超过 idle 的桶,随 ctx 取消退出。
func (l *Limiter) StartJanitor(ctx context.Context, every, idle time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				l.cleanup(idle)
			}
		}
	}()
}
