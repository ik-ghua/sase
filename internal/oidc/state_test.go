package oidc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestStateStorePutTakeOnce:Put → TakeOnce 一次性返回(并删),二次取 → ErrInvalidState。
func TestStateStorePutTakeOnce(t *testing.T) {
	s := NewInMemoryStateStore()
	defer s.Stop()
	ctx := context.Background()
	id, err := s.Put(ctx, StateRecord{TenantID: "t1", IDPID: "i1", CodeVerifier: "v1", RedirectURI: "http://cb"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	rec, err := s.TakeOnce(ctx, id)
	if err != nil {
		t.Fatalf("TakeOnce: %v", err)
	}
	if rec.TenantID != "t1" || rec.IDPID != "i1" || rec.CodeVerifier != "v1" {
		t.Fatalf("rec 字段错: %+v", rec)
	}
	// 二次取:已被删
	if _, err := s.TakeOnce(ctx, id); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("二次 TakeOnce: 期望 ErrInvalidState,得 %v", err)
	}
}

// TestStateStoreUnknown:不存在的 ID → ErrInvalidState。
func TestStateStoreUnknown(t *testing.T) {
	s := NewInMemoryStateStore()
	defer s.Stop()
	if _, err := s.TakeOnce(context.Background(), "nope"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("期望 ErrInvalidState,得 %v", err)
	}
}

// TestStateStoreExpired:把记录的 CreatedAt 改成"远过去"模拟过期 → TakeOnce 返 ErrStateExpired 且记录被删。
// 不修改 s.ttl(janitor goroutine 读它,无锁修改会触发 -race);默认 TTL 5min,1 小时前已足够过期。
func TestStateStoreExpired(t *testing.T) {
	s := NewInMemoryStateStore()
	defer s.Stop()
	ctx := context.Background()
	id, err := s.Put(ctx, StateRecord{TenantID: "t1"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// 经 mutex 改 CreatedAt(janitor 也走 mu);1 小时前 > 默认 5min TTL 必判过期
	s.mu.Lock()
	rec := s.records[id]
	rec.CreatedAt = time.Now().Add(-time.Hour)
	s.records[id] = rec
	s.mu.Unlock()
	if _, err := s.TakeOnce(ctx, id); !errors.Is(err, ErrStateExpired) {
		t.Fatalf("期望 ErrStateExpired,得 %v", err)
	}
	// 过期项 TakeOnce 后也已删
	s.mu.Lock()
	_, exists := s.records[id]
	s.mu.Unlock()
	if exists {
		t.Fatal("过期项 TakeOnce 后应已删")
	}
}
