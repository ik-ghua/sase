package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// stateTTL 是登录状态在内存中保留的最长时间(用户从跳 IdP 到回调的窗口;5min 对真实交互足够)。
const stateTTL = 5 * time.Minute

// StateRecord 是一次登录开始时记录的服务端上下文(回调按 state ID 找回)。
// **不**让客户端持有这些字段(尤其 IDPID/CodeVerifier 是 capability/secret)。
type StateRecord struct {
	TenantID     string
	IDPID        string
	CodeVerifier string
	RedirectURI  string // IdP 回调地址(本服务的 callback URL);需与 IdP 配置中允许的 URI 一致
	ReturnTo     string // Slice37c:登录成功后浏览器跳回的 SPA 路径(同源相对路径,LoginHandler 已校验)
	CreatedAt    time.Time
}

// StateStore 是登录状态的服务端 store。当前为单进程内存实现;集群部署改 Redis(后续刀,接口不变)。
type StateStore interface {
	// Put 生成新 state ID 并存记录,返回 state ID。
	Put(ctx context.Context, rec StateRecord) (string, error)
	// TakeOnce 按 state ID 一次性取回记录(取出即删,防重放);找不到/过期返 ErrInvalidState/ErrStateExpired。
	TakeOnce(ctx context.Context, stateID string) (StateRecord, error)
}

// InMemoryStateStore 单进程内存 store(map+mutex+janitor)。
type InMemoryStateStore struct {
	mu       sync.Mutex
	records  map[string]StateRecord
	ttl      time.Duration
	now      func() time.Time
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewInMemoryStateStore 构造内存 store;启动 janitor 周期清理过期项(每 TTL/2 一次)。
// 调用方负责进程退出前调 Stop(避免泄漏 goroutine)。
func NewInMemoryStateStore() *InMemoryStateStore {
	s := &InMemoryStateStore{
		records: make(map[string]StateRecord),
		ttl:     stateTTL,
		now:     time.Now,
		stopCh:  make(chan struct{}),
	}
	go s.janitor()
	return s
}

// Put 生成 256bit 随机 state ID,写入 map。
func (s *InMemoryStateStore) Put(_ context.Context, rec StateRecord) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("oidc.state: rand: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	rec.CreatedAt = s.now()
	s.mu.Lock()
	s.records[id] = rec
	s.mu.Unlock()
	return id, nil
}

// TakeOnce 取出并删除;不存在→ErrInvalidState;存在但过期→ErrStateExpired(并删之)。
func (s *InMemoryStateStore) TakeOnce(_ context.Context, stateID string) (StateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[stateID]
	if !ok {
		return StateRecord{}, ErrInvalidState
	}
	delete(s.records, stateID) // 一次性:无论过期与否都删,防同一 state 多次回调
	if s.now().Sub(rec.CreatedAt) > s.ttl {
		return StateRecord{}, ErrStateExpired
	}
	return rec, nil
}

// Stop 退出 janitor goroutine。
func (s *InMemoryStateStore) Stop() { s.stopOnce.Do(func() { close(s.stopCh) }) }

func (s *InMemoryStateStore) janitor() {
	t := time.NewTicker(s.ttl / 2)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.gcExpired()
		}
	}
}

func (s *InMemoryStateStore) gcExpired() {
	cutoff := s.now().Add(-s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range s.records {
		if rec.CreatedAt.Before(cutoff) {
			delete(s.records, id)
		}
	}
}
