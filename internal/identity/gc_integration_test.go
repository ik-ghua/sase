package identity_test

// 吊销表 GC:GCExpiredRevocations 删过期项(expire_at<now)、留未过期;RevokeCredential 机会式顺手删过期。
// 需 SASE_DB_RW_DSN;未设则 SKIP。前置:migrations 0003。

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/identity"
)

func insertRevocation(t *testing.T, store data.Store, tid, jti string, expireAt time.Time) {
	t.Helper()
	err := store.InTx(context.Background(), tid, func(q data.Queries) error {
		_, e := q.Exec(context.Background(),
			`INSERT INTO revocations (tenant_id, jti, subject, reason, expire_at) VALUES ($1,$2,$3,$4,$5)`,
			tid, jti, "sub", "test", expireAt)
		return e
	})
	if err != nil {
		t.Fatalf("插入吊销项: %v", err)
	}
}

func countRevocations(t *testing.T, store data.Store, tid string) int {
	t.Helper()
	var n int
	err := store.InTxRO(context.Background(), tid, func(q data.Queries) error {
		return q.QueryRow(context.Background(), `SELECT count(*) FROM revocations`).Scan(&n)
	})
	if err != nil {
		t.Fatalf("计数: %v", err)
	}
	return n
}

func TestGCExpiredRevocations(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过吊销表 GC 测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := identity.NewService(store)
	tid := uuid.NewString()

	insertRevocation(t, store, tid, "expired-1", time.Now().Add(-time.Hour))
	insertRevocation(t, store, tid, "expired-2", time.Now().Add(-time.Minute))
	insertRevocation(t, store, tid, "live-1", time.Now().Add(time.Hour))

	n, err := svc.GCExpiredRevocations(ctx, tid)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 2 {
		t.Fatalf("应删 2 条过期,得 %d", n)
	}
	if c := countRevocations(t, store, tid); c != 1 {
		t.Fatalf("应剩 1 条未过期,得 %d", c)
	}

	// 机会式 GC:RevokeCredential 顺手删过期(再插一条过期,撤新 jti 应连带清掉过期)
	insertRevocation(t, store, tid, "expired-3", time.Now().Add(-time.Hour))
	if err := svc.RevokeCredential(ctx, tid, "new-jti", "sub", "r"); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	// 剩:live-1 + new-jti = 2(expired-3 被机会式 GC 清掉)
	if c := countRevocations(t, store, tid); c != 2 {
		t.Fatalf("机会式 GC 后应剩 2 条(live-1+new-jti),得 %d", c)
	}

	// 跨租户隔离:租户 B 的过期项不被租户 A 的 GC 触及(RLS;项目"0 泄漏"风格)
	tidB := uuid.NewString()
	insertRevocation(t, store, tidB, "b-expired", time.Now().Add(-time.Hour))
	if n, err := svc.GCExpiredRevocations(ctx, tid); err != nil || n != 0 {
		t.Fatalf("租户A 的 GC 不应删租户B 的过期项(应删 0),得 n=%d err=%v", n, err)
	}
	if c := countRevocations(t, store, tidB); c != 1 {
		t.Fatalf("租户B 过期项应仍在(GC 跨租户隔离),得 %d", c)
	}
}
