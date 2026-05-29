package risk_test

// risk 持久化快照层集成测试(真 PG;需 SASE_DB_RW_DSN/SASE_DB_RO_DSN,未设则 SKIP)。
// 覆盖:
//   ① 评分变更 → 快照落库;GetScore 读回(score/level/factors/updated_at)。
//   ② upsert:同 (tenant,subject) 再评分 → 覆盖快照(单行,非追加),score/level 反映新值。
//   ③ GetScore 不存在 → ErrNoScore。
//   ④ **RLS 跨租户隔离**:另一租户经 GetScore 读不到本租户快照(0 泄漏)。
//   ⑤ 未配 store 的 Service → GetScore 返 ErrNoStore(快照层未启用,fail-loud)。
// 前置:migrations 0001-0023。risk_scores 无 FK 到 tenants(同 swg/dlp),故可用任意租户 UUID。

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/risk"
)

func newStore(t *testing.T) (data.Store, context.Context) {
	t.Helper()
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 risk 持久化集成测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	t.Cleanup(store.Close)
	return store, ctx
}

func TestRiskSnapshotPersistAndGet(t *testing.T) {
	store, ctx := newStore(t)
	svc := risk.NewService(nil, risk.WithStore(store))
	tid := uuid.NewString()

	// ① 评分变更(姿态非合规 → critical)即触发快照落库。
	svc.ObservePosture(tid, "alice", "jti-1", "jailbroken_rooted")
	sc, err := svc.GetScore(ctx, tid, "alice")
	if err != nil {
		t.Fatalf("GetScore 应成功,得 %v", err)
	}
	if sc.Subject != "alice" || sc.Level != risk.LevelCritical || sc.Score != risk.WeightPostureNonCompliant {
		t.Fatalf("快照应为 critical/score=%d,得 subject=%s level=%s score=%d",
			risk.WeightPostureNonCompliant, sc.Subject, sc.Level, sc.Score)
	}
	if sc.UpdatedAt.IsZero() {
		t.Fatal("updated_at 应非零")
	}
	if len(sc.Factors) == 0 {
		t.Fatal("critical 快照应含可解释 factors(posture)")
	}

	// ② upsert:恢复合规 → score 回落到 low(单行被覆盖,非追加)。
	svc.ObservePosture(tid, "alice", "jti-2", "compliant")
	sc2, err := svc.GetScore(ctx, tid, "alice")
	if err != nil {
		t.Fatalf("GetScore(upsert 后)应成功,得 %v", err)
	}
	if sc2.Level != risk.LevelLow || sc2.Score != 0 {
		t.Fatalf("恢复合规后快照应 low/0,得 level=%s score=%d", sc2.Level, sc2.Score)
	}
	// 单行验证:计数应恰为 1(upsert 不追加)。
	assertRowCount(t, ctx, store, tid, "alice", 1)

	// ③ 不存在的 subject → ErrNoScore。
	if _, err := svc.GetScore(ctx, tid, "nobody"); !errors.Is(err, risk.ErrNoScore) {
		t.Fatalf("无快照应 ErrNoScore,得 %v", err)
	}
}

// TestRiskSnapshotRLSIsolation:RLS 跨租户隔离——另一租户读不到本租户快照。
func TestRiskSnapshotRLSIsolation(t *testing.T) {
	store, ctx := newStore(t)
	svc := risk.NewService(nil, risk.WithStore(store))
	tA := uuid.NewString()
	tB := uuid.NewString()

	// 在租户 A 落一条快照(用 DLP 命中累积到有分)。
	svc.Report(tA, "shared-subject", "j", dlp.Finding{RuleName: "身份证", Severity: dlp.SeverityHigh})
	if _, err := svc.GetScore(ctx, tA, "shared-subject"); err != nil {
		t.Fatalf("租户 A 应能读到自己快照,得 %v", err)
	}
	// 租户 B 用**相同 subject** 查 —— RLS 必须隔离,读不到 A 的行 → ErrNoScore。
	if _, err := svc.GetScore(ctx, tB, "shared-subject"); !errors.Is(err, risk.ErrNoScore) {
		t.Fatalf("RLS 隔离:租户 B 不应读到租户 A 的快照(同 subject),得 %v", err)
	}
}

// TestRiskNoStore:未注入 store 的 Service GetScore → ErrNoStore(快照层未启用)。
func TestRiskNoStore(t *testing.T) {
	svc := risk.NewService(nil) // 纯内存,无 WithStore
	if _, err := svc.GetScore(context.Background(), uuid.NewString(), "x"); !errors.Is(err, risk.ErrNoStore) {
		t.Fatalf("未配 store 应 ErrNoStore,得 %v", err)
	}
}

// assertRowCount 在租户 RLS 上下文内断言 risk_scores 行数(验 upsert 单行,非追加)。
func assertRowCount(t *testing.T, ctx context.Context, store data.Store, tid, subject string, want int) {
	t.Helper()
	var n int
	err := store.InTxRO(ctx, tid, func(q data.Queries) error {
		return q.QueryRow(ctx, `SELECT count(*) FROM risk_scores WHERE subject = $1`, subject).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count 查询失败: %v", err)
	}
	if n != want {
		t.Fatalf("risk_scores 行数应为 %d,得 %d(upsert 不应追加)", want, n)
	}
}
