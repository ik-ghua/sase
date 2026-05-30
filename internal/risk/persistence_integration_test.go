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

// TestRiskListScores:ListScores 列本租户全部快照,验排序(score 降序、subject 升序)+ 空租户空切片。
func TestRiskListScores(t *testing.T) {
	store, ctx := newStore(t)
	svc := risk.NewService(nil, risk.WithStore(store))
	tid := uuid.NewString()

	// 空租户 → 空切片(非 nil),无快照。
	got, err := svc.ListScores(ctx, tid)
	if err != nil {
		t.Fatalf("空租户 ListScores 应成功,得 %v", err)
	}
	if got == nil {
		t.Fatal("空租户应返回非 nil 空切片(便 JSON 序列化为 [])")
	}
	if len(got) != 0 {
		t.Fatalf("空租户应 0 条,得 %d", len(got))
	}

	// 落多条:alice critical(90)、bob medium(DLP high=50)、carol low(DLP low=10)。
	svc.ObservePosture(tid, "alice", "j1", "jailbroken_rooted")                             // score 90 → critical
	svc.Report(tid, "bob", "j2", dlp.Finding{RuleName: "身份证", Severity: dlp.SeverityHigh})  // score 50 → medium
	svc.Report(tid, "carol", "j3", dlp.Finding{RuleName: "手机号", Severity: dlp.SeverityLow}) // score 10 → low

	got, err = svc.ListScores(ctx, tid)
	if err != nil {
		t.Fatalf("ListScores 应成功,得 %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("应 3 条快照,得 %d: %+v", len(got), got)
	}
	// 排序断言:score 降序 → alice(90) > bob(50) > carol(10)。
	wantOrder := []struct {
		subject string
		score   int
		level   risk.Level
	}{
		{"alice", risk.WeightPostureNonCompliant, risk.LevelCritical},
		{"bob", risk.WeightDLPHigh, risk.LevelMedium},
		{"carol", risk.WeightDLPLow, risk.LevelLow},
	}
	for i, w := range wantOrder {
		if got[i].Subject != w.subject || got[i].Score != w.score || got[i].Level != w.level {
			t.Fatalf("第 %d 条应 %s/%d/%s,得 %s/%d/%s(排序或值错)",
				i, w.subject, w.score, w.level, got[i].Subject, got[i].Score, got[i].Level)
		}
		if got[i].UpdatedAt.IsZero() {
			t.Fatalf("第 %d 条(%s)updated_at 应非零", i, got[i].Subject)
		}
	}

	// 同分 subject 升序:再落两条 score 相同(均 DLP low=10)的 d-sub / a-sub。
	tid2 := uuid.NewString()
	svc.Report(tid2, "d-sub", "jd", dlp.Finding{RuleName: "r", Severity: dlp.SeverityLow})
	svc.Report(tid2, "a-sub", "ja", dlp.Finding{RuleName: "r", Severity: dlp.SeverityLow})
	got2, err := svc.ListScores(ctx, tid2)
	if err != nil {
		t.Fatalf("ListScores(tid2): %v", err)
	}
	if len(got2) != 2 || got2[0].Subject != "a-sub" || got2[1].Subject != "d-sub" {
		t.Fatalf("同分应按 subject 升序 a-sub<d-sub,得 %+v", got2)
	}
}

// TestRiskListScoresRLSIsolation:RLS 跨租户隔离——租户 B 列不到租户 A 的快照(0 泄漏)。
func TestRiskListScoresRLSIsolation(t *testing.T) {
	store, ctx := newStore(t)
	svc := risk.NewService(nil, risk.WithStore(store))
	tA := uuid.NewString()
	tB := uuid.NewString()

	// 租户 A 落两条快照;租户 B 不落任何。
	svc.ObservePosture(tA, "a-user-1", "j1", "jailbroken_rooted")
	svc.Report(tA, "a-user-2", "j2", dlp.Finding{RuleName: "身份证", Severity: dlp.SeverityHigh})

	listA, err := svc.ListScores(ctx, tA)
	if err != nil {
		t.Fatalf("租户 A ListScores: %v", err)
	}
	if len(listA) != 2 {
		t.Fatalf("租户 A 应列到自己 2 条,得 %d", len(listA))
	}
	// 租户 B 列:RLS 必须隔离 → 0 条(读不到 A 的任何行)。
	listB, err := svc.ListScores(ctx, tB)
	if err != nil {
		t.Fatalf("租户 B ListScores: %v", err)
	}
	if len(listB) != 0 {
		t.Fatalf("RLS 隔离:租户 B 不应列到租户 A 的任何快照,得 %d 条: %+v", len(listB), listB)
	}
}

// TestRiskListScoresNoStore:未注入 store 的 Service ListScores → ErrNoStore(快照层未启用)。
func TestRiskListScoresNoStore(t *testing.T) {
	svc := risk.NewService(nil) // 纯内存,无 WithStore
	if _, err := svc.ListScores(context.Background(), uuid.NewString()); !errors.Is(err, risk.ErrNoStore) {
		t.Fatalf("未配 store 应 ErrNoStore,得 %v", err)
	}
}

// TestRiskScoreLevelCheckRejectsInvalid:经 store 直插非法 level → DB CHECK(0024 chk_risk_level)拒绝。
// 验证 DB 层纵深防线:即便绕过应用枚举(直写 SQL),非法 level 也写不进表。
// 前置:migration 0024 已应用(否则约束不存在 → 该插入会成功,测试失败提示缺迁移)。
func TestRiskScoreLevelCheckRejectsInvalid(t *testing.T) {
	store, ctx := newStore(t)
	tid := uuid.NewString()

	// 直插非法 level(绕过 store.go 的 persistSnapshot 应用路径),应被 DB CHECK 拒。
	err := store.InTx(ctx, tid, func(q data.Queries) error {
		_, e := q.Exec(ctx,
			`INSERT INTO risk_scores (tenant_id, subject, score, level) VALUES ($1,$2,$3,$4)`,
			tid, "bad-subject", 50, "bogus")
		return e
	})
	if err == nil {
		t.Fatal("非法 level 'bogus' 应被 DB CHECK(chk_risk_level)拒绝;若通过则 migration 0024 未应用")
	}

	// 反证:合法 level 同路径应成功落库(确认约束不误伤合法值)。
	if e := store.InTx(ctx, tid, func(q data.Queries) error {
		_, ex := q.Exec(ctx,
			`INSERT INTO risk_scores (tenant_id, subject, score, level) VALUES ($1,$2,$3,$4)`,
			tid, "good-subject", 90, string(risk.LevelCritical))
		return ex
	}); e != nil {
		t.Fatalf("合法 level 应落库成功,得 %v", e)
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
