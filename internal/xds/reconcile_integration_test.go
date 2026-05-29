package xds

// Slice59 ReconcileAll 端到端(真实 PG):断连期间丢失的撤销 NOTIFY,经全量对账补回缓存。
// 内部包测试:直接调 onDeltaRequest(模拟订阅)+ 直插 revocations 表(模拟丢失的 NOTIFY)+ 查 revCache。
// 需 SASE_DB_RW_DSN + SASE_DB_RO_DSN;前置 migrations(revocations 表)。

import (
	"context"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"

	xdspb "github.com/ikuai8/sase/api/proto/sase/xds/v1"
	"github.com/ikuai8/sase/internal/data"
)

func TestReconcileAllCatchesMissedRevocation(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN/RO_DSN,跳过 Slice59 对账测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	srv := NewServer(ctx, store)
	tid := uuid.NewString()
	name := xdspb.ResourceName(tid)

	// 1) 模拟 PoP 订阅该租户的 revocation:登记 subscribed + 初次 load(此刻 DB 无撤销 → 空)
	if err := srv.onDeltaRequest(0, &discoveryv3.DeltaDiscoveryRequest{
		TypeUrl:                revTypeURL,
		ResourceNamesSubscribe: []string{name},
	}); err != nil {
		t.Fatalf("onDeltaRequest: %v", err)
	}
	if got := revJtis(t, srv, name); len(got) != 0 {
		t.Fatalf("初始应空,得 %v", got)
	}

	// 2) **模拟断连期间丢失的撤销**:直接写 revocations 表(不经 OnRevocationNotify,即 NOTIFY 丢了)
	jti := "j-missed-" + uuid.NewString()[:8]
	if err := store.InTx(ctx, tid, func(q data.Queries) error {
		_, e := q.Exec(ctx,
			`INSERT INTO revocations (tenant_id, jti, subject, reason, expire_at) VALUES ($1,$2,$3,$4,$5)`,
			tid, jti, "sub", "test-missed", time.Now().Add(time.Hour))
		return e
	}); err != nil {
		t.Fatalf("直插 revocation: %v", err)
	}

	// 3) 缓存仍空(NOTIFY 丢了,未对账)——**证明缺口存在**(被撤销凭证此刻在 PoP 仍存活)
	if got := revJtis(t, srv, name); len(got) != 0 {
		t.Fatalf("丢 NOTIFY 后缓存本应仍空(证缺口),得 %v", got)
	}

	// 4) 全量对账(=断连重连钩子/周期 ticker 所做)
	srv.ReconcileAll()

	// 5) 缓存现在应含该 jti(对账补回 → PoP 下次推送即生效)
	got := revJtis(t, srv, name)
	if len(got) != 1 || got[0] != jti {
		t.Fatalf("对账后应含 %q,得 %v", jti, got)
	}

	// 6) 未订阅的租户不被对账(ReconcileAll 只动 subscribed 集)
	if _, exists := srv.revCache.GetResources()[xdspb.ResourceName(uuid.NewString())]; exists {
		t.Fatalf("未订阅租户不应出现在缓存")
	}
}

func revJtis(t *testing.T, srv *Server, name string) []string {
	t.Helper()
	res, ok := srv.revCache.GetResources()[name]
	if !ok {
		return nil
	}
	rl, ok := res.(*xdspb.RevocationList)
	if !ok {
		t.Fatalf("缓存资源类型错: %T", res)
	}
	return rl.Jtis
}
