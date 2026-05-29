package idp_test

// Slice37c IdP Delete 联动淘汰 token cache:验证
//   ① Delete 成功后 hook 被调,且收到 kind + client_id;
//   ② Delete 不存在的 IdP → hook 不调;
//   ③ Delete RETURNING 取 kind/client_id 与 Create 入参一致。
// 需 SASE_DB_RW_DSN;前置 migrations 0001-0021。

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/secret"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestIdPDeleteHook(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	secProvider, _ := secret.NewDevProvider("")
	secSvc := secret.NewService(store, secProvider)
	tenantSvc := tenant.NewService(store, tenant.WithKeyCreator(secSvc))

	// 注入 hook 记录调用
	var calls []struct{ tid, idpid, kind, client string }
	svc := idp.NewService(store, secSvc, idp.WithDeleteHook(func(tid, idpid, kind, client string) {
		calls = append(calls, struct{ tid, idpid, kind, client string }{tid, idpid, kind, client})
	}))

	// 建租户 + 一个 wecom IdP
	tid := uuid.NewString()
	if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "T-hook"}); err != nil {
		t.Fatalf("建租户: %v", err)
	}
	c, err := svc.Create(ctx, tid, idp.CreateRequest{
		Name: "WeCom-Hook", Kind: "wecom", Endpoint: "http://x", ClientID: "corp-hook-" + uuid.NewString()[:6], ClientSecret: "s",
	})
	if err != nil {
		t.Fatalf("Create idp: %v", err)
	}

	// ① Delete → hook 被调,字段对齐
	if err := svc.Delete(ctx, tid, c.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("hook 应被调 1 次,得 %d", len(calls))
	}
	got := calls[0]
	if got.tid != tid || got.idpid != c.ID || got.kind != "wecom" || got.client != c.ClientID {
		t.Errorf("hook 参数错: %+v(want tid=%s idpid=%s kind=wecom client=%s)", got, tid, c.ID, c.ClientID)
	}

	// ② Delete 不存在 → hook 不调
	calls = nil
	if err := svc.Delete(ctx, tid, uuid.NewString()); err == nil {
		t.Fatal("Delete 不存在应返错")
	}
	if len(calls) != 0 {
		t.Errorf("Delete 不存在 hook 不应被调,得 %d 次", len(calls))
	}
}
