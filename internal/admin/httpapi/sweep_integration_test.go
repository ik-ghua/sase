package httpapi_test

// Slice35 硬删自动清扫端点端到端:验证
//   ① 宽限期已到的 offboarding 租户被扫到 → DEK 销毁 + 状态推进 decommissioned;
//   ② 宽限期未到的 offboarding 租户**不**被扫;active 租户也不被扫(过滤正确);
//   ③ 重跑幂等(已 decommissioned 不再处理,因状态已非 offboarding);
//   ④ authz:tenant_admin 调用 → 403。
// 需 SASE_DB_RW_DSN + SASE_DB_PLATFORM_DSN(平台跨租户路径);前置 migrations 0001-0016。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/admin/httpapi"
	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/authz"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/fw"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/secret"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

// backdateDecommission 把租户的 decommission_at 改成"已过期"(直接 SQL,跳过宽限等待)。
func backdateDecommission(t *testing.T, store data.Store, ctx context.Context, tid string) { //nolint:revive // 测试 helper:ctx 在 t 之后
	t.Helper()
	err := store.InTx(ctx, tid, func(q data.Queries) error {
		_, e := q.Exec(ctx, `UPDATE tenants SET decommission_at = now() - interval '1 hour' WHERE id=$1`, tid)
		return e
	})
	if err != nil {
		t.Fatalf("backdate: %v", err)
	}
}

func TestDecommissionSweep(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" {
		t.Skip("未设 SASE_DB_RW_DSN + SASE_DB_PLATFORM_DSN,跳过 sweep 端到端测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	signer, _ := cred.GenerateSigner()
	verifier, _ := cred.NewVerifier(signer.Public())
	identitySvc := identity.NewService(store, identity.WithSigner(signer))

	secProvider, _ := secret.NewDevProvider("")
	secSvc := secret.NewService(store, secProvider)
	tenantSvc := tenant.NewService(store, tenant.WithKeyCreator(secSvc))

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenantSvc, identitySvc, policy.NewService(store), resource.NewService(store),
		audit.NewService(store), swg.NewService(store), site.NewService(store),
		fw.NewService(store), dlp.NewService(store), enroll.NewService(store, nil),
		testPlatformSvc(store, secSvc, tenantSvc),
		nil, // popReg
		nil, // platform audit svc
		nil, // platform RBAC svc
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil,
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	platTok, _ := identitySvc.IssueAdminToken(ctx, "ops", authz.RolePlatformAdmin, "", time.Hour)

	// 准备 3 个租户:
	//   tidDue       — offboarding 且 decommission_at 已过(应被扫)
	//   tidNotYet    — offboarding 但 decommission_at 未到(不应被扫)
	//   tidActive    — active(不应被扫)
	tidDue, tidNotYet, tidActive := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, tid := range []string{tidDue, tidNotYet, tidActive} {
		if err := tenantSvc.Create(ctx, &tenant.Tenant{ID: tid, Name: "T-" + tid[:6]}); err != nil {
			t.Fatalf("建租户 %s: %v", tid, err)
		}
	}
	if _, err := tenantSvc.Decommission(ctx, tidDue, time.Hour); err != nil {
		t.Fatalf("Decommission tidDue: %v", err)
	}
	backdateDecommission(t, store, ctx, tidDue) // 把它的 decommission_at 改成已过期
	if _, err := tenantSvc.Decommission(ctx, tidNotYet, time.Hour); err != nil {
		t.Fatalf("Decommission tidNotYet: %v", err)
	}

	// ① 调用 sweep
	st, body := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/decommissions/sweep", nil)
	if st != http.StatusOK {
		t.Fatalf("sweep 应 200,得 %d body=%s", st, body)
	}
	var resp struct {
		Processed []string `json:"processed"`
		Skipped   []struct {
			TenantID string `json:"tenant_id"`
			Reason   string `json:"reason"`
		} `json:"skipped"`
	}
	if e := json.Unmarshal(body, &resp); e != nil {
		t.Fatalf("解析响应: %v", e)
	}
	// processed 应**含** tidDue(可能含其它历史已过期租户,故"含"而非"等"——本测在共享 DB,宽容)
	hasDue := false
	for _, x := range resp.Processed {
		if x == tidDue {
			hasDue = true
		}
	}
	if !hasDue {
		t.Fatalf("sweep 应处理 tidDue=%s,得 processed=%v", tidDue, resp.Processed)
	}
	// ② tidNotYet / tidActive 不应在 processed
	for _, x := range resp.Processed {
		if x == tidNotYet || x == tidActive {
			t.Fatalf("不应处理未到期/active 租户,却处理了 %s", x)
		}
	}

	// 状态验证:tidDue 应 status=decommissioned + DEK 已销毁
	dueT, err := tenantSvc.Get(ctx, tidDue)
	if err != nil || dueT.Status != "decommissioned" {
		t.Fatalf("tidDue 应 status=decommissioned,得 %+v err=%v", dueT, err)
	}
	if d, _ := secSvc.IsDestroyed(ctx, tidDue); !d {
		t.Fatal("tidDue 的 DEK 应已销毁")
	}
	// tidNotYet 仍 offboarding,DEK 仍活
	notYetT, _ := tenantSvc.Get(ctx, tidNotYet)
	if notYetT.Status != "offboarding" {
		t.Fatalf("tidNotYet 应仍 offboarding,得 %s", notYetT.Status)
	}
	if d, _ := secSvc.IsDestroyed(ctx, tidNotYet); d {
		t.Fatal("tidNotYet 的 DEK 不应被销毁")
	}

	// ③ 重跑幂等:再 sweep 一次,tidDue 已 decommissioned 不在 due 列表,不被处理
	_, body2 := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/decommissions/sweep", nil)
	var resp2 struct{ Processed []string }
	_ = json.Unmarshal(body2, &resp2)
	for _, x := range resp2.Processed {
		if x == tidDue {
			t.Fatalf("二次 sweep 不应再处理已 decommissioned 的 tidDue")
		}
	}

	// ④ authz:tenant_admin 调用 → 403
	taTok, _ := identitySvc.IssueAdminToken(ctx, "ta", authz.RoleTenantAdmin, tidActive, time.Hour)
	st3, _ := doRaw(t, srv.URL, taTok, "POST", "/api/v1/platform/decommissions/sweep", nil)
	if st3 != http.StatusForbidden {
		t.Fatalf("tenant_admin 调用 sweep 应 403,得 %d", st3)
	}
}
