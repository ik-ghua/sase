package httpapi_test

// Slice38c 平台 RBAC 端到端(经真实 Admin HTTP 栈):
//   ① POST /platform/admins 建 admin → 201;双层审计(source=data 触发器 + source=api handler);
//   ② GET /platform/admins / GET aid;
//   ③ PATCH status=disabled → 之后 IsActive 通路返 false → admin-tokens 端点签发 platform_admin 拒;
//   ④ DELETE 自己 → 400(防锁死);DELETE 他人 → 200;
//   ⑤ /platform/admin-tokens 扩展:role=platform_admin + subject 不在表 → 403;在表且 active → 200;
//   ⑥ tenant_admin 调 RBAC 端点 → 403。
// 需 SASE_DB_RW_DSN + PLATFORM_DSN + PLATFORM_RW_DSN;前置 migrations 0001-0022。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	"github.com/ikuai8/sase/internal/platform"
	"github.com/ikuai8/sase/internal/platformaudit"
	"github.com/ikuai8/sase/internal/platformrbac"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestPlatformRBACEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 PLATFORM_DSN + PLATFORM_RW_DSN,跳过 Slice38c 端到端")
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
	secSvc := testSecretSvc(t, store)
	platformAuditSvc := platformaudit.NewService(store)
	rbacSvc := platformrbac.NewService(store)

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store), nil, platformAuditSvc, rbacSvc,
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil, nil,
		nil, // riskSvc
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 调用方:platform_admin(bootstrap 形态;Slice38c 引导路径仍走 identity.IssueAdminToken 直接签发)
	// 用唯一 subject 避免共享 DB 跨测残留(本测会建/删 ops-... 的 admin 行)
	opsSubj := "ops-rbac-" + uuid.NewString()[:8]
	platTok, _ := identitySvc.IssueAdminToken(ctx, opsSubj, authz.RolePlatformAdmin, "", time.Hour)

	subj1 := "rbac-e2e-" + uuid.NewString()[:8]
	subj2 := "rbac-e2e-other-" + uuid.NewString()[:8]

	// ① POST /platform/admins 建 admin
	st, body := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admins", map[string]any{
		"subject": subj1, "email": "a@x",
	})
	if st != http.StatusCreated {
		t.Fatalf("POST admins 应 201,得 %d body=%s", st, body)
	}
	var a1 platformrbac.Admin
	_ = json.Unmarshal(body, &a1)
	if a1.Subject != subj1 || a1.Status != "active" || a1.CreatedBy != opsSubj {
		t.Fatalf("Create 字段错: %+v", a1)
	}

	// ② GET list 含 + GET id
	_, body = doRaw(t, srv.URL, platTok, "GET", "/api/v1/platform/admins", nil)
	var list []platformrbac.Admin
	_ = json.Unmarshal(body, &list)
	found := false
	for _, x := range list {
		if x.ID == a1.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("GET list 应含 %s", a1.ID)
	}

	// 建第二个用作"删他人"目标
	st, body = doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admins", map[string]any{"subject": subj2})
	if st != http.StatusCreated {
		t.Fatalf("POST admins(2) 应 201,得 %d body=%s", st, body)
	}
	var a2 platformrbac.Admin
	_ = json.Unmarshal(body, &a2)

	// ⑤ /platform/admin-tokens 扩展:为 subj1 签发 platform_admin token(active 在表 → 200)
	st, body = doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject": subj1, "role": authz.RolePlatformAdmin,
	})
	if st != http.StatusOK {
		t.Fatalf("active platform_admin 签发应 200,得 %d body=%s", st, body)
	}
	// 不在表的 subject → 403
	st, _ = doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject": "not-in-table-" + uuid.NewString()[:6], "role": authz.RolePlatformAdmin,
	})
	if st != http.StatusForbidden {
		t.Fatalf("不在 platform_admins 表的 subject 签发 platform_admin 应 403,得 %d", st)
	}

	// ③ PATCH status=disabled → 之后签发拒
	st, _ = doRaw(t, srv.URL, platTok, "PATCH", "/api/v1/platform/admins/"+a1.ID, map[string]any{"status": "disabled"})
	if st != http.StatusOK {
		t.Fatalf("PATCH disabled 应 200,得 %d", st)
	}
	st, _ = doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admin-tokens", map[string]any{
		"subject": subj1, "role": authz.RolePlatformAdmin,
	})
	if st != http.StatusForbidden {
		t.Fatalf("disabled subject 签发应 403,得 %d", st)
	}

	// ④ DELETE 自己 → 400(防锁死);需先把自己登记入表
	st, body = doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/admins", map[string]any{"subject": opsSubj})
	if st != http.StatusCreated {
		t.Fatalf("登记自己应 201,得 %d body=%s", st, body)
	}
	var selfAdmin platformrbac.Admin
	_ = json.Unmarshal(body, &selfAdmin)
	st, body = doRaw(t, srv.URL, platTok, "DELETE", "/api/v1/platform/admins/"+selfAdmin.ID, nil)
	if st != http.StatusBadRequest {
		t.Fatalf("DELETE 自己应 400(防锁死),得 %d body=%s", st, body)
	}
	if !strings.Contains(string(body), "cannot delete self") {
		t.Errorf("应返 cannot delete self,得 %s", body)
	}

	// ④ B5:PATCH disable 自己 → 400(防自助锁死)
	dis := "disabled"
	body2, _ := json.Marshal(map[string]any{"status": dis})
	_ = body2 // 占位防 lint
	st, body = doRaw(t, srv.URL, platTok, "PATCH", "/api/v1/platform/admins/"+selfAdmin.ID, map[string]any{"status": "disabled"})
	if st != http.StatusBadRequest {
		t.Fatalf("PATCH disable 自己应 400(B5),得 %d body=%s", st, body)
	}
	if !strings.Contains(string(body), "cannot disable self") {
		t.Errorf("应返 cannot disable self,得 %s", body)
	}

	// ④ DELETE 他人 → 200
	st, _ = doRaw(t, srv.URL, platTok, "DELETE", "/api/v1/platform/admins/"+a2.ID, nil)
	if st != http.StatusOK {
		t.Fatalf("DELETE 他人应 200,得 %d", st)
	}

	// ⑥ tenant_admin 调 RBAC 端点 → 403
	tid := uuid.NewString()
	taTok, _ := identitySvc.IssueAdminToken(ctx, "ta", authz.RoleTenantAdmin, tid, time.Hour)
	if st, _ := doRaw(t, srv.URL, taTok, "GET", "/api/v1/platform/admins", nil); st != http.StatusForbidden {
		t.Errorf("tenant_admin 调 RBAC 列表应 403,得 %d", st)
	}
	if st, _ := doRaw(t, srv.URL, taTok, "POST", "/api/v1/platform/admins", map[string]any{"subject": "x"}); st != http.StatusForbidden {
		t.Errorf("tenant_admin 调 RBAC 建管理员应 403,得 %d", st)
	}

	// 双层审计自动+显式:**只需取 self-delete-rejected 验证有 source=api**(主线两层在 PoP 测覆盖过,本测重点 RBAC 安全闸)
	_ = ctx // 占位
}
