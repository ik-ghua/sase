package httpapi_test

// Slice39 平台审计端到端(经真实 Admin HTTP 栈):验证
//   ① PoP 注册(POST /platform/pop-nodes)成功 → DB 触发器写 source=data + handler 显式写 source=api 两条;
//   ② actor_subject 经 authz Principal + data.WithActor → 触发器/handler 同源;
//   ③ GET /api/v1/platform/audit 列平台审计(认 platform_admin only);
//   ④ tenant_admin 调用 → 403;
//   ⑤ 失败路径(name 重复 → 409)经 handler 显式写 source=api(触发器因事务回滚不写)。
// 需 SASE_DB_RW_DSN + PLATFORM_DSN + PLATFORM_RW_DSN;前置 migrations 0001-0021。

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
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestPlatformAuditEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 SASE_DB_RW_DSN + PLATFORM_DSN + PLATFORM_RW_DSN,跳过 Slice39 端到端")
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
	popReg := platform.NewPopRegistry(store)
	platformAuditSvc := platformaudit.NewService(store)

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store), popReg, platformAuditSvc,
		nil, // platform RBAC svc:本测覆盖 Slice39 平台审计,不走 RBAC
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil, nil,
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	platTok, _ := identitySvc.IssueAdminToken(ctx, "ops-39", authz.RolePlatformAdmin, "", time.Hour)

	// 用唯一前缀避免共享 DB 历史影响
	popName := "audit-pop-" + uuid.NewString()[:8]
	st, body := doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/pop-nodes", map[string]any{
		"name": popName, "region": "cn-test", "endpoint": "x:443",
	})
	if st != http.StatusCreated {
		t.Fatalf("POST pop-nodes 应 201,得 %d body=%s", st, body)
	}
	var p platform.PoP
	_ = json.Unmarshal(body, &p)

	// GET /platform/audit;应含 source=data(action=INSERT pop_nodes detail=id=...)+ source=api(action=POST .../pop-nodes)两条
	st, body = doRaw(t, srv.URL, platTok, "GET", "/api/v1/platform/audit?limit=200", nil)
	if st != http.StatusOK {
		t.Fatalf("GET audit 应 200,得 %d body=%s", st, body)
	}
	var es []platformaudit.Entry
	if e := json.Unmarshal(body, &es); e != nil {
		t.Fatalf("解审计: %v", e)
	}
	var sawData, sawAPI bool
	for _, e := range es {
		// 关心本次插入的行
		if !strings.Contains(e.Detail, p.ID) && !strings.Contains(e.Detail, popName) {
			continue
		}
		if e.Source == platformaudit.SourceData && e.Action == "INSERT pop_nodes" {
			sawData = true
			if e.ActorSubject != "ops-39" || e.ActorRole != authz.RolePlatformAdmin {
				t.Errorf("source=data actor 错: %+v", e)
			}
		}
		if e.Source == platformaudit.SourceAPI && e.Action == "POST /api/v1/platform/pop-nodes" {
			sawAPI = true
			if e.ActorSubject != "ops-39" || e.Result != http.StatusCreated {
				t.Errorf("source=api 字段错: %+v", e)
			}
			if !strings.Contains(e.Detail, "name="+popName) {
				t.Errorf("source=api detail 应含 name=%s,得 %q", popName, e.Detail)
			}
		}
	}
	if !sawData {
		t.Errorf("应有 source=data 触发器审计(action=INSERT pop_nodes detail 含 id=%s)", p.ID)
	}
	if !sawAPI {
		t.Errorf("应有 source=api handler 审计(action=POST .../pop-nodes detail 含 name=%s)", popName)
	}

	// ④ tenant_admin 调 GET /platform/audit → 403
	tid := uuid.NewString()
	taTok, _ := identitySvc.IssueAdminToken(ctx, "ta", authz.RoleTenantAdmin, tid, time.Hour)
	if st, _ := doRaw(t, srv.URL, taTok, "GET", "/api/v1/platform/audit", nil); st != http.StatusForbidden {
		t.Fatalf("tenant_admin 调平台审计应 403,得 %d", st)
	}

	// ⑤ 失败路径(name 重复 → 409),handler 显式写 source=api 失败行;触发器因事务回滚不写
	st, _ = doRaw(t, srv.URL, platTok, "POST", "/api/v1/platform/pop-nodes", map[string]any{
		"name": popName, "region": "cn-test2", "endpoint": "y:443",
	})
	if st != http.StatusConflict {
		t.Fatalf("重复 name 应 409,得 %d", st)
	}
	_, body = doRaw(t, srv.URL, platTok, "GET", "/api/v1/platform/audit?limit=200", nil)
	es = es[:0]
	_ = json.Unmarshal(body, &es)
	var sawFailAPI bool
	for _, e := range es {
		if e.Source == platformaudit.SourceAPI && e.Action == "POST /api/v1/platform/pop-nodes" &&
			e.Result == http.StatusConflict && strings.Contains(e.Detail, "name="+popName) {
			sawFailAPI = true
		}
	}
	if !sawFailAPI {
		t.Errorf("失败路径应有 source=api result=409 审计(覆盖 2xx-零变更盲区)")
	}
}
