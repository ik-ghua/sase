package httpapi_test

// risk 评分快照只读端点端到端(真 PG;需 SASE_DB_RW_DSN;未设则 SKIP)。前置:migrations 0001-0023。
// 覆盖:
//   ① 落快照后 tenant_admin GET /tenants/{tid}/risk/{subject} → 200 + 正确 score/level/factors/updated_at。
//   ② 无快照 subject → 404。
//   ③ auditor(只读)GET → 200(子路径读放行)。
//   ④ **跨租户**:tenant_admin(本租户 tA)读 tB 的快照 → 403(authz 限本租户)。
//   ⑤ platform_admin 经 path-tid 读任意租户 → 200(对齐 listPolicies/listUsers 模式)。
//   ⑥ riskSvc=nil(未装配)→ 503(端点仍在,守路由清单)。

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
	"github.com/ikuai8/sase/internal/platform"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/risk"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestRiskScoreEndpoint(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 risk 端点端到端测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("签发器: %v", err)
	}
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("验证器: %v", err)
	}
	identitySvc := identity.NewService(store, identity.WithSigner(signer))
	secSvc := testSecretSvc(t, store)
	riskSvc := risk.NewService(nil, risk.WithStore(store))

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store), nil, nil, nil,
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil, nil,
		riskSvc,
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tA := uuid.NewString()
	tB := uuid.NewString()

	// 落快照:tA/alice 升 critical;tA/bob 由 DLP 命中(medium 区间)。
	riskSvc.ObservePosture(tA, "alice", "jti-a", "jailbroken_rooted")
	riskSvc.Report(tA, "bob", "jti-b", dlp.Finding{RuleName: "身份证", Severity: dlp.SeverityHigh})

	taTok, err := identitySvc.IssueAdminToken(ctx, "ta", authz.RoleTenantAdmin, tA, time.Hour)
	if err != nil {
		t.Fatalf("签发 tenant_admin(tA): %v", err)
	}
	tbTok, err := identitySvc.IssueAdminToken(ctx, "tb", authz.RoleTenantAdmin, tB, time.Hour)
	if err != nil {
		t.Fatalf("签发 tenant_admin(tB): %v", err)
	}
	audTok, err := identitySvc.IssueAdminToken(ctx, "aud", authz.RoleAuditor, tA, time.Hour)
	if err != nil {
		t.Fatalf("签发 auditor(tA): %v", err)
	}
	platTok, err := identitySvc.IssueAdminToken(ctx, "plat", authz.RolePlatformAdmin, "", time.Hour)
	if err != nil {
		t.Fatalf("签发 platform_admin: %v", err)
	}

	// ① tenant_admin 读 tA/alice → 200,critical。
	st, body := doRaw(t, srv.URL, taTok, "GET", "/api/v1/tenants/"+tA+"/risk/alice", nil)
	if st != http.StatusOK {
		t.Fatalf("tenant_admin 读 tA/alice 应 200,得 %d body=%s", st, body)
	}
	var sc struct {
		Subject   string `json:"subject"`
		Score     int    `json:"score"`
		Level     string `json:"level"`
		Factors   []any  `json:"factors"`
		UpdatedAt string `json:"updated_at"`
	}
	if e := json.Unmarshal(body, &sc); e != nil {
		t.Fatalf("解析快照: %v body=%s", e, body)
	}
	if sc.Subject != "alice" || sc.Level != string(risk.LevelCritical) || sc.UpdatedAt == "" {
		t.Fatalf("tA/alice 快照应 critical+updated_at,得 %+v", sc)
	}
	if len(sc.Factors) == 0 {
		t.Fatalf("critical 快照应含 factors,得 %+v", sc)
	}

	// ② 无快照 subject → 404。
	st, _ = doRaw(t, srv.URL, taTok, "GET", "/api/v1/tenants/"+tA+"/risk/nobody", nil)
	if st != http.StatusNotFound {
		t.Fatalf("无快照应 404,得 %d", st)
	}

	// ③ auditor(只读)GET tA/bob → 200。
	st, body = doRaw(t, srv.URL, audTok, "GET", "/api/v1/tenants/"+tA+"/risk/bob", nil)
	if st != http.StatusOK {
		t.Fatalf("auditor 读 tA/bob 应 200,得 %d body=%s", st, body)
	}

	// ④ 跨租户:tB 的 tenant_admin 读 tA/alice → 403(authz 限本租户)。
	st, _ = doRaw(t, srv.URL, tbTok, "GET", "/api/v1/tenants/"+tA+"/risk/alice", nil)
	if st != http.StatusForbidden {
		t.Fatalf("跨租户读应 403,得 %d", st)
	}

	// ⑤ platform_admin 经 path-tid 读任意租户 → 200。
	st, body = doRaw(t, srv.URL, platTok, "GET", "/api/v1/tenants/"+tA+"/risk/alice", nil)
	if st != http.StatusOK {
		t.Fatalf("platform_admin 经 path-tid 读应 200,得 %d body=%s", st, body)
	}
}

// TestRiskScoreEndpointNotConfigured:riskSvc=nil(未装配)→ 503(端点仍在,守路由清单)。
func TestRiskScoreEndpointNotConfigured(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过")
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

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store), nil, nil, nil,
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil, nil,
		nil, // riskSvc=nil
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tid := uuid.NewString()
	platTok, _ := identitySvc.IssueAdminToken(ctx, "plat", authz.RolePlatformAdmin, "", time.Hour)
	st, body := doRaw(t, srv.URL, platTok, "GET", "/api/v1/tenants/"+tid+"/risk/x", nil)
	if st != http.StatusServiceUnavailable {
		t.Fatalf("riskSvc=nil 应 503,得 %d body=%s", st, body)
	}
}
