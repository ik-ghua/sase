package httpapi_test

// POST /tenants/{tid}/apps 与 /tenants/{tid}/connectors 的错误码治理端到端
// (真 PG;需 SASE_DB_RW_DSN;未设则 SKIP)。前置:migrations 0001-0006。
//
// 背景:createApp/createConnector 此前对 svc 返回的**所有**错误一律 writeInternalErr(500),
// 把"缺字段"等输入校验错误也误报为 500。Slice73 接续 Slice72 5xx 脱敏,补完 4xx 治理:
//   - 缺必填字段(ErrInvalidResource)→ 400 + 回显安全校验文案;
//   - app_key 唯一冲突(apps 表 UNIQUE(tenant_id, app_key))→ 409(非 400/500);
//   - DB 错(非法 tid 使 tenant_id 类型转换在 DB 层失败)→ 500 脱敏,不直出底层 err。
// connectors 无 UNIQUE 约束,故只验校验错 400 + 创建成功 201。

import (
	"context"
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
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestResourceCreateErrorCodes(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 resource create 错误码端到端测试")
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

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store), nil, nil, nil,
		testIDPSvc(t, store, secSvc),
		nil, nil, verifier, nil, nil,
		nil,
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tA := uuid.NewString()
	taTok, err := identitySvc.IssueAdminToken(ctx, "ta", authz.RoleTenantAdmin, tA, time.Hour)
	if err != nil {
		t.Fatalf("签发 tenant_admin: %v", err)
	}
	platTok, err := identitySvc.IssueAdminToken(ctx, "plat", authz.RolePlatformAdmin, "", time.Hour)
	if err != nil {
		t.Fatalf("签发 platform_admin: %v", err)
	}

	// ── apps ──

	// (a) 缺字段(无 app_key)→ 400 + 回显安全校验文案(不应是 500)。
	st, body := doRaw(t, srv.URL, taTok, "POST", "/api/v1/tenants/"+tA+"/apps",
		map[string]string{"name": "no-key"})
	if st != http.StatusBadRequest {
		t.Fatalf("POST app 缺 app_key 应 400(非 500 误报),得 %d body=%s", st, body)
	}
	if !strings.Contains(string(body), "必填") {
		t.Fatalf("400 响应应回显校验文案(含\"必填\"),得 %q", string(body))
	}
	if strings.Contains(string(body), "internal error") {
		t.Fatalf("缺字段应是 400 校验错,不应是 500 脱敏文案,得 %q", string(body))
	}

	// (b) 正常创建 → 201。
	st, body = doRaw(t, srv.URL, taTok, "POST", "/api/v1/tenants/"+tA+"/apps",
		map[string]string{"app_key": "app-1", "name": "App One", "upstream": "10.0.0.1:443"})
	if st != http.StatusCreated {
		t.Fatalf("正常建 app 应 201,得 %d body=%s", st, body)
	}

	// (c) app_key 唯一冲突 → 409(非 400/500),且不泄漏底层约束细节。
	st, body = doRaw(t, srv.URL, taTok, "POST", "/api/v1/tenants/"+tA+"/apps",
		map[string]string{"app_key": "app-1", "name": "App Dup", "upstream": "10.0.0.2:443"})
	if st != http.StatusConflict {
		t.Fatalf("重复 app_key 应 409,得 %d body=%s", st, body)
	}
	if strings.Contains(string(body), "duplicate key") || strings.Contains(string(body), "uq_apps") {
		t.Fatalf("409 响应不应泄漏底层约束/SQLSTATE 细节,得 %q", string(body))
	}

	// (d) DB 错路径(非法 tid)→ 500 脱敏。platform_admin 经 path-tid 可达 handler;
	// 非 UUID 的 tenant_id 在 INSERT 时 DB 层类型转换失败 → DB 错(未包 ErrInvalidResource)→ 500。
	st, body = doRaw(t, srv.URL, platTok, "POST", "/api/v1/tenants/not-a-uuid/apps",
		map[string]string{"app_key": "k", "name": "n"})
	if st != http.StatusInternalServerError {
		t.Fatalf("DB 错(非法 tid)应 500,得 %d body=%s", st, body)
	}
	if strings.Contains(string(body), "invalid input syntax") || strings.Contains(string(body), "uuid") ||
		strings.Contains(string(body), "SQLSTATE") || strings.Contains(string(body), "pgx") {
		t.Fatalf("500 响应应脱敏(不含底层 DB/驱动细节),得 %q", string(body))
	}

	// ── connectors(无 UNIQUE 约束)──

	// (e) 缺字段(无 name)→ 400(非 500 误报)。
	st, body = doRaw(t, srv.URL, taTok, "POST", "/api/v1/tenants/"+tA+"/connectors",
		map[string]string{"app_key": "app-1"})
	if st != http.StatusBadRequest {
		t.Fatalf("POST connector 缺 name 应 400,得 %d body=%s", st, body)
	}
	if !strings.Contains(string(body), "必填") {
		t.Fatalf("connector 400 响应应回显校验文案(含\"必填\"),得 %q", string(body))
	}

	// (f) 正常创建 → 201。
	st, body = doRaw(t, srv.URL, taTok, "POST", "/api/v1/tenants/"+tA+"/connectors",
		map[string]string{"app_key": "app-1", "name": "conn-1"})
	if st != http.StatusCreated {
		t.Fatalf("正常建 connector 应 201,得 %d body=%s", st, body)
	}
}
