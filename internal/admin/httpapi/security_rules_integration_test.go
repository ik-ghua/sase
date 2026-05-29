package httpapi_test

// Slice62 安全规则 PUT/DELETE 全链路 HTTP e2e(真 PG):经真实 router+中间件链验证
//   - POST → 201 + 响应含 id;PUT 全量替换 → 200 + 列表反映更新;PUT 不存在 id → 404;
//   - authz:auditor(只读)PUT/DELETE → 403(子路径写,line161 拒);DELETE → 204、再 DELETE → 404。
// SWG 作模板(fw/dlp 的 handler 逻辑与 authz 同形,由各自 service 集成测覆盖)。需 SASE_DB_RW_DSN。

import (
	"bytes"
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
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestSecurityRuleLifecycleHTTP(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过安全规则 HTTP e2e")
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
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tid := uuid.NewString()
	taTok, err := identitySvc.IssueAdminToken(ctx, "ta", authz.RoleTenantAdmin, tid, time.Hour)
	if err != nil {
		t.Fatalf("签发 tenant_admin 令牌: %v", err)
	}
	audTok, err := identitySvc.IssueAdminToken(ctx, "aud", authz.RoleAuditor, tid, time.Hour)
	if err != nil {
		t.Fatalf("签发 auditor 令牌: %v", err)
	}

	base := "/api/v1/tenants/" + tid + "/swg/rules"

	// POST 建规则 → 201 + 响应含 id
	st, body := doRaw(t, srv.URL, taTok, "POST", base, map[string]string{"kind": "host", "pattern": "evil.com", "action": "block"})
	if st != http.StatusCreated {
		t.Fatalf("POST swg 规则应 201,得 %d body=%s", st, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if e := json.Unmarshal(body, &created); e != nil || created.ID == "" {
		t.Fatalf("POST 响应应含 id,得 body=%s err=%v", body, e)
	}
	id := created.ID

	// PUT 全量替换 → 200;GET 列表反映更新
	do(t, srv.URL, taTok, "PUT", base+"/"+id, map[string]string{"kind": "host", "pattern": "worse.com", "action": "block"}, http.StatusOK)
	_, lb := doRaw(t, srv.URL, taTok, "GET", base, nil)
	if !bytes.Contains(lb, []byte("worse.com")) || bytes.Contains(lb, []byte("evil.com")) {
		t.Fatalf("列表应反映更新(worse.com 替 evil.com),得 %s", lb)
	}

	// PUT 不存在 id → 404
	do(t, srv.URL, taTok, "PUT", base+"/"+uuid.NewString(), map[string]string{"kind": "host", "pattern": "x.com", "action": "block"}, http.StatusNotFound)

	// Slice66 错误码治理:PUT 校验失败(非法 kind)→ 400(非 500;ErrInvalidRule 分流)
	do(t, srv.URL, taTok, "PUT", base+"/"+id, map[string]string{"kind": "bogus", "pattern": "x", "action": "block"}, http.StatusBadRequest)
	// POST 校验失败(缺 pattern)→ 400
	do(t, srv.URL, taTok, "POST", base, map[string]string{"kind": "host", "action": "block"}, http.StatusBadRequest)

	// authz:auditor(只读)PUT/DELETE → 403(子路径写被 authz line161 拒)
	do(t, srv.URL, audTok, "PUT", base+"/"+id, map[string]string{"kind": "host", "pattern": "y.com", "action": "block"}, http.StatusForbidden)
	do(t, srv.URL, audTok, "DELETE", base+"/"+id, nil, http.StatusForbidden)

	// DELETE → 204;再 DELETE → 404
	do(t, srv.URL, taTok, "DELETE", base+"/"+id, nil, http.StatusNoContent)
	do(t, srv.URL, taTok, "DELETE", base+"/"+id, nil, http.StatusNotFound)
}
