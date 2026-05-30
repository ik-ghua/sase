package httpapi_test

// Slice55 admin 令牌主动撤销端到端(经真实 Admin HTTP 栈):
//   platform_admin 被 disable 后,其**已签出**令牌每请求复查 IsActive → 即时失效(401);
//   bootstrap 豁免 subject(不在表)的令牌不受影响。
// 需 SASE_DB_RW_DSN + PLATFORM_DSN + PLATFORM_RW_DSN;前置 migrations 0001-0022。

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
	"github.com/ikuai8/sase/internal/platformaudit"
	"github.com/ikuai8/sase/internal/platformrbac"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/tenant"
)

func TestAdminTokenActiveRevocation(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 PLATFORM_DSN + PLATFORM_RW_DSN,跳过 Slice55 主动撤销端到端")
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
	rbacSvc := platformrbac.NewService(store)

	// 主动撤销 checker(同 cmd 装配):bootstrap subject 豁免(不在表),其余查 IsActive。
	bootSub := "rev-boot-" + uuid.NewString()[:8]
	checker := func(ctx context.Context, subject string) (bool, error) {
		if subject == bootSub {
			return true, nil
		}
		return rbacSvc.IsActive(ctx, subject)
	}

	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store), identitySvc,
		policy.NewService(store), resource.NewService(store), audit.NewService(store),
		swg.NewService(store), site.NewService(store), fw.NewService(store), dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store), nil, platformaudit.NewService(store), rbacSvc,
		testIDPSvc(t, store, secSvc),
		nil, nil, nil, verifier, checker, nil,
		nil, // riskSvc
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 用 bootstrap 豁免令牌做 setup(其 subject 不在表,被 checker 豁免)
	bootTok, _ := identitySvc.IssueAdminToken(ctx, bootSub, authz.RolePlatformAdmin, "", time.Hour)

	// keeper:防 last-admin guard(Slice55)拦截 disable;rev:被撤销对象
	keeperSub := "rev-keeper-" + uuid.NewString()[:8]
	revSub := "rev-target-" + uuid.NewString()[:8]
	if st, b := doRaw(t, srv.URL, bootTok, "POST", "/api/v1/platform/admins", map[string]any{"subject": keeperSub}); st != http.StatusCreated {
		t.Fatalf("建 keeper 应 201,得 %d %s", st, b)
	}
	st, body := doRaw(t, srv.URL, bootTok, "POST", "/api/v1/platform/admins", map[string]any{"subject": revSub})
	if st != http.StatusCreated {
		t.Fatalf("建 rev-admin 应 201,得 %d %s", st, body)
	}
	var rev platformrbac.Admin
	_ = json.Unmarshal(body, &rev)

	// rev-admin 的 platform_admin 令牌(此刻 active 在表)
	revTok, _ := identitySvc.IssueAdminToken(ctx, revSub, authz.RolePlatformAdmin, "", time.Hour)

	// active → 200
	if st, _ := doRaw(t, srv.URL, revTok, "GET", "/api/v1/platform/tenants", nil); st != http.StatusOK {
		t.Fatalf("active 管理员令牌应 200,得 %d", st)
	}
	// disable rev-admin(keeper 在,非最后一枚 active,guard 不拦)
	if st, b := doRaw(t, srv.URL, bootTok, "PATCH", "/api/v1/platform/admins/"+rev.ID, map[string]any{"status": "disabled"}); st != http.StatusOK {
		t.Fatalf("disable rev-admin 应 200,得 %d %s", st, b)
	}
	// **主动撤销**:同一令牌未过期,但 subject 已 disabled → 即时失效 401
	if st, _ := doRaw(t, srv.URL, revTok, "GET", "/api/v1/platform/tenants", nil); st != http.StatusUnauthorized {
		t.Fatalf("disable 后令牌应即时失效 401,得 %d", st)
	}
	// bootstrap 豁免令牌仍 200(不在表,应急通道)
	if st, _ := doRaw(t, srv.URL, bootTok, "GET", "/api/v1/platform/tenants", nil); st != http.StatusOK {
		t.Fatalf("bootstrap 豁免令牌应仍 200,得 %d", st)
	}
}
