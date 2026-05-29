package httpapi_test

// Slice 8:管理面 TLS 收口——Admin API 经 HTTPS(单向 server-TLS)提供,明文 HTTP 被拒。
// 不需 DB:只打 GET /api/v1/trust/pubkey(identity 签发公钥,不触 store)。可无条件跑。

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/admin/httpapi"
	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
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

func TestAdminAPIServerTLS(t *testing.T) {
	store := data.NewStubStore() // 仅打 trust 端点,不触 DB
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("签发器: %v", err)
	}
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("验证器: %v", err)
	}
	secSvc := testSecretSvc(t, store)
	mux := http.NewServeMux()
	httpapi.Register(mux,
		tenant.NewService(store),
		identity.NewService(store, identity.WithSigner(signer)),
		policy.NewService(store),
		resource.NewService(store),
		audit.NewService(store),
		swg.NewService(store),
		site.NewService(store),
		fw.NewService(store),
		dlp.NewService(store),
		enroll.NewService(store, nil),
		platform.NewService(store),
		nil, // popReg
		nil, // platform audit svc
		nil, // platform RBAC svc
		testIDPSvc(t, store, secSvc),
		nil, // oidc deps
		nil, // 限流器(测试不限流)
		verifier, nil, nil,
		nil, // riskSvc
	)

	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	srvTLS, err := ca.ServerTLSServerOnly("localhost")
	if err != nil {
		t.Fatalf("server-only TLS: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	srv := &http.Server{Handler: mux, TLSConfig: srvTLS, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	defer srv.Close()
	addr := lis.Addr().String()

	// ① HTTPS(验服务端证书)→ 200 + pubkey
	cliTLS, err := ca.ClientTLS("localhost")
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	httpsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: cliTLS}, Timeout: 3 * time.Second}
	resp, err := httpsClient.Get("https://" + addr + "/api/v1/trust/pubkey")
	if err != nil {
		t.Fatalf("HTTPS 请求: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS 应 200,得 %d", resp.StatusCode)
	}
	var body struct {
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Pubkey == "" {
		t.Fatalf("应返回 pubkey,得 %+v err=%v", body, err)
	}

	// ② 不信任 dev CA 的客户端 → 证书校验失败(证明是真 server-TLS,非 InsecureSkipVerify)
	untrusted := &http.Client{Timeout: 3 * time.Second} // 默认走系统根,不含 dev CA
	if _, err := untrusted.Get("https://" + addr + "/api/v1/trust/pubkey"); err == nil {
		t.Fatal("不信任 CA 的客户端应因证书校验失败而报错")
	}
}
