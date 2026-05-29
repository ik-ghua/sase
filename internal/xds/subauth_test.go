package xds

// subauth 纯单测(无 PG):授权谓词全分支 + 用**真 devpki 签发证书**验 peerCertIdentity 提取
// (不用假证书,避免"提取逻辑看似对、真证书提不出"的假信心)。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	xdspb "github.com/ikuai8/sase/api/proto/sase/xds/v1"
	"github.com/ikuai8/sase/internal/devpki"
)

func TestAuthorizeSubscription(t *testing.T) {
	const tidA, tidB = "tenant-a", "tenant-b"
	cases := []struct {
		name       string
		role       string
		hasCert    bool
		certTenant string
		subTenant  string
		strict     bool
		wantOK     bool
	}{
		{"pop 订任意租户-宽松", devpki.RolePoP, true, "", tidA, false, true},
		{"pop 订任意租户-严格", devpki.RolePoP, true, "", tidB, true, true},
		{"device 订自身租户", devpki.RoleDevice, true, tidA, tidA, false, true},
		{"device 订自身租户-严格", devpki.RoleDevice, true, tidA, tidA, true, true},
		{"device 跨租户拒-宽松", devpki.RoleDevice, true, tidA, tidB, false, false},
		{"device 跨租户拒-严格", devpki.RoleDevice, true, tidA, tidB, true, false},
		{"device 空证书租户拒", devpki.RoleDevice, true, "", tidA, false, false},
		{"role-less 宽松放行", "", true, "", tidA, false, true},
		{"role-less 严格拒", "", true, "", tidA, true, false},
		{"无证书 宽松放行", "", false, "", tidA, false, true},
		{"无证书 严格拒", "", false, "", tidA, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := authorizeSubscription(c.role, c.hasCert, c.certTenant, c.subTenant, c.strict)
			if ok != c.wantOK {
				t.Fatalf("authorizeSubscription=%v(%s),期望 %v", ok, reason, c.wantOK)
			}
			if reason == "" {
				t.Fatalf("reason 不应为空(可观测性)")
			}
		})
	}
}

// 用真 devpki 证书 + 合成 peer ctx 验提取:role:device 出 (device, 租户)、role:pop 出 (pop, "")、无 peer 出 hasCert=false。
func TestPeerCertIdentity(t *testing.T) {
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	devCSR, _, _ := devpki.GenerateCSR("cpe-a")
	devPEM, err := ca.SignCSR(devCSR, "tenant-a", "cpe-a")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	role, certTenant, hasCert := peerCertIdentity(certCtx(t, devPEM))
	if !hasCert || role != devpki.RoleDevice || certTenant != "tenant-a" {
		t.Fatalf("device 证书应 (device, tenant-a, true),得 (%q, %q, %v)", role, certTenant, hasCert)
	}

	popCSR, _, _ := devpki.GenerateCSR("pop-1")
	popPEM, err := ca.SignPoP(popCSR, "pop-1")
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	role, certTenant, hasCert = peerCertIdentity(certCtx(t, popPEM))
	if !hasCert || role != devpki.RolePoP || certTenant != "" {
		t.Fatalf("pop 证书应 (pop, \"\", true),得 (%q, %q, %v)", role, certTenant, hasCert)
	}

	// 无 peer / 无 TLSInfo → hasCert=false
	if _, _, hc := peerCertIdentity(context.Background()); hc {
		t.Fatalf("无 peer ctx 应 hasCert=false")
	}
}

// certCtx 把一张 PEM 证书包成带已验证 mTLS 叶证书的 gRPC peer 上下文(模拟 RequireAndVerifyClientCert 后的 ctx)。
func certCtx(t *testing.T, certPEM []byte) context.Context {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("证书 PEM 解析失败")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("解析证书: %v", err)
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}},
	})
}

// subReq 构造订阅某 type URL 下某租户资源的 Delta 请求(共享给集成测试)。
func subReq(typeURL, tid string) *discoveryv3.DeltaDiscoveryRequest {
	return &discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResourceNamesSubscribe: []string{xdspb.ResourceName(tid)}}
}

// tenantRef 读某租户当前活跃订阅引用计数(持锁;共享给集成测试)。
func tenantRef(srv *Server, tid string) int {
	srv.refMu.Lock()
	defer srv.refMu.Unlock()
	return srv.tenantRefs[tid]
}

// 拒绝路径端到端 wiring(无 PG:拒在 load 前返回,store=nil 不被触及):
// ① device-A 证书订他租户 → PermissionDenied 且不填充缓存、不计引用;② 严格模式无证书订阅 → 拒;
// ③ wildcard 首请求(空 ResourceNamesSubscribe)→ 拒(评审 H1);④ 显式 "*" 资源名 → 拒。
func TestOnDeltaRequestAuthz(t *testing.T) {
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	ctx := context.Background()

	// ① device-A 跨租户被拒
	srv := NewServer(ctx, nil) // store=nil:拒绝路径不读 DB
	devCSR, _, _ := devpki.GenerateCSR("cpe-a")
	devPEM, err := ca.SignCSR(devCSR, "tenant-a", "cpe-a")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	const sid = int64(7)
	if err := srv.onDeltaStreamOpen(certCtx(t, devPEM), sid, ""); err != nil {
		t.Fatalf("onDeltaStreamOpen: %v", err)
	}
	err = srv.onDeltaRequest(sid, subReq(revTypeURL, "tenant-b"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("device-A 订 tenant-b 应 PermissionDenied,得 %v", err)
	}
	if _, exists := srv.revCache.GetResources()[xdspb.ResourceName("tenant-b")]; exists {
		t.Fatalf("跨租户订阅被拒后不应填充 tenant-b 缓存")
	}
	if got := tenantRef(srv, "tenant-b"); got != 0 {
		t.Fatalf("被拒订阅不应计引用,得 %d", got)
	}

	// ② 严格模式:无证书订阅被拒
	strict := NewServer(ctx, nil)
	strict.SetStrictSubAuth(true)
	const sid2 = int64(8)
	if err := strict.onDeltaStreamOpen(context.Background(), sid2, ""); err != nil {
		t.Fatalf("onDeltaStreamOpen: %v", err)
	}
	if err := strict.onDeltaRequest(sid2, subReq(revTypeURL, "tenant-x")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("严格模式无证书订阅应 PermissionDenied,得 %v", err)
	}

	// ③ wildcard 首请求(空 ResourceNamesSubscribe)→ 拒(评审 H1:否则 go-control-plane 置 wildcard watch 回全部租户)
	wc := NewServer(ctx, nil)
	const sid3 = int64(9)
	if err := wc.onDeltaStreamOpen(certCtx(t, devPEM), sid3, ""); err != nil {
		t.Fatalf("onDeltaStreamOpen: %v", err)
	}
	emptyReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: revTypeURL} // 空 ResourceNamesSubscribe = wildcard 触发
	if err := wc.onDeltaRequest(sid3, emptyReq); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wildcard 首请求应 PermissionDenied,得 %v", err)
	}

	// ④ 显式 "*" 资源名 → 拒(tenantFromName 返空,绝不静默放过)
	starReq := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: revTypeURL, ResourceNamesSubscribe: []string{"*"}}
	if err := wc.onDeltaRequest(sid3, starReq); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("显式 \"*\" 订阅应 PermissionDenied,得 %v", err)
	}
}
