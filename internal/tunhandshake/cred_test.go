package tunhandshake_test

// Slice77 A:tunhandshake 加可选会话凭证验证(ZTNA 形态),SD-WAN 形态零改回归。
// 验:① NewServerWithCred 验过 cred 后 Established.Claims 透出 principal;② 签名失败/格式坏拒握手;
// ③ 跨租户(cred.tid != 证书 Org)拒;④ SD-WAN NewServer(不设 hook)行为不变(Cred 不被消费、Claims 零值)。

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/tunhandshake"
)

// credPoP 起一个挂 verifyCred 的握手服务,返回握手地址 + 收到的 Established(线程安全)。
type credPoP struct {
	addr string
	mu   sync.Mutex
	est  []tunhandshake.Established
}

func (c *credPoP) established() []tunhandshake.Established {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]tunhandshake.Established(nil), c.est...)
}

// startCredPoP 起握手服务,verifyCred = 真 cred.Verifier 验签 + 交叉核对租户(模拟终结器入口闸)。
func startCredPoP(t *testing.T, ctx context.Context, ca *devpki.CA, v *cred.Verifier) *credPoP {
	t.Helper()
	dataConn := udpConn(t)
	cp := &credPoP{}
	verify := func(certTenant, token string, now time.Time) (cred.Claims, error) {
		claims, err := v.Verify(token, now)
		if err != nil {
			return cred.Claims{}, err
		}
		if claims.TenantID != certTenant {
			return cred.Claims{}, errTestTenantMismatch
		}
		return claims, nil
	}
	srv := tunhandshake.NewServerWithCred(dataConn.LocalAddr().String(), dptunnel.AlgChaCha20Poly1305,
		func(e tunhandshake.Established) {
			cp.mu.Lock()
			cp.est = append(cp.est, e)
			cp.mu.Unlock()
		}, verify)

	popCfg, err := ca.ServerTLS("localhost")
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ln := tls.NewListener(tcpLn, popCfg)
	go func() { _ = srv.Serve(ctx, ln) }()
	cp.addr = ln.Addr().String()
	return cp
}

var errTestTenantMismatch = errTest("租户不符")

type errTest string

func (e errTest) Error() string { return string(e) }

func issueCred(t *testing.T, signer *cred.Signer, tenant, sub, jti string, groups []string, ttl time.Duration) string {
	t.Helper()
	tok, err := signer.Issue(cred.Claims{JTI: jti, TenantID: tenant, Subject: sub, Groups: groups}, ttl, time.Now())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

func newSignerVerifier(t *testing.T) (*cred.Signer, *cred.Verifier) {
	t.Helper()
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	v, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return signer, v
}

func TestHandshakeCredVerifiedClaimsExposed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)
	signer, v := newSignerVerifier(t)
	cp := startCredPoP(t, ctx, ca, v)

	tenant := "11111111-1111-1111-1111-111111111111"
	tok := issueCred(t, signer, tenant, "alice", "jti-ok", []string{"eng"}, time.Hour)

	dataConn := udpConn(t)
	res, err := tunhandshake.DialWithCred(ctx, cp.addr, deviceTLS(t, ca, tenant, "dev1"),
		dptunnel.AlgChaCha20Poly1305, dataConn.LocalAddr().String(), tenant, "dev1", tok)
	if err != nil {
		t.Fatalf("DialWithCred(合法 cred)应成功: %v", err)
	}
	if res.Tenant != tenant {
		t.Fatalf("Result.Tenant=%q", res.Tenant)
	}
	// 校验 PoP 侧 Established.Claims 透出已验 principal。
	waitFor(t, func() bool { return len(cp.established()) == 1 })
	got := cp.established()[0]
	if got.Claims.Subject != "alice" || got.Claims.JTI != "jti-ok" {
		t.Fatalf("Established.Claims 未透出 principal: %+v", got.Claims)
	}
	if len(got.Claims.Groups) != 1 || got.Claims.Groups[0] != "eng" {
		t.Fatalf("groups 未透出: %v", got.Claims.Groups)
	}
}

func TestHandshakeCredBadSignatureRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)
	_, v := newSignerVerifier(t)
	cp := startCredPoP(t, ctx, ca, v)

	// 用**另一签发器**签的 token → 验签失败。
	otherSigner, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	tenant := "11111111-1111-1111-1111-111111111111"
	forged := issueCred(t, otherSigner, tenant, "mallory", "jti-x", nil, time.Hour)

	dataConn := udpConn(t)
	_, err = tunhandshake.DialWithCred(ctx, cp.addr, deviceTLS(t, ca, tenant, "dev1"),
		dptunnel.AlgChaCha20Poly1305, dataConn.LocalAddr().String(), tenant, "dev1", forged)
	if err == nil {
		t.Fatal("伪签 cred 应拒握手(验签失败 fail-closed),却成功")
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(cp.established()); n != 0 {
		t.Fatalf("验签失败不应触发 onEstablished,却有 %d 个", n)
	}
}

func TestHandshakeCredCrossTenantRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)
	signer, v := newSignerVerifier(t)
	cp := startCredPoP(t, ctx, ca, v)

	// 设备证书租户 = tenantA,但 cred 的 tid = tenantB → 交叉核对失败拒握手(防拼接绕隔离)。
	tenantA := "11111111-1111-1111-1111-111111111111"
	tenantB := "22222222-2222-2222-2222-222222222222"
	credB := issueCred(t, signer, tenantB, "bob", "jti-b", nil, time.Hour)

	dataConn := udpConn(t)
	_, err := tunhandshake.DialWithCred(ctx, cp.addr, deviceTLS(t, ca, tenantA, "dev1"),
		dptunnel.AlgChaCha20Poly1305, dataConn.LocalAddr().String(), tenantA, "dev1", credB)
	if err == nil {
		t.Fatal("证书租户(A)与凭证租户(B)不符应拒握手(交叉核对),却成功")
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(cp.established()); n != 0 {
		t.Fatalf("交叉核对失败不应触发 onEstablished,却有 %d 个", n)
	}
}

func TestHandshakeCredMissingRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)
	_, v := newSignerVerifier(t)
	cp := startCredPoP(t, ctx, ca, v)

	tenant := "11111111-1111-1111-1111-111111111111"
	// 不携 cred(空)→ verifyCred 验空 token → 格式非法拒。
	dataConn := udpConn(t)
	_, err := tunhandshake.DialWithCred(ctx, cp.addr, deviceTLS(t, ca, tenant, "dev1"),
		dptunnel.AlgChaCha20Poly1305, dataConn.LocalAddr().String(), tenant, "dev1", "")
	if err == nil {
		t.Fatal("ZTNA 形态空 cred 应拒握手,却成功")
	}
}

// TestSDWANNoCredHookRegression:SD-WAN 形态 NewServer(不设 verifyCred)行为与旧版一致——
// CPE 即便误带 Cred 也不被消费,Established.Claims 为零值,握手照常成功。
func TestSDWANNoCredHookRegression(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newCA(t)

	dataConn := udpConn(t)
	var mu sync.Mutex
	var est []tunhandshake.Established
	srv := tunhandshake.NewServer(dataConn.LocalAddr().String(), dptunnel.AlgChaCha20Poly1305,
		func(e tunhandshake.Established) {
			mu.Lock()
			est = append(est, e)
			mu.Unlock()
		})
	popCfg, err := ca.ServerTLS("localhost")
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ln := tls.NewListener(tcpLn, popCfg)
	go func() { _ = srv.Serve(ctx, ln) }()

	tenant := "t1"
	// 携一个垃圾 cred —— SD-WAN 形态不设 hook,绝不消费它,握手仍成功。
	cdc := udpConn(t)
	_, err = tunhandshake.DialWithCred(ctx, ln.Addr().String(), deviceTLS(t, ca, tenant, "siteA"),
		dptunnel.AlgChaCha20Poly1305, cdc.LocalAddr().String(), tenant, "siteA", "garbage.token")
	if err != nil {
		t.Fatalf("SD-WAN 形态(无 hook)握手应成功(不消费 Cred): %v", err)
	}
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(est) == 1
	})
	mu.Lock()
	got := est[0]
	mu.Unlock()
	if got.Claims.Subject != "" || got.Claims.JTI != "" {
		t.Fatalf("SD-WAN 形态 Established.Claims 应为零值(不验 cred),却 %+v", got.Claims)
	}
	// 普通 Dial(零改签名)同样应成功。
	cdc2 := udpConn(t)
	if _, err := tunhandshake.Dial(ctx, ln.Addr().String(), deviceTLS(t, ca, tenant, "siteB"),
		dptunnel.AlgChaCha20Poly1305, cdc2.LocalAddr().String(), tenant, "siteB"); err != nil {
		t.Fatalf("普通 Dial(SD-WAN 零改)应成功: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}
