package ztnaterm

// Slice77 C 单测(-race):5 元组解析 / appResolver 租户分域 / VerifyCred 四道闸入口 / 逐流 PEP 裁决 +
// 连接级缓存 / 撤销拆 session / deadline 兜底 / 出站写 PoP-TUN(allow)+ deny 丢弃 / 回程 Seal 写回。

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/pop"
)

const tenant = "11111111-1111-1111-1111-111111111111"

// ---- 脚手架 ----

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

// agentPoPSessions 造一对镜像方向的 dptunnel 会话(Agent send=Agent→PoP / PoP recv 一致),共享密钥。
func agentPoPSessions(t *testing.T) (agent, popSess *dptunnel.Session) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	a1, err := dptunnel.NewAEAD(dptunnel.AlgChaCha20Poly1305, key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	a2, err := dptunnel.NewAEAD(dptunnel.AlgChaCha20Poly1305, key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	// Agent 侧:send=dirAgent(1), recv=dirPoP(2);PoP 侧镜像。用 1/2 与 tunhandshake 方向常量一致。
	agent = dptunnel.NewSession(a1, 0, 1, 2)
	popSess = dptunnel.NewSession(a2, 0, 2, 1)
	return agent, popSess
}

func ipv4TCP(src, dst string, dport uint16) []byte {
	p := make([]byte, 24)
	p[0] = 0x45 // v4, IHL=5
	p[9] = 6    // TCP
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	p[22] = byte(dport >> 8)
	p[23] = byte(dport)
	return p
}

// fakeAddr 实现 net.Addr(测试用 srcAddr)。
type fakeAddr string

func (a fakeAddr) Network() string { return "udp" }
func (a fakeAddr) String() string  { return string(a) }

// allowBundle 造一条放行 group=eng → app 的 bundle;denyBundle 反之。
func allowBundle(app string) xdsv1.PolicyBundle {
	return xdsv1.PolicyBundle{TenantID: tenant, L7Rules: []xdsv1.L7Rule{
		{Priority: 10, SubjectKind: "group", SubjectValue: "eng", Resource: app, Action: "connect", Effect: xdsv1.EffectAllow},
	}}
}

// newTerm 装配一个 Terminator(MemIO 作 PoP-TUN),登入一个 Agent session,返回 term + popSession + tun。
func newTerm(t *testing.T, signer *cred.Signer, v *cred.Verifier, bundle *xdsv1.PolicyBundle, appCIDR, appKey string) (*Terminator, *dptunnel.Session, *dptunnel.MemIO, fakeAddr) {
	t.Helper()
	bundles := pop.NewBundleStore()
	if bundle != nil {
		bundles.Set(*bundle)
	}
	revoked := pop.NewRevocationStore()
	apps := NewAppResolver()
	if appCIDR != "" {
		if err := apps.Add(tenant, appCIDR, 0, appKey); err != nil {
			t.Fatalf("apps.Add: %v", err)
		}
	}
	tun := dptunnel.NewMemIO(16)
	term := New(v, bundles, revoked, apps, tun, nil, time.Hour)

	agentSess, popSess := agentPoPSessions(t)
	src := fakeAddr("10.0.0.9:5000")
	tok := issue(t, signer, tenant, "alice", "jti-1", []string{"eng"}, time.Hour)
	claims, verr := term.VerifyCred(tenant, tok, time.Now())
	if verr != nil {
		t.Fatalf("VerifyCred: %v", verr)
	}
	// 登终结表:PoP 侧 session(收 Agent→PoP)。
	term.Establish(tenant, claims, mustUDP(t, "10.0.0.9:5000"), func() (*dptunnel.Session, error) { return popSess, nil })
	_ = src
	return term, agentSess, tun, fakeAddr("10.0.0.9:5000")
}

func mustUDP(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	return a
}

func issue(t *testing.T, signer *cred.Signer, tid, sub, jti string, groups []string, ttl time.Duration) string {
	t.Helper()
	tok, err := signer.Issue(cred.Claims{JTI: jti, TenantID: tid, Subject: sub, Groups: groups}, ttl, time.Now())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

// sealInner 用 Agent session 封一个内层包为隧道数据报。
func sealInner(t *testing.T, agentSess *dptunnel.Session, inner []byte) []byte {
	t.Helper()
	frames, err := agentSess.Seal(inner)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("期望 1 帧,得 %d", len(frames))
	}
	return frames[0]
}

// ---- 测试 ----

func TestParse5Tuple(t *testing.T) {
	p := ipv4TCP("10.0.0.9", "10.99.0.5", 80)
	tup, ok := parse5Tuple(p)
	if !ok {
		t.Fatal("应解析成功")
	}
	if tup.DstIP.String() != "10.99.0.5" || tup.DstPort != 80 || tup.Proto != 6 {
		t.Fatalf("5 元组错: %+v", tup)
	}
	if _, ok := parse5Tuple([]byte{0x00}); ok {
		t.Fatal("短包应失败")
	}
	if _, ok := parse5Tuple(nil); ok {
		t.Fatal("空包应失败")
	}
	// 畸形 IHL(<5)→ 拒。
	bad := ipv4TCP("10.0.0.1", "10.0.0.2", 1)
	bad[0] = 0x44 // IHL=4
	if _, ok := parse5Tuple(bad); ok {
		t.Fatal("畸形 IHL 应失败")
	}
}

func TestAppResolverTenantIsolation(t *testing.T) {
	ar := NewAppResolver()
	if err := ar.Add(tenant, "10.99.0.0/24", 0, "app-a"); err != nil {
		t.Fatal(err)
	}
	if err := ar.Add("other", "10.99.0.0/24", 0, "app-other"); err != nil {
		t.Fatal(err)
	}
	if app, ok := ar.Resolve(tenant, net.ParseIP("10.99.0.5"), 80); !ok || app != "app-a" {
		t.Fatalf("本租户应解析到 app-a,得 %q ok=%v", app, ok)
	}
	// 跨租户不可见:tenant 域内查不到 other 的规则(若误用 other 的 app 即泄漏)。
	if app, _ := ar.Resolve(tenant, net.ParseIP("10.99.0.5"), 80); app == "app-other" {
		t.Fatal("跨租户隔离失败:解析到了他租户的 appKey")
	}
	// 未登记目的 → 无匹配。
	if _, ok := ar.Resolve(tenant, net.ParseIP("10.1.2.3"), 80); ok {
		t.Fatal("未登记目的应无匹配")
	}
	// 端口约束。
	if err := ar.Add(tenant, "10.88.0.0/24", 443, "https-app"); err != nil {
		t.Fatal(err)
	}
	if _, ok := ar.Resolve(tenant, net.ParseIP("10.88.0.1"), 80); ok {
		t.Fatal("端口 80 不应命中 443 规则")
	}
	if app, ok := ar.Resolve(tenant, net.ParseIP("10.88.0.1"), 443); !ok || app != "https-app" {
		t.Fatalf("端口 443 应命中,得 %q", app)
	}
}

func TestVerifyCredCrossTenantAndRevoked(t *testing.T) {
	signer, v := newSignerVerifier(t)
	bundles := pop.NewBundleStore()
	revoked := pop.NewRevocationStore()
	term := New(v, bundles, revoked, NewAppResolver(), dptunnel.NewMemIO(4), nil, time.Hour)

	// 合法。
	tok := issue(t, signer, tenant, "alice", "jti-ok", nil, time.Hour)
	if _, err := term.VerifyCred(tenant, tok, time.Now()); err != nil {
		t.Fatalf("合法 cred 应通过: %v", err)
	}
	// 跨租户:证书租户 != cred.tid → 拒。
	if _, err := term.VerifyCred("other-tenant", tok, time.Now()); err == nil {
		t.Fatal("交叉核对失败应拒(证书租户与 cred.tid 不符)")
	}
	// 撤销:jti 命中 → 拒(入口闸)。
	revoked.Set(tenant, []string{"jti-ok"})
	if _, err := term.VerifyCred(tenant, tok, time.Now()); err == nil {
		t.Fatal("撤销的 cred 应在入口闸被拒")
	}
	// 过期:VerifyCred 经 cred.Verify 拒。
	expTok := issue(t, signer, tenant, "alice", "jti-exp", nil, -time.Second)
	if _, err := term.VerifyCred(tenant, expTok, time.Now()); err == nil {
		t.Fatal("过期 cred 应拒")
	}
	// 伪签:另一签发器 → 验签失败。
	other, _ := cred.GenerateSigner()
	forged := issue(t, other, tenant, "m", "jti-f", nil, time.Hour)
	if _, err := term.VerifyCred(tenant, forged, time.Now()); err == nil {
		t.Fatal("伪签 cred 应拒(验签失败)")
	}
}

func TestForwardAllowWritesTUN(t *testing.T) {
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	term, agentSess, tun, src := newTerm(t, signer, v, &b, "10.99.0.0/24", "internal-app")

	inner := ipv4TCP("10.0.0.9", "10.99.0.5", 80)
	term.handleDatagram(sealInner(t, agentSess, inner), src)

	select {
	case got := <-tun.Out():
		// 写入 PoP-TUN 的应是解封出的原内层包(内核 SNAT 出站)。
		if string(got) != string(inner) {
			t.Fatalf("写入 TUN 的包与内层不符")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("allow 的包应写入 PoP-TUN,超时未见")
	}
}

func TestForwardDenyDropsAndCaches(t *testing.T) {
	signer, v := newSignerVerifier(t)
	// 放行的是 other-app,但目的解析为 internal-app → PEP default-deny。
	b := allowBundle("other-app")
	term, agentSess, tun, src := newTerm(t, signer, v, &b, "10.99.0.0/24", "internal-app")

	term.handleDatagram(sealInner(t, agentSess, ipv4TCP("10.0.0.9", "10.99.0.5", 80)), src)
	select {
	case got := <-tun.Out():
		t.Fatalf("deny 的包不应写入 PoP-TUN,却收到 %v", got)
	case <-time.After(300 * time.Millisecond):
	}
	// 验缓存:同流第二包仍 deny(走缓存,不再 PEP)。检查 flow 表已缓存 deny。
	ts := term.bySrc[src.String()]
	if ts == nil {
		t.Fatal("session 应在表中")
	}
	ts.mu.Lock()
	n := len(ts.flows)
	ts.mu.Unlock()
	if n != 1 {
		t.Fatalf("应缓存 1 条流裁决,得 %d", n)
	}
}

func TestForwardNoAppDenied(t *testing.T) {
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	// appResolver 为空 → 目的解析不出 resource → deny(默认拒绝),不写 TUN。
	term, agentSess, tun, src := newTerm(t, signer, v, &b, "", "")

	term.handleDatagram(sealInner(t, agentSess, ipv4TCP("10.0.0.9", "10.99.0.5", 80)), src)
	select {
	case <-tun.Out():
		t.Fatal("目的解析不出 resource 应 deny,不应写 TUN")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestUnknownSourceDropped(t *testing.T) {
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	term, agentSess, tun, _ := newTerm(t, signer, v, &b, "10.99.0.0/24", "internal-app")

	// 来自未注册源 → no_session 丢弃(不 panic、不写 TUN)。
	term.handleDatagram(sealInner(t, agentSess, ipv4TCP("10.0.0.9", "10.99.0.5", 80)), fakeAddr("9.9.9.9:1"))
	select {
	case <-tun.Out():
		t.Fatal("未注册源应丢弃,不应写 TUN")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestForgedDatagramDropped(t *testing.T) {
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	term, _, tun, src := newTerm(t, signer, v, &b, "10.99.0.0/24", "internal-app")

	// 已注册源但数据报无有效 AEAD(垃圾)→ decrypt_fail 丢弃,不 panic。
	term.handleDatagram([]byte("not-a-valid-sealed-datagram-xxxxxxxxxxxxxxxx"), src)
	select {
	case <-tun.Out():
		t.Fatal("伪造数据报应解封失败丢弃,不应写 TUN")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestEvictRevokedTearsDownSession(t *testing.T) {
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	term, _, _, src := newTerm(t, signer, v, &b, "10.99.0.0/24", "internal-app")

	if term.bySrc[src.String()] == nil {
		t.Fatal("session 应在表中")
	}
	// 撤销该 jti → 主撤销路径回调拆 session。
	term.revoked.Set(tenant, []string{"jti-1"})
	term.EvictRevoked(tenant)
	if term.bySrc[src.String()] != nil {
		t.Fatal("撤销后 session 应被拆除(主撤销路径)")
	}
	// 未撤销的他租户不受影响(此处只一个 session,验 EvictRevoked 不误拆其它租户)。
	term.EvictRevoked("other-tenant") // 不应 panic
}

func TestNewFlowGateRevokedTearsDown(t *testing.T) {
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	term, agentSess, tun, src := newTerm(t, signer, v, &b, "10.99.0.0/24", "internal-app")

	// 先撤销(模拟撤销集已更新但主回调未触达,靠新流闸兜底)。
	term.revoked.Set(tenant, []string{"jti-1"})
	// 新流到来 → 新流闸查吊销命中 → 拆 session + 丢包。
	term.handleDatagram(sealInner(t, agentSess, ipv4TCP("10.0.0.9", "10.99.0.5", 80)), src)
	select {
	case <-tun.Out():
		t.Fatal("撤销命中的新流应被拒,不应写 TUN")
	case <-time.After(200 * time.Millisecond):
	}
	if term.bySrc[src.String()] != nil {
		t.Fatal("新流闸命中撤销应拆 session")
	}
}

func TestDeadlineExpiryTearsDown(t *testing.T) {
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	bundles := pop.NewBundleStore()
	bundles.Set(b)
	revoked := pop.NewRevocationStore()
	apps := NewAppResolver()
	_ = apps.Add(tenant, "10.99.0.0/24", 0, "internal-app")
	tun := dptunnel.NewMemIO(8)
	term := New(v, bundles, revoked, apps, tun, nil, time.Hour)

	agentSess, popSess := agentPoPSessions(t)
	// cred TTL 1s → deadline ≈ now+1s。
	tok := issue(t, signer, tenant, "alice", "jti-1", []string{"eng"}, time.Second)
	claims, _ := term.VerifyCred(tenant, tok, time.Now())
	src := fakeAddr("10.0.0.9:5000")
	term.Establish(tenant, claims, mustUDP(t, "10.0.0.9:5000"), func() (*dptunnel.Session, error) { return popSess, nil })

	// 把 now 提前过 deadline。
	term.now = func() time.Time { return time.Now().Add(2 * time.Second) }
	term.handleDatagram(sealInner(t, agentSess, ipv4TCP("10.0.0.9", "10.99.0.5", 80)), src)
	if term.bySrc[src.String()] != nil {
		t.Fatal("deadline 到期应拆 session(兜底闸)")
	}
}

func TestReturnPumpSealsBackToAgent(t *testing.T) {
	signer, v := newSignerVerifier(t)
	b := allowBundle("internal-app")
	term, agentSess, tun, src := newTerm(t, signer, v, &b, "10.99.0.0/24", "internal-app")

	// 先来一个出向包,使终结器学到 Agent 内层 IP 10.0.0.9 → session。
	term.handleDatagram(sealInner(t, agentSess, ipv4TCP("10.0.0.9", "10.99.0.5", 80)), src)
	<-tun.Out() // 消费 allow 写出的包

	// 起回程 pump:用一个回环 UDP conn 收 Seal 回的数据报。
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// 把 session 的 srcAddr 改为本地回环可达地址(原 fakeAddr 不可达)。
	ts := term.bySrc[src.String()]
	ts.srcAddr = conn.LocalAddr()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go term.returnPump(ctx, conn)

	// 内核回程包(dst = Agent 内层 IP 10.0.0.9)注入 PoP-TUN。
	reply := ipv4TCP("10.99.0.5", "10.0.0.9", 80)
	tun.Inject(reply)

	// pump 应把回程 Seal 后经 UDP 发回 Agent;用 agentSess.Open 还原验证。
	buf := make([]byte, 65535)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, rerr := conn.ReadFrom(buf)
	if rerr != nil {
		t.Fatalf("回程未收到: %v", rerr)
	}
	pkts, oerr := agentSess.Open(append([]byte(nil), buf[:n]...))
	if oerr != nil || len(pkts) != 1 {
		t.Fatalf("Agent 解封回程失败: %v len=%d", oerr, len(pkts))
	}
	if string(pkts[0]) != string(reply) {
		t.Fatal("回程包内容不符")
	}
}
