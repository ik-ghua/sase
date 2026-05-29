package dptunnel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// LPM trie 单测:直接验 lpm.go 的最长前缀/同族隔离/无命中/多 CIDR/空表,
// 与 router_test 经 route() 的端到端覆盖互补(此处只测 trie 本身)。

// v4ones 解析 CIDR 并断言其为 v4,返回 4 字节规范网络地址 + ones(对齐 rebuildRoutesLocked 的 v4 入 trie 方式)。
func v4ones(t *testing.T, s string) (net.IP, int) {
	t.Helper()
	n := cidr(t, s)
	ip4 := n.IP.To4()
	if ip4 == nil {
		t.Fatalf("%s 不是 v4 CIDR", s)
	}
	ones, _ := n.Mask.Size()
	return ip4, ones
}

func TestLPMLongestPrefixWins(t *testing.T) {
	tr := newLPMTrie(32)
	broad := &siteEntry{site: "broad"} // 10.0.0.0/8
	narrow := &siteEntry{site: "narrow"}

	// 故意先插更宽前缀、再插更窄前缀,验终值只看前缀长度、与插入顺序无关
	ip, ones := v4ones(t, "10.0.0.0/8")
	tr.insert(ip, ones, broad)
	ip, ones = v4ones(t, "10.1.0.0/16")
	tr.insert(ip, ones, narrow)

	// 10.1.0.5 同时命中 /8 与 /16 → 取最长 /16(narrow)
	if got := tr.longestPrefix(net.ParseIP("10.1.0.5").To4()); got != narrow {
		t.Fatalf("10.1.0.5 应命中最长前缀 /16(narrow),得 %v", got)
	}
	// 10.2.0.5 只命中 /8 → broad
	if got := tr.longestPrefix(net.ParseIP("10.2.0.5").To4()); got != broad {
		t.Fatalf("10.2.0.5 只在 /8 内,应得 broad,得 %v", got)
	}
}

// 顺序无关:先窄后宽插入,10.1.0.5 仍应命中最长 /16。
func TestLPMInsertOrderIndependent(t *testing.T) {
	tr := newLPMTrie(32)
	broad := &siteEntry{site: "broad"}
	narrow := &siteEntry{site: "narrow"}
	ip, ones := v4ones(t, "10.1.0.0/16")
	tr.insert(ip, ones, narrow)
	ip, ones = v4ones(t, "10.0.0.0/8")
	tr.insert(ip, ones, broad)
	if got := tr.longestPrefix(net.ParseIP("10.1.0.5").To4()); got != narrow {
		t.Fatalf("插入顺序不应影响最长前缀:应得 narrow,得 %v", got)
	}
}

func TestLPMNoMatchNil(t *testing.T) {
	tr := newLPMTrie(32)
	site := &siteEntry{site: "s"}
	ip, ones := v4ones(t, "10.1.0.0/24")
	tr.insert(ip, ones, site)
	if got := tr.longestPrefix(net.ParseIP("192.168.0.1").To4()); got != nil {
		t.Fatalf("无匹配前缀应返回 nil,得 %v", got)
	}
}

func TestLPMEmptyTrie(t *testing.T) {
	if got := newLPMTrie(32).longestPrefix(net.ParseIP("10.0.0.1").To4()); got != nil {
		t.Fatalf("空 trie 应返回 nil,得 %v", got)
	}
	if got := newLPMTrie(128).longestPrefix(net.ParseIP("2001:db8::1").To16()); got != nil {
		t.Fatalf("空 v6 trie 应返回 nil,得 %v", got)
	}
}

// 一个站点挂多个 CIDR:同一 siteEntry 经多次 insert,各前缀均命中该站点。
func TestLPMOneSiteMultipleCIDRs(t *testing.T) {
	tr := newLPMTrie(32)
	site := &siteEntry{site: "multi"}
	for _, c := range []string{"10.1.0.0/24", "10.2.0.0/24", "172.16.0.0/12"} {
		ip, ones := v4ones(t, c)
		tr.insert(ip, ones, site)
	}
	for _, dst := range []string{"10.1.0.9", "10.2.0.9", "172.16.5.5"} {
		if got := tr.longestPrefix(net.ParseIP(dst).To4()); got != site {
			t.Fatalf("%s 应命中 multi 站点,得 %v", dst, got)
		}
	}
	if got := tr.longestPrefix(net.ParseIP("10.3.0.9").To4()); got != nil {
		t.Fatalf("10.3.0.9 不在任何 CIDR,应 nil,得 %v", got)
	}
}

// v4/v6 隔离:同 ones(如 /24)的 v4 与 v6 前缀在各自 trie 内,不互相误配。
// 经 route() 选路时按目的族分流到对应 trie——此处直接验两棵 trie 互不串扰。
func TestLPMFamilyIsolation(t *testing.T) {
	v4 := newLPMTrie(32)
	v6 := newLPMTrie(128)
	s4 := &siteEntry{site: "v4"}
	s6 := &siteEntry{site: "v6"}

	ip, ones := v4ones(t, "10.2.0.0/24")
	v4.insert(ip, ones, s4)

	n6 := cidr(t, "2001:db8::/32")
	o6, _ := n6.Mask.Size()
	v6.insert(n6.IP.To16(), o6, s6)

	// v4 目的只查 v4 trie:命中 s4;v6 目的查 v6 trie:命中 s6
	if got := v4.longestPrefix(net.ParseIP("10.2.0.9").To4()); got != s4 {
		t.Fatalf("v4 trie 应命中 s4,得 %v", got)
	}
	if got := v6.longestPrefix(net.ParseIP("2001:db8::1").To16()); got != s6 {
		t.Fatalf("v6 trie 应命中 s6,得 %v", got)
	}
	// v6 目的查 v4 trie 不应误配(模拟若错误地跨族查询)——v4 trie 里没有 v6 前缀
	if got := v4.longestPrefix(net.ParseIP("10.0.0.0").To4()); got != nil {
		t.Fatalf("v4 trie 对未覆盖的 v4 目的应 nil,得 %v", got)
	}
}

// 同前缀重复插入:后插入覆盖(终态确定,等价 Router 重建后该前缀对应唯一站点)。
func TestLPMSamePrefixOverwrite(t *testing.T) {
	tr := newLPMTrie(32)
	first := &siteEntry{site: "first"}
	second := &siteEntry{site: "second"}
	ip, ones := v4ones(t, "10.5.0.0/16")
	tr.insert(ip, ones, first)
	tr.insert(ip, ones, second)
	if got := tr.longestPrefix(net.ParseIP("10.5.0.1").To4()); got != second {
		t.Fatalf("同前缀重复插入应取后者(second),得 %v", got)
	}
}

// /0 默认路由:覆盖整个 v4 空间,任意 v4 目的在无更长匹配时命中之。
func TestLPMDefaultRoute(t *testing.T) {
	tr := newLPMTrie(32)
	def := &siteEntry{site: "default"}
	specific := &siteEntry{site: "specific"}
	_, dn, _ := net.ParseCIDR("0.0.0.0/0")
	tr.insert(dn.IP.To4(), 0, def)
	ip, ones := v4ones(t, "10.1.0.0/24")
	tr.insert(ip, ones, specific)

	if got := tr.longestPrefix(net.ParseIP("8.8.8.8").To4()); got != def {
		t.Fatalf("无更长匹配应命中默认路由,得 %v", got)
	}
	if got := tr.longestPrefix(net.ParseIP("10.1.0.5").To4()); got != specific {
		t.Fatalf("有更长匹配应命中 specific,得 %v", got)
	}
}

// v4-mapped IPv6(::ffff:a.b.c.d)经 route() 命中 v4 站点:route() 用 dst.To4() 归一,
// v4-mapped 地址 To4() 返回 4 字节 v4 → 进 v4 trie,不会被当成 v6 误进 v6 树(导致无路由)。
// 把这条不变量钉进测试(此前靠人工推理 route() 的 To4() 派发正确性)。
func TestRouteV4MappedHitsV4Trie(t *testing.T) {
	r := NewRouter()
	v4site := &siteEntry{tenant: "t1", site: "v4"}
	v6site := &siteEntry{tenant: "t1", site: "v6"}
	// 直接挂表 + 重建,避开 Register 对真 Session 的依赖(route() 只读 routes,不碰 sess)。
	r.byTenant["t1"] = []*siteEntry{v4site, v6site}
	v4site.cidrs = []*net.IPNet{cidr(t, "10.2.0.0/24")}
	v6site.cidrs = []*net.IPNet{cidr(t, "2001:db8::/32")}
	r.mu.Lock()
	r.rebuildRoutesLocked("t1")
	r.mu.Unlock()

	// ::ffff:10.2.0.9 是 10.2.0.9 的 v4-mapped 形式:其 To4() 非 nil → route 走 v4 trie → 命中 v4 站点。
	mapped := net.ParseIP("::ffff:10.2.0.9")
	if mapped.To4() == nil {
		t.Fatalf("前提:::ffff:10.2.0.9 应可 To4() 归一(得 nil 说明 net 行为变了)")
	}
	if got := r.route("t1", mapped); got != v4site {
		t.Fatalf("v4-mapped 地址应经 To4() 命中 v4 站点,得 %v", got)
	}
	// 与纯 v4 字面量等价(同一前缀、同一站点),坐实归一一致。
	if got := r.route("t1", net.ParseIP("10.2.0.9")); got != v4site {
		t.Fatalf("纯 v4 字面量应同样命中 v4 站点,得 %v", got)
	}
	// 真 v6 目的(非 v4-mapped)才走 v6 trie,命中 v6 站点(反证:归一只影响 v4-mapped)。
	if got := r.route("t1", net.ParseIP("2001:db8::1")); got != v6site {
		t.Fatalf("真 v6 目的应命中 v6 站点,得 %v", got)
	}
}

// 错族键越界防御:16 字节 v6 键误进 32 位 v4 trie(或反之)→ 入口断言 panic,
// 把潜在的 ip[i/8] 静默错配/越界转为可观测失败(本不变量由 route() 的 To4()/To16() 派发保证不发生,
// 此测试钉住「真传错族键时响亮失败」这条防御契约)。
// 错族/越界键:防御性**跳过**(insert no-op / longestPrefix 返 nil)而**非 panic**——数据面/控制面绝不
// 因键异常 crash PoP 进程。正常派发(rebuildRoutesLocked 按掩码位宽)不触发此守,此处直测守本身的安全降级。
func TestLPMWrongFamilyKeySkips(t *testing.T) {
	// longestPrefix 错族键 → nil(无命中,不 panic)
	if got := newLPMTrie(32).longestPrefix(net.ParseIP("2001:db8::1").To16()); got != nil {
		t.Fatalf("v6 键进 v4 树应返 nil,得 %v", got)
	}
	if got := newLPMTrie(128).longestPrefix(net.ParseIP("10.0.0.1").To4()); got != nil {
		t.Fatalf("v4 键进 v6 树应返 nil,得 %v", got)
	}
	// insert 错族/越界键 → no-op(不 panic、不污染 trie):后续合法插入仍正确命中
	tr := newLPMTrie(32)
	tr.insert(net.ParseIP("2001:db8::1").To16(), 32, &siteEntry{site: "bad-family"}) // 错族:跳过
	tr.insert(net.ParseIP("10.0.0.0").To4(), 33, &siteEntry{site: "bad-ones"})       // ones>32:跳过
	good := &siteEntry{site: "good"}
	tr.insert(net.ParseIP("10.0.0.0").To4(), 8, good) // 合法
	if got := tr.longestPrefix(net.ParseIP("10.0.0.5").To4()); got != good {
		t.Fatalf("合法插入后应命中 good,得 %v(错族/越界插入应被跳过未污染 trie)", got)
	}
}

// 回归(reviewer H1):租户可控的合法 v4-mapped CIDR(前缀 /96-128,如 ::ffff:10.0.0.0/104)经
// Register→rebuildRoutesLocked **不再 panic crash PoP**——此前按 IP.To4()(4 字节)派发进 v4 trie 但
// ones=104(16 字节掩码)越界 → panic(无 recover → 整 PoP 崩)。改按掩码位宽判族:104 对应 128 位掩码 → 进 v6 trie。
// 同租户正常 v4 CIDR 仍正确选路(v4-mapped 入 v6 trie、对 v4 目的惰性不命中,但不崩、不误路由)。
func TestRouterV4MappedCIDRNoPanic(t *testing.T) {
	router := NewRouter()
	_, mapped, err := net.ParseCIDR("::ffff:10.0.0.0/104") // 合法,net.ParseCIDR 接受
	if err != nil {
		t.Fatalf("解析 v4-mapped CIDR: %v", err)
	}
	addr1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51001}
	addr2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51002}
	// 不 panic 即过(此前这一步 crash 整个进程);route 不解引用 sess,nil 安全
	router.Register("t1", "siteMapped", nil, addr1, []*net.IPNet{mapped})
	router.Register("t1", "siteV4", nil, addr2, []*net.IPNet{cidr(t, "10.1.0.0/24")})
	if got := router.route("t1", net.ParseIP("10.1.0.5")); got == nil || got.site != "siteV4" {
		t.Fatalf("正常 v4 CIDR 应正确选路到 siteV4,得 %+v", got)
	}
}

// 并发 route() 查询 + 并发 Register/Deregister 的 -race 测试:坐实「longestPrefix 纯只读 + rebuild 原子替换」——
// 读者在 RLock 下查旧/新 trie,写者在 Lock 下重建后整棵替换 routes[tenant],二者无 data race。
// 断言:无 race(-race 检测器主证)+ 全程不 panic + 已稳定注册的前缀(siteA)始终稳定命中(读到旧或新 trie 均含 A)。
// **不**断言时序/计数(机器相关 flaky):只断不变量(稳定前缀稳定命中 + 无 race)。
func TestRouterConcurrentRouteAndChurn(t *testing.T) {
	r := NewRouter()
	// 稳定站点 A:不参与 churn,任何时刻读到的 trie 都应含其前缀 → route 恒命中。
	siteA := &siteEntry{tenant: "t1", site: "siteA", cidrs: []*net.IPNet{cidr(t, "10.1.0.0/24")}}
	r.byTenant["t1"] = []*siteEntry{siteA}
	r.mu.Lock()
	r.rebuildRoutesLocked("t1")
	r.mu.Unlock()

	dstA := net.ParseIP("10.1.0.9")
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 多读者:并发 route() 查询稳定前缀 A,断言恒命中(读旧或新 trie 都含 A,因 churn 只增删 siteB/C)。
	var hitMismatch atomic.Bool
	const readers = 8
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if got := r.route("t1", dstA); got != siteA {
					hitMismatch.Store(true) // 稳定前缀不应丢命中
				}
				// 顺带查 churn 中前缀(命中/不命中都合法,只确保不 race/不 panic)
				_ = r.route("t1", net.ParseIP("10.9.0.9"))
			}
		}()
	}

	// 多写者:并发反复 Register/Deregister 第二/三站点(触发 rebuildRoutesLocked 原子替换 routes["t1"])。
	const writers = 3
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			site := fmt.Sprintf("churn%d", w)
			_, dn, _ := net.ParseCIDR(fmt.Sprintf("10.%d.0.0/24", 9+w))
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Register 不需真 sess(route() 只读 cidrs/routes,不解封);addr 唯一避免 bySrc 串扰。
				addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000 + w}
				r.Register("t1", site, nil, addr, []*net.IPNet{dn})
				r.Deregister("t1", site)
			}
		}(w)
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if hitMismatch.Load() {
		t.Fatal("稳定前缀 siteA 在 churn 期间出现丢命中(rebuild 原子替换不成立或读到中间态)")
	}
	// churn 收敛:所有 churn 站点已 Deregister,t1 应仅余 siteA。
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n := len(r.byTenant["t1"]); n != 1 {
		t.Fatalf("churn 收敛后 t1 应仅余 siteA,得 %d 个站点", n)
	}
	if got := r.route("t1", dstA); got != siteA {
		t.Fatalf("收敛后稳定前缀仍应命中 siteA,得 %v", got)
	}
}
