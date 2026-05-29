package dptunnel

import (
	"net"
	"testing"
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
