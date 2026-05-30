package agentd

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

// TestShouldTunnelWhitelist 验证默认最小接管:命中接管 CIDR → 进隧道;未命中 → 旁路;空集 → 全旁路。
func TestShouldTunnelWhitelist(t *testing.T) {
	fm := NewFlowManager()

	// 空集:任何目的都旁路(不全量抢 default route,L2 §3.3)。
	if fm.ShouldTunnel(net.ParseIP("10.1.2.3")) {
		t.Fatalf("空 CIDR 集应全部旁路")
	}

	fm.SetRoutes([]*net.IPNet{mustCIDR(t, "10.1.0.0/16"), mustCIDR(t, "10.2.0.0/16")})
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},     // 命中 10.1/16 → 接管
		{"10.2.255.1", true},   // 命中 10.2/16 → 接管
		{"10.3.0.1", false},    // 未命中 → 旁路
		{"8.8.8.8", false},     // 公网 → 旁路
		{"192.168.1.1", false}, // 本地 LAN → 旁路
	}
	for _, c := range cases {
		if got := fm.ShouldTunnel(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("ShouldTunnel(%s)=%v,want %v", c.ip, got, c.want)
		}
	}
	// nil dst 不崩,旁路。
	if fm.ShouldTunnel(nil) {
		t.Errorf("nil dst 应旁路")
	}
}

// TestSetRoutesFromStrings 验证非法 CIDR 被拒、合法的被接管、重复去重。
func TestSetRoutesFromStrings(t *testing.T) {
	fm := NewFlowManager()
	accepted, rejected := fm.SetRoutesFromStrings([]string{
		"10.1.0.0/16", "  ", "not-a-cidr", "10.1.0.0/16", "fd00::/8", "999.0.0.0/8",
	})
	if len(accepted) != 2 { // 10.1.0.0/16(去重一份)+ fd00::/8
		t.Fatalf("接受应 2 条(去重 + v6),得 %d: %v", len(accepted), accepted)
	}
	if len(rejected) != 2 { // not-a-cidr + 999.0.0.0/8
		t.Fatalf("拒绝应 2 条,得 %d: %v", len(rejected), rejected)
	}
	if !fm.ShouldTunnel(net.ParseIP("fd00::1")) {
		t.Errorf("v6 CIDR 应接管")
	}
}

// TestInternalDomainSuffixMatch 验证 split-DNS 后缀精确匹配(不误命中公网相邻域名)。
func TestInternalDomainSuffixMatch(t *testing.T) {
	fm := NewFlowManager()
	fm.SetInternalDomains([]string{"Corp.Example.com", ".intra.example.", "intra.example"}) // 大小写/前导点/尾点/重复

	cases := []struct {
		name string
		want bool
	}{
		{"app.corp.example.com", true},  // 子域命中
		{"corp.example.com", true},      // 完全相等命中
		{"CORP.example.com", true},      // 大小写不敏感
		{"db.intra.example", true},      // 第二后缀命中
		{"evilcorp.example.com", false}, // 相邻域名不误命中(须 .corp.example.com 边界)
		{"example.com", false},          // 父域不命中
		{"google.com", false},           // 公网旁路
		{"", false},
	}
	for _, c := range cases {
		if got := fm.InternalDomain(c.name); got != c.want {
			t.Errorf("InternalDomain(%q)=%v,want %v", c.name, got, c.want)
		}
	}
	// DNSRules 快照应去重并稳定(intra.example 与 .intra.example. 归一为一条)。
	rules := fm.DNSRules()
	if len(rules.InternalSuffixes) != 2 {
		t.Fatalf("内部后缀去重后应 2 条,得 %v", rules.InternalSuffixes)
	}
}
