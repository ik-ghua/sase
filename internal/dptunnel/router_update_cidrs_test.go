package dptunnel

import (
	"net"
	"testing"
)

// TestRouterUpdateCIDRsKeepsSession 锁住 Slice75 H1 修复:站点 CIDR 经 xDS 晚于握手到达时,
// 必须只更新路由、**保留原会话实例**(AEAD 密钥与发送计数器连续);绝不重建会话——
// 重建会复用旧密钥但把计数器归零 → nonce 复用(同密钥+同 nonce 加密不同明文),是机密性/认证灾难。
//
// 断言:① UpdateCIDRs 后 siteEntry.sess 仍是**同一指针**(未重建);② 新 CIDR 生效、旧 CIDR 失效;
// ③ 对未登记站点 no-op 返 false。
func TestRouterUpdateCIDRsKeepsSession(t *testing.T) {
	r := NewRouter()
	sess := NewSession(mustAEAD(t, key32(0xB2)), 1, 1, 0)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47001}

	// 握手时以(当时已知的)CIDR 登记。
	r.Register("t1", "siteB", sess, addr, []*net.IPNet{cidr(t, "10.2.0.0/24")})

	// 记下登记后的会话指针(应在 UpdateCIDRs 后保持不变)。
	r.mu.RLock()
	var before *Session
	for _, e := range r.byTenant["t1"] {
		if e.site == "siteB" {
			before = e.sess
		}
	}
	r.mu.RUnlock()
	if before != sess {
		t.Fatalf("登记后 sess 应为传入实例")
	}

	// 模拟 xDS 晚到的 CIDR 更新:换成新网段。
	if ok := r.UpdateCIDRs("t1", "siteB", []*net.IPNet{cidr(t, "10.9.0.0/24")}); !ok {
		t.Fatalf("UpdateCIDRs 对已登记站点应返回 true")
	}

	// ① 会话实例必须未变(同指针)——这是 H1 的核心不变量:不重建会话、计数器连续。
	r.mu.RLock()
	var after *Session
	var gotCIDR string
	for _, e := range r.byTenant["t1"] {
		if e.site == "siteB" {
			after = e.sess
			if len(e.cidrs) == 1 {
				gotCIDR = e.cidrs[0].String()
			}
		}
	}
	tr := r.routes["t1"]
	r.mu.RUnlock()
	if after != before {
		t.Fatalf("UpdateCIDRs 不得重建会话:sess 指针变了(before=%p after=%p)= nonce 复用风险", before, after)
	}
	if gotCIDR != "10.9.0.0/24" {
		t.Fatalf("UpdateCIDRs 应更新 cidrs 为新网段,得 %q", gotCIDR)
	}

	// ② 新 CIDR 选路命中、旧 CIDR 不再命中。
	if tr == nil || tr.v4 == nil {
		t.Fatal("更新后应有该租户 v4 路由 trie")
	}
	if e := tr.v4.longestPrefix(net.IPv4(10, 9, 0, 5).To4()); e == nil || e.site != "siteB" {
		t.Fatalf("新网段 10.9.0.5 应选路到 siteB,得 %v", e)
	}
	if e := tr.v4.longestPrefix(net.IPv4(10, 2, 0, 5).To4()); e != nil {
		t.Fatalf("旧网段 10.2.0.5 不应再命中,得 %v", e)
	}

	// ③ 未登记站点 → no-op 返 false。
	if ok := r.UpdateCIDRs("t1", "nope", []*net.IPNet{cidr(t, "10.3.0.0/24")}); ok {
		t.Fatalf("UpdateCIDRs 对未登记站点应返回 false")
	}
	if ok := r.UpdateCIDRs("nosuchtenant", "siteB", nil); ok {
		t.Fatalf("UpdateCIDRs 对未登记租户应返回 false")
	}
}
