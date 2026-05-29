package fw

import (
	"net"
	"testing"
)

func tcp(src, dst string, port uint16) Packet {
	return Packet{SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Proto: ipTCP, DstPort: port}
}

func TestEvaluate(t *testing.T) {
	eng := NewRuleEngine()

	// 默认拒绝:无规则
	if d := eng.Evaluate(nil, tcp("10.1.0.5", "10.2.0.9", 80)); d.Allow {
		t.Fatal("无规则应默认拒绝")
	}

	// allow 命中
	allow80 := []Rule{{Priority: 10, Action: ActionAllow, Protocol: ProtoTCP, DstCIDR: "10.2.0.0/24", DstPortMin: 80, DstPortMax: 80}}
	if d := eng.Evaluate(allow80, tcp("10.1.0.5", "10.2.0.9", 80)); !d.Allow {
		t.Fatalf("应放行 tcp:80,得 %+v", d)
	}
	// 端口不符 → 默认拒绝
	if d := eng.Evaluate(allow80, tcp("10.1.0.5", "10.2.0.9", 22)); d.Allow {
		t.Fatal("tcp:22 不在允许端口,应拒")
	}
	// 协议不符(udp)→ 默认拒绝
	if d := eng.Evaluate(allow80, Packet{SrcIP: net.ParseIP("10.1.0.5"), DstIP: net.ParseIP("10.2.0.9"), Proto: ipUDP, DstPort: 80}); d.Allow {
		t.Fatal("udp:80 协议不符,应拒")
	}
	// 目的 CIDR 不符 → 默认拒绝
	if d := eng.Evaluate(allow80, tcp("10.1.0.5", "10.3.0.9", 80)); d.Allow {
		t.Fatal("目的不在 10.2/24,应拒")
	}

	// 优先级首次匹配:低优先级 deny 先于高优先级 allow
	rules := []Rule{
		{Priority: 1, Action: ActionDeny, Protocol: ProtoTCP, DstCIDR: "10.2.0.9/32", DstPortMin: 22, DstPortMax: 22},
		{Priority: 5, Action: ActionAllow, Protocol: ProtoTCP, DstCIDR: "10.2.0.0/24"},
	}
	if d := eng.Evaluate(rules, tcp("10.1.0.5", "10.2.0.9", 22)); d.Allow {
		t.Fatal("优先级 1 的 deny 应先命中,拒绝 tcp:22")
	}
	if d := eng.Evaluate(rules, tcp("10.1.0.5", "10.2.0.9", 80)); !d.Allow {
		t.Fatal("tcp:80 应被优先级 5 的 allow 放行")
	}

	// src CIDR 匹配
	srcRule := []Rule{{Priority: 1, Action: ActionAllow, SrcCIDR: "10.1.0.0/24", DstCIDR: "10.2.0.0/24"}}
	if d := eng.Evaluate(srcRule, tcp("10.9.0.5", "10.2.0.9", 80)); d.Allow {
		t.Fatal("源不在 10.1/24,应拒")
	}
	// 非法 CIDR 规则 fail-closed(不放行)
	bad := []Rule{{Priority: 1, Action: ActionAllow, DstCIDR: "not-a-cidr"}}
	if d := eng.Evaluate(bad, tcp("10.1.0.5", "10.2.0.9", 80)); d.Allow {
		t.Fatal("非法 CIDR 规则不应匹配放行(fail-closed)")
	}
}
