// Package fw 是安全能力 FWaaS(L3/L4 防火墙,P4)的规则模型 + 纯函数裁决引擎。
//
// 安全栈 L2:三项安全能力共享底座(authoring→编译/下发→PoP 执行同一管线),加能力不加基础设施。
// FWaaS 的执行点是 **PoP 数据面包路径**(dptunnel Router 站点间转发前裁决),实现每租户网络分段。
// 裁决纯函数、**默认拒绝 + 优先级首次匹配**(与策略编译器/PEP 同范式:fail-closed、无解释器、有界查表)。
// 起步用户态规则匹配;生产 L3/L4 数据面下沉 eBPF/XDP(规则模型不变,只换执行层),L7 防火墙复用 Envoy
// /SWG 的 L7 检查点——均后续刀(同 SWG 的 ML/采购后置)。
package fw

import (
	"net"
	"strconv"
)

// 动作 / 协议。
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"

	ProtoAny  = "any"
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoICMP = "icmp"
)

// IP 协议号。
const (
	ipTCP  = 6
	ipUDP  = 17
	ipICMP = 1
)

// Rule 是一条 L3/L4 防火墙规则(5 元组匹配)。空 CIDR / 0 端口范围 = any。
type Rule struct {
	ID         string `json:"id,omitempty"` // authoring/管理标识(PUT/DELETE 寻址用);数据面引擎不读
	Priority   int    `json:"priority"`
	Action     string `json:"action"`   // allow | deny
	Protocol   string `json:"protocol"` // any | tcp | udp | icmp
	SrcCIDR    string `json:"src_cidr"`
	DstCIDR    string `json:"dst_cidr"`
	DstPortMin uint16 `json:"dst_port_min"`
	DstPortMax uint16 `json:"dst_port_max"`
}

// Packet 是被裁决的包要素。注:起步规则只按 dst 端口匹配,**源端口不参与**(典型分段按目的端口),
// 故此处不带 SrcPort;rule 亦无源端口字段。
type Packet struct {
	SrcIP   net.IP
	DstIP   net.IP
	Proto   uint8 // IP 协议号(6/17/1)
	DstPort uint16
}

// Decision 是防火墙裁决。
type Decision struct {
	Allow  bool
	Reason string
}

// Engine 是裁决引擎(接口隔离:用户态规则匹配起步,后续可换 eBPF 下沉/采购规则源)。
type Engine interface {
	Evaluate(rules []Rule, p Packet) Decision
}

// NewRuleEngine 返回规则引擎:按 priority 升序首次匹配取其 action;无匹配 → 默认拒绝(fail-closed)。
// 注:rules 须已按 priority 升序(下发侧 ORDER BY priority 保证);引擎不再排序(避免每包分配)。
func NewRuleEngine() Engine { return ruleEngine{} }

type ruleEngine struct{}

func (ruleEngine) Evaluate(rules []Rule, p Packet) Decision {
	for i := range rules {
		r := &rules[i]
		if matches(r, p) {
			if r.Action == ActionAllow {
				return Decision{Allow: true, Reason: "allow rule pri=" + strconv.Itoa(r.Priority)}
			}
			return Decision{Allow: false, Reason: "deny rule pri=" + strconv.Itoa(r.Priority)}
		}
	}
	return Decision{Allow: false, Reason: "default-deny"} // 默认拒绝
}

func matches(r *Rule, p Packet) bool {
	if !protoMatch(r.Protocol, p.Proto) {
		return false
	}
	if !cidrMatch(r.SrcCIDR, p.SrcIP) || !cidrMatch(r.DstCIDR, p.DstIP) {
		return false
	}
	// 端口范围仅对 tcp/udp 有意义;0,0 = any
	if r.DstPortMin != 0 || r.DstPortMax != 0 {
		if p.Proto != ipTCP && p.Proto != ipUDP {
			return false
		}
		if p.DstPort < r.DstPortMin || p.DstPort > r.DstPortMax {
			return false
		}
	}
	return true
}

func protoMatch(ruleProto string, pkt uint8) bool {
	switch ruleProto {
	case "", ProtoAny:
		return true
	case ProtoTCP:
		return pkt == ipTCP
	case ProtoUDP:
		return pkt == ipUDP
	case ProtoICMP:
		return pkt == ipICMP
	default:
		return false // 未知协议名不匹配(fail-closed)
	}
}

// cidrMatch:空 CIDR=any;非法 CIDR 视为不匹配(fail-closed,不放行)。
// 骨架性能限:每包每规则 net.ParseCIDR 重解析字符串;生产应把 CIDR 预编译为 *net.IPNet 缓存进 Rule
// (与 dptunnel Router 线性 LPM 同属骨架,生产需预编译/radix)。
func cidrMatch(cidr string, ip net.IP) bool {
	if cidr == "" {
		return true
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}
