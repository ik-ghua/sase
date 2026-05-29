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
//   - Evaluate:对原始规则裁决(每次内部 Compile,便于测试/低频路径)。
//   - EvaluateCompiled:对**预编译**规则集裁决(热路径:CIDR 已解析为 *net.IPNet,免每包重解析)。
type Engine interface {
	Evaluate(rules []Rule, p Packet) Decision
	EvaluateCompiled(cs CompiledRuleSet, p Packet) Decision
}

// NewRuleEngine 返回规则引擎:按 priority 升序首次匹配取其 action;无匹配 → 默认拒绝(fail-closed)。
// 注:rules 须已按 priority 升序(下发侧 ORDER BY priority 保证);引擎不再排序(避免每包分配)。
func NewRuleEngine() Engine { return ruleEngine{} }

type ruleEngine struct{}

// compiledRule 是预编译的规则:CIDR 已解析为 *net.IPNet(nil + !any = 非法 CIDR → neverMatch)。
// 消除每包 net.ParseCIDR(骨架性能限收口);匹配语义与原 matches 完全一致。
type compiledRule struct {
	priority   int
	action     string
	protocol   string
	srcNet     *net.IPNet // nil 且 srcAny=false → 非法 CIDR,永不匹配(fail-closed)
	dstNet     *net.IPNet
	srcAny     bool // 空 CIDR = any
	dstAny     bool
	neverMatch bool // 任一 CIDR 非空但解析失败 → 该规则永不匹配(保留原 cidrMatch fail-closed)
	dstPortMin uint16
	dstPortMax uint16
}

// CompiledRuleSet 是预编译规则集(下发侧 Set 时编译一次,热路径零解析)。
type CompiledRuleSet struct {
	rules []compiledRule
}

// Len 返回规则条数(测试/自检用;零值 CompiledRuleSet 为 0)。
func (cs CompiledRuleSet) Len() int { return len(cs.rules) }

// Compile 把规则集预编译:CIDR 解析一次。rules 须已按 priority 升序(下发侧保证);保序不重排。
func Compile(rules []Rule) CompiledRuleSet {
	out := make([]compiledRule, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		cr := compiledRule{
			priority:   r.Priority,
			action:     r.Action,
			protocol:   r.Protocol,
			dstPortMin: r.DstPortMin,
			dstPortMax: r.DstPortMax,
		}
		cr.srcAny, cr.srcNet, cr.neverMatch = compileCIDR(r.SrcCIDR)
		if !cr.neverMatch {
			var dstNever bool
			cr.dstAny, cr.dstNet, dstNever = compileCIDR(r.DstCIDR)
			cr.neverMatch = dstNever
		}
		out = append(out, cr)
	}
	return CompiledRuleSet{rules: out}
}

// compileCIDR:空=any(isAny=true);合法→(false,*IPNet,false);非法→never=true(保留 fail-closed)。
func compileCIDR(cidr string) (isAny bool, ipnet *net.IPNet, never bool) {
	if cidr == "" {
		return true, nil, false
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, nil, true
	}
	return false, n, false
}

func (ruleEngine) Evaluate(rules []Rule, p Packet) Decision {
	return ruleEngine{}.EvaluateCompiled(Compile(rules), p)
}

func (ruleEngine) EvaluateCompiled(cs CompiledRuleSet, p Packet) Decision {
	for i := range cs.rules {
		cr := &cs.rules[i]
		if matchesCompiled(cr, p) {
			if cr.action == ActionAllow {
				return Decision{Allow: true, Reason: "allow rule pri=" + strconv.Itoa(cr.priority)}
			}
			return Decision{Allow: false, Reason: "deny rule pri=" + strconv.Itoa(cr.priority)}
		}
	}
	return Decision{Allow: false, Reason: "default-deny"} // 默认拒绝
}

func matchesCompiled(cr *compiledRule, p Packet) bool {
	if cr.neverMatch {
		return false
	}
	if !protoMatch(cr.protocol, p.Proto) {
		return false
	}
	if !cr.srcAny && (cr.srcNet == nil || !cr.srcNet.Contains(p.SrcIP)) {
		return false
	}
	if !cr.dstAny && (cr.dstNet == nil || !cr.dstNet.Contains(p.DstIP)) {
		return false
	}
	// 端口范围仅对 tcp/udp 有意义;0,0 = any
	if cr.dstPortMin != 0 || cr.dstPortMax != 0 {
		if p.Proto != ipTCP && p.Proto != ipUDP {
			return false
		}
		if p.DstPort < cr.dstPortMin || p.DstPort > cr.dstPortMax {
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
