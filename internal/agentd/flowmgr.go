package agentd

import (
	"net"
	"sort"
	"strings"
	"sync"
)

// FlowManager 管理 split-tunnel 分流(L2 §3.3 子块3):维护「内部应用 CIDR 集」,决定哪些目的网段
// 路由进 TUN(经 NetCapture.ConfigureRoutes 让内核只把这些网段的包送 TUN),其余旁路本地协议栈。
//
// 默认最小接管(关键原则,L2 §3.3):白名单模式——仅命中接管 CIDR 的流量进隧道;空 CIDR 集 = 不接管
// 任何流量(全旁路),而非全量抢 default route(降低与本地网络/其它 VPN 冲突)。
//
// split-DNS 基础(L2 §3.3):维护租户内部域名后缀集,InternalDomain 判定某域名是否应劫持解析。
// 本刀仅做后缀匹配判定;真正的 DNS 代理/overlay 映射经壳 ConfigureDNS,深化为后续刀。
//
// 数据结构:CIDR 判定用 net.IPNet 线性匹配(Agent 侧内部 CIDR 数通常很小,几十条量级)。
// L2 §3.3 提到可复用 dptunnel 的 LPM radix trie,但该 trie 当前 unexported 且为每包热路径优化;
// Agent 的 split-tunnel 判定主要在「配路由时」批量做(交内核按最长前缀路由),热路径不在用户态逐包判,
// 故本刀用简单线性匹配 + 最长前缀择优,避免跨包导出内部类型(诚实标注:CIDR 多时可换 LPM)。
type FlowManager struct {
	mu        sync.RWMutex
	cidrs     []*net.IPNet // 接管 CIDR(白名单);已规范化去重
	dnsSuffix []string     // 租户内部域名后缀(小写、去前导点)
}

// NewFlowManager 构造分流管理器(空集 = 不接管任何流量)。
func NewFlowManager() *FlowManager { return &FlowManager{} }

// SetRoutes 设置接管 CIDR 集(入网/实时通道 config_update 下发,L2 §3.3/§3.6 全量替换)。
// 非法/重复 CIDR 被忽略(防一条坏配置影响全局);返回规范化后的实际接管集(供壳配路由)。
func (m *FlowManager) SetRoutes(cidrs []*net.IPNet) []*net.IPNet {
	seen := map[string]bool{}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if c == nil || c.IP == nil || c.Mask == nil {
			continue
		}
		key := c.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	m.mu.Lock()
	m.cidrs = out
	m.mu.Unlock()
	return out
}

// SetRoutesFromStrings 解析 CIDR 字符串并设置;返回成功解析的网段与被拒的非法项(供 cmd/调用方日志)。
func (m *FlowManager) SetRoutesFromStrings(specs []string) (accepted []*net.IPNet, rejected []string) {
	parsed := make([]*net.IPNet, 0, len(specs))
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil || ipnet == nil {
			rejected = append(rejected, s)
			continue
		}
		parsed = append(parsed, ipnet)
	}
	return m.SetRoutes(parsed), rejected
}

// Routes 返回当前接管 CIDR 集的快照(供壳 ConfigureRoutes / 日志)。
func (m *FlowManager) Routes() []*net.IPNet {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]*net.IPNet(nil), m.cidrs...)
}

// ShouldTunnel 判定去往 dst 的包是否应进隧道(命中任一接管 CIDR → true=接管;否则 false=旁路本地栈)。
// 默认最小接管:空 CIDR 集恒返回 false。nil/无效 dst → false(fail-open 旁路,不接管未知目的,绝不崩)。
func (m *FlowManager) ShouldTunnel(dst net.IP) bool {
	if dst == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.cidrs {
		if c.Contains(dst) {
			return true
		}
	}
	return false
}

// SetInternalDomains 设置租户内部域名后缀集(split-DNS,L2 §3.3)。后缀规范化为小写、去前导点。
func (m *FlowManager) SetInternalDomains(suffixes []string) {
	out := make([]string, 0, len(suffixes))
	seen := map[string]bool{}
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, ".")
		s = strings.TrimSuffix(s, ".") // 去 FQDN 尾点,统一比较
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	// 排序使 DNSRules 下发与日志稳定确定。
	sort.Strings(out)
	m.mu.Lock()
	m.dnsSuffix = out
	m.mu.Unlock()
}

// InternalDomain 判定 name 是否属租户内部域名(命中后缀 → 应劫持解析走隧道;否则公网旁路,L2 §3.3)。
// 后缀精确匹配:name 须 == suffix 或以 "."+suffix 结尾(避免 evilcorp.com 误命中 corp.com)。
func (m *FlowManager) InternalDomain(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, suf := range m.dnsSuffix {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			return true
		}
	}
	return false
}

// DNSRules 构造交壳 ConfigureDNS 的 split-DNS 策略快照。
func (m *FlowManager) DNSRules() DNSRules {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return DNSRules{InternalSuffixes: append([]string(nil), m.dnsSuffix...)}
}
