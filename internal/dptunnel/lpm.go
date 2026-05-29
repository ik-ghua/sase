package dptunnel

import "net"

// 每租户最长前缀匹配(LPM):把 route 的 O(站点数×CIDR数) 线性全表扫描换成二进制 radix trie,
// 查询复杂度 O(地址位宽)(v4 最多 32 步、v6 最多 128 步),与租户站点/CIDR 数量无关——消除每包热路径的骨架性能限。
//
// 语义与原线性 route() 完全一致(见 router_test 覆盖):
//   - 最长前缀匹配:多 CIDR 命中取掩码最长(ones 最大)的站点;
//   - 同地址族内比较:v4 与 v6 各自独立一棵 trie(不跨族比 ones,杜绝 v4/v6 误配);
//   - 无命中 → nil;一个站点可挂多个 CIDR、多个站点可挂不同 CIDR。
//
// 并发:查询(longestPrefix)只读,在 Router 的 RLock 下安全并发;插入(insert)只在 Router 写锁下进行。

// lpmNode 是 radix trie 的一个节点。child[0]/child[1] 按 IP 当前比特(0/1)下行;
// hasValue 标记该节点恰好对应某个已插入前缀的终点,value 为其站点条目。
type lpmNode struct {
	child    [2]*lpmNode
	hasValue bool
	value    *siteEntry
}

// lpmTrie 是单地址族的 LPM 表:v4(32 位)或 v6(128 位)各持一棵。
type lpmTrie struct {
	root *lpmNode
	bits int // 该族地址位宽:v4=32,v6=128(用于一致性校验,不限制查询长度)
}

// newLPMTrie 构造一棵指定族位宽的 trie。
func newLPMTrie(bits int) *lpmTrie {
	return &lpmTrie{root: &lpmNode{}, bits: bits}
}

// insert 插入一个前缀(ip 的前 ones 位)→ value。
// ip 必须是与本 trie 同族的规范字节(v4=4 字节、v6=16 字节);ones 为掩码位数。
// 同一前缀重复插入 → 后插入覆盖(确定性:终态只由「当前已登记的站点集合」决定,与登记顺序无关,
// 因为 Router 每次重建/增删后该前缀至多对应一个站点条目)。
func (t *lpmTrie) insert(ip net.IP, ones int, value *siteEntry) {
	n := t.root
	for i := 0; i < ones; i++ {
		b := bitAt(ip, i)
		if n.child[b] == nil {
			n.child[b] = &lpmNode{}
		}
		n = n.child[b]
	}
	n.hasValue = true
	n.value = value
}

// longestPrefix 返回包含 ip 的最长前缀对应的站点条目;无命中 → nil。
// 沿 ip 比特逐位下行,记录沿途遇到的最深 hasValue 节点(即最长匹配前缀)。
func (t *lpmTrie) longestPrefix(ip net.IP) *siteEntry {
	n := t.root
	var best *siteEntry
	for i := 0; i <= t.bits; i++ {
		if n == nil {
			break
		}
		if n.hasValue {
			best = n.value // 沿途更深的命中覆盖更浅的 → 终值即最长前缀
		}
		if i == t.bits {
			break // 已到地址末位,n 的 value 已在上面纳入
		}
		n = n.child[bitAt(ip, i)]
	}
	return best
}

// bitAt 取规范 IP 字节序列第 i 位(0=最高位 / 网络序最左位),返回 0 或 1。
// 调用方保证 i < len(ip)*8。
func bitAt(ip net.IP, i int) int {
	return int(ip[i/8]>>(7-uint(i%8))) & 1
}
