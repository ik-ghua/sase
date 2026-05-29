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
//
// 防御(**跳过而非 panic**):key 位宽须 == 本 trie 族位宽(v4 键 4 字节进 32 位 trie、v6 键 16 字节进
// 128 位 trie),且 ones∈[0, bits]。键长/ones 不符说明上游派发未归一——**防御性跳过该前缀(不插入)**而非
// panic:本路径在控制面(Register,经 tunhandshake accept goroutine 无 recover),panic 会 crash 整个 PoP
// 进程(全租户受影响),把一条可疑 CIDR 升级成可用性事故得不偿失。rebuildRoutesLocked 现按 Mask.Size() 的
// bits 判族,合法 net.ParseCIDR 输出(含 v4-mapped /96-128)恒满足前置;此守仅为纵深防御,正常路径不触发。
func (t *lpmTrie) insert(ip net.IP, ones int, value *siteEntry) {
	if len(ip)*8 != t.bits || ones < 0 || ones > t.bits {
		return // 错族/越界键:跳过(不崩进程);正常派发不会到这
	}
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
//
// 防御(**返回 nil 而非 panic**):key 位宽须 == 本 trie 族位宽(同 insert)。route() 按目的族 To4()/To16()
// 分流,正确调用恒满足;错族键返回 nil(无命中)而非 panic——本路径是每包数据面热路径,绝不因键异常 crash。
func (t *lpmTrie) longestPrefix(ip net.IP) *siteEntry {
	if len(ip)*8 != t.bits {
		return nil // 错族键:视为无命中(不崩进程)
	}
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
// 前置 i < len(ip)*8 由唯一两个调用方(insert/longestPrefix)的入口守保证:二者均校验键位宽 == 族位宽
// (不符则跳过/返回 nil,不进循环),且循环 i 上界(insert 的 ones / longestPrefix 的 bits)≤ 族位宽,
// 故进到 bitAt 时 i 永不越界。
func bitAt(ip net.IP, i int) int {
	return int(ip[i/8]>>(7-uint(i%8))) & 1
}
