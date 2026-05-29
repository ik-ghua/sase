package dptunnel

import (
	"context"
	"log"
	"net"
	"runtime"
	"sync"
)

// PoP 侧 SD-WAN 隧道路由:每租户独立路由域,按内层 IP 目的地址在**本租户**站点间转发(站点不直连,PoP 中继)。
// 跨租户严格隔离:源站点租户的路由表外的目的 → 丢弃(对齐 L1 3.2 隔离 / PoC-1 路由域;真实部署叠加 netns)。
//
// 租户隔离的**权威锚点是每会话独立 AEAD 密钥**,非 UDP 源地址:srcAddr→site 仅作入向解复用提速;
// 即便源地址被伪造成某站点,伪造者无该会话密钥 → `sess.Open` 失败丢弃,不产生跨租户明文转发。
// 入向解复用(srcAddr→site)dev/非 NAT 可行;NAT 下须用握手协商的 receiver-index(待握手/审查)。
//
// 收发已由单 goroutine 升级为 worker pool(见 Serve):N 个 worker 各自从同一 net.PacketConn 并发
// ReadFrom(Go UDPConn.ReadFrom 并发安全,每次一个完整数据报)→ Handle → WriteTo,吃满多核;
// SO_REUSEPORT(多 socket 分摊内核队列)为后续生产项。
// 选路已由线性全表扫描升级为每租户 v4/v6 LPM trie(见 lpm.go),热路径 O(地址位宽)、与站点/CIDR 数无关。

// siteEntry 是 PoP 上一个已接入站点的隧道状态。
type siteEntry struct {
	tenant string
	site   string
	sess   *Session     // PoP ↔ 该站点的隧道会话(密钥由握手注入,本骨架测试期预置)
	addr   net.Addr     // 该站点 CPE 的 UDP 回程地址
	cidrs  []*net.IPNet // 该站点的子网(选路用)
}

// Packet5Tuple 是内层包 5 元组(供 FWaaS L3/L4 裁决)。
type Packet5Tuple struct {
	SrcIP   net.IP
	DstIP   net.IP
	Proto   uint8 // IP 协议号
	SrcPort uint16
	DstPort uint16
}

// Firewall 是 L3/L4 防火墙裁决钩子(FWaaS,安全栈 L2):站点间转发前按租户规则裁决,deny → 丢弃。
// 实现在 fw/pop 层(本包不依赖 fw 策略,只调钩子);返回 false = 拒绝转发。
type Firewall interface {
	Allow(tenant string, p Packet5Tuple) bool
}

// tenantRoutes 持单租户的两族 LPM trie(v4/v6 分开,杜绝跨族 ones 误比)。
// 由 byTenant[tenant] 的站点 CIDR 派生,在 Register/removeLocked(均持写锁)时重建,保持与 byTenant 一致。
type tenantRoutes struct {
	v4 *lpmTrie
	v6 *lpmTrie
}

// Router 持各接入站点,做入向解复用 + 按内层目的 IP 的租户内选路 + 可选 FWaaS L3/L4 裁决。
type Router struct {
	mu       sync.RWMutex
	bySrc    map[string]*siteEntry    // udp src addr → 站点(入向解复用)
	byTenant map[string][]*siteEntry  // 租户 → 站点(站点集合的权威来源;登记/注销在此增删)
	routes   map[string]*tenantRoutes // 租户 → LPM trie(选路热路径,由 byTenant 派生重建)
	fw       Firewall                 // 可选 FWaaS 钩子(SetFirewall 设;须在 Serve 前设,之后只读)
	onDrop   func(reason string)      // 可选丢包计数钩子(SetDropHook 设;数据面可观测,Slice67)
}

// NewRouter 构造路由器。
func NewRouter() *Router {
	return &Router{
		bySrc:    map[string]*siteEntry{},
		byTenant: map[string][]*siteEntry{},
		routes:   map[string]*tenantRoutes{},
	}
}

// SetFirewall 挂 FWaaS L3/L4 裁决钩子(每租户网络分段)。同锁写,与 Handle 读取无竞争。
func (r *Router) SetFirewall(fw Firewall) {
	r.mu.Lock()
	r.fw = fw
	r.mu.Unlock()
}

// SetDropHook 挂丢包计数钩子(按原因计量,供 /metrics 暴露数据面隧道丢弃可观测,Slice67)。
// 须在 Serve 前设、之后只读(同 fw);nil = 不计量。
func (r *Router) SetDropHook(fn func(reason string)) {
	r.mu.Lock()
	r.onDrop = fn
	r.mu.Unlock()
}

// Register 登记/替换一个接入站点(隧道建立或重连后调用;骨架测试期由调用方预置 sess/key)。
// 同 (tenant, site) 重复登记 → 先移除旧条目(防 byTenant 残留旧会话致黑洞/选路漂移,评审 S2)。
func (r *Router) Register(tenant, site string, sess *Session, addr net.Addr, cidrs []*net.IPNet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(tenant, site)
	e := &siteEntry{tenant: tenant, site: site, sess: sess, addr: addr, cidrs: cidrs}
	r.bySrc[addr.String()] = e
	r.byTenant[tenant] = append(r.byTenant[tenant], e)
	r.rebuildRoutesLocked(tenant)
}

// Deregister 注销一个站点(隧道断开/撤销时调用)。
func (r *Router) Deregister(tenant, site string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(tenant, site)
}

// removeLocked 移除 (tenant, site) 的现有条目并重建该租户 trie(调用方持写锁)。
func (r *Router) removeLocked(tenant, site string) {
	sites := r.byTenant[tenant]
	for i, e := range sites {
		if e.site == site {
			delete(r.bySrc, e.addr.String())
			r.byTenant[tenant] = append(sites[:i], sites[i+1:]...)
			r.rebuildRoutesLocked(tenant)
			return
		}
	}
}

// rebuildRoutesLocked 由 byTenant[tenant] 的站点 CIDR 重建该租户的 v4/v6 LPM trie(调用方持写锁)。
// 重建(O(站点×CIDR))只在登记/注销的控制面路径发生(低频),换取选路热路径 O(地址位宽);
// 全量重建保证 trie 与 byTenant 一致(终态只由当前站点集合决定,与增删顺序无关,等价原线性扫描)。
// 站点为空 → 删除该租户的 routes 项(route 取不到即返回 nil,语义同无站点)。
func (r *Router) rebuildRoutesLocked(tenant string) {
	sites := r.byTenant[tenant]
	if len(sites) == 0 {
		delete(r.routes, tenant)
		return
	}
	tr := &tenantRoutes{v4: newLPMTrie(32), v6: newLPMTrie(128)}
	for _, e := range sites {
		for _, c := range e.cidrs {
			ones, _ := c.Mask.Size()
			if ip4 := c.IP.To4(); ip4 != nil {
				tr.v4.insert(ip4, ones, e) // v4 用 4 字节规范地址 + 0..32 位
			} else {
				tr.v6.insert(c.IP.To16(), ones, e) // v6 用 16 字节规范地址 + 0..128 位
			}
		}
	}
	r.routes[tenant] = tr
}

// Outbound 是一条待 PoP 发出的数据报(转发给目的站点)。
type Outbound struct {
	Addr net.Addr
	Data []byte
}

// Handle 处理一个从 src 收到的数据报:解复用→解封→按内层目的 IP 在源租户内选路→以目的站点会话重封。
// 返回待发数据报(可能多个:FEC 恢复出多包 / 目的会话产 parity)。未知源/跨租户/无路由 → 丢弃(空返回)。
func (r *Router) Handle(datagram []byte, src net.Addr) []Outbound {
	r.mu.RLock()
	from := r.bySrc[src.String()]
	fw := r.fw         // 同锁读取,与 SetFirewall 无竞争
	onDrop := r.onDrop // 同上(Slice67 丢包计数;设于 Serve 前)
	r.mu.RUnlock()
	drop := func(reason string) {
		if onDrop != nil {
			onDrop(reason)
		}
	}
	if from == nil {
		drop("no_session") // 未注册源(NAT 下需 receiver-index,待握手)
		return nil
	}
	inners, err := from.sess.Open(datagram)
	if err != nil {
		drop("decrypt_fail") // AEAD 解封失败(伪造源无密钥 / 损坏帧)
		return nil
	}
	var out []Outbound
	for _, pkt := range inners {
		tuple, ok := parse5Tuple(pkt)
		if !ok {
			drop("parse_fail")
			continue
		}
		// FWaaS L3/L4 裁决(每租户分段):deny → 丢弃,不转发
		if fw != nil && !fw.Allow(from.tenant, tuple) {
			drop("firewall_deny")
			continue
		}
		to := r.route(from.tenant, tuple.DstIP) // 仅在源租户内选路(跨租户隔离)
		if to == nil || to == from {
			drop("no_route") // 无路由 / 自指 → 丢弃
			continue
		}
		frames, err := to.sess.Seal(pkt)
		if err != nil {
			drop("seal_fail")
			continue
		}
		for _, f := range frames {
			out = append(out, Outbound{Addr: to.addr, Data: f})
		}
	}
	return out
}

// route 在 tenant 路由域内按最长前缀匹配选目的站点(经 LPM trie,O(地址位宽))。
// 按目的地址族在对应族的 trie 内查询:v4 目的只查 v4 trie、v6 目的只查 v6 trie → 同族比较、不跨族误配。
func (r *Router) route(tenant string, dst net.IP) *siteEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tr := r.routes[tenant]
	if tr == nil {
		return nil // 该租户无站点 → 无路由
	}
	if ip4 := dst.To4(); ip4 != nil {
		return tr.v4.longestPrefix(ip4)
	}
	return tr.v6.longestPrefix(dst.To16())
}

// parse5Tuple 从 L3 包提取 5 元组(IPv4/IPv6;dst/src IP 偏移与 IHL/分片无关,可靠)。
// **L4 端口/proto 解析的已知骨架限**(生产下沉 eBPF + 重组时收口):
//   - IPv4 IP 选项(IHL>5)下端口偏移按 IHL 计算,但若分片首片不含完整 L4 头 → 端口落 0(可能误判端口规则);
//   - IPv6 扩展头未解析,直接取 NextHeader 作 proto → 带扩展头的 TCP/UDP 会 proto 失配(偏保守不放行,不泄漏)。
//
// 故带 IP 选项/IPv6 扩展头/分片的环境暂勿依赖 L4 端口精确匹配(L3 网段匹配不受影响)。
func parse5Tuple(pkt []byte) (Packet5Tuple, bool) {
	if len(pkt) < 1 {
		return Packet5Tuple{}, false
	}
	var t Packet5Tuple
	var l4off int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return Packet5Tuple{}, false
		}
		t.Proto = pkt[9]
		t.SrcIP, t.DstIP = net.IP(pkt[12:16]), net.IP(pkt[16:20])
		l4off = int(pkt[0]&0x0f) * 4 // IHL
	case 6:
		if len(pkt) < 40 {
			return Packet5Tuple{}, false
		}
		t.Proto = pkt[6] // NextHeader(扩展头未解析)
		t.SrcIP, t.DstIP = net.IP(pkt[8:24]), net.IP(pkt[24:40])
		l4off = 40
	default:
		return Packet5Tuple{}, false
	}
	if (t.Proto == 6 || t.Proto == 17) && len(pkt) >= l4off+4 {
		t.SrcPort = uint16(pkt[l4off])<<8 | uint16(pkt[l4off+1])
		t.DstPort = uint16(pkt[l4off+2])<<8 | uint16(pkt[l4off+3])
	}
	return t, true
}

// Serve 在 conn 上以 worker pool 收 UDP 数据报、经 Router 并发转发,直到 ctx 取消后所有 worker 干净退出。
//
// 并发安全论证:① net.UDPConn/PacketConn 的 ReadFrom 多 goroutine 并发安全,每次返回一个完整数据报
// (UDP 面向消息,运行时内部串行化读、不会撕裂);② 每 worker 持**独立 buf**,互不共享(否则并发 ReadFrom
// 写同一缓冲 = data race);Handle 入参又经 append 拷贝为独立切片;③ Handle 经 RWMutex + 每会话 Session.mu
// 保护,与 Register/Deregister 并发安全;④ WriteTo 多 goroutine 并发安全(UDP sendto 单数据报原子)。
// 全程无 worker 间共享可变状态。
//
// worker 数默认 runtime.NumCPU()(至少 1):单核机退化为 1 worker,等价原单 goroutine 行为。
func (r *Router) Serve(ctx context.Context, conn net.PacketConn) {
	// ctx 取消 → 关闭 conn,令所有阻塞在 ReadFrom 的 worker 一并出错返回(复用原单 goroutine 模式)。
	go func() { <-ctx.Done(); _ = conn.Close() }()

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, maxDatagram) // 每 worker 独立 buf,杜绝并发 ReadFrom 写同缓冲的 data race
			for {
				n, src, err := conn.ReadFrom(buf)
				if err != nil {
					if ctx.Err() != nil {
						return // ctx 取消触发的 conn.Close → 正常退出
					}
					// conn 已关闭(ctx 取消)对所有 worker 报错;非取消的真实读错才记日志。
					log.Printf("[dptunnel] PoP 读 UDP: %v", err)
					return
				}
				for _, o := range r.Handle(append([]byte(nil), buf[:n]...), src) {
					if _, err := conn.WriteTo(o.Data, o.Addr); err != nil {
						log.Printf("[dptunnel] PoP 转发: %v", err)
					}
				}
			}
		}()
	}
	wg.Wait()
}
