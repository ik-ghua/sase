package dptunnel

import (
	"context"
	"log"
	"net"
	"sync"
)

// PoP 侧 SD-WAN 隧道路由:每租户独立路由域,按内层 IP 目的地址在**本租户**站点间转发(站点不直连,PoP 中继)。
// 跨租户严格隔离:源站点租户的路由表外的目的 → 丢弃(对齐 L1 3.2 隔离 / PoC-1 路由域;真实部署叠加 netns)。
//
// 租户隔离的**权威锚点是每会话独立 AEAD 密钥**,非 UDP 源地址:srcAddr→site 仅作入向解复用提速;
// 即便源地址被伪造成某站点,伪造者无该会话密钥 → `sess.Open` 失败丢弃,不产生跨租户明文转发。
// 入向解复用(srcAddr→site)dev/非 NAT 可行;NAT 下须用握手协商的 receiver-index(待握手/审查)。
//
// 骨架性能限:单 Serve goroutine 串行收发、route 线性全表 LPM——生产需 worker pool/SO_REUSEPORT + radix LPM。

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

// Router 持各接入站点,做入向解复用 + 按内层目的 IP 的租户内选路 + 可选 FWaaS L3/L4 裁决。
type Router struct {
	mu       sync.RWMutex
	bySrc    map[string]*siteEntry   // udp src addr → 站点(入向解复用)
	byTenant map[string][]*siteEntry // 租户 → 站点(选路,租户内 LPM)
	fw       Firewall                // 可选 FWaaS 钩子(SetFirewall 设;须在 Serve 前设,之后只读)
	onDrop   func(reason string)     // 可选丢包计数钩子(SetDropHook 设;数据面可观测,Slice67)
}

// NewRouter 构造路由器。
func NewRouter() *Router {
	return &Router{bySrc: map[string]*siteEntry{}, byTenant: map[string][]*siteEntry{}}
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
}

// Deregister 注销一个站点(隧道断开/撤销时调用)。
func (r *Router) Deregister(tenant, site string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(tenant, site)
}

// removeLocked 移除 (tenant, site) 的现有条目(调用方持写锁)。
func (r *Router) removeLocked(tenant, site string) {
	sites := r.byTenant[tenant]
	for i, e := range sites {
		if e.site == site {
			delete(r.bySrc, e.addr.String())
			r.byTenant[tenant] = append(sites[:i], sites[i+1:]...)
			return
		}
	}
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

// route 在 tenant 路由域内按最长前缀匹配选目的站点。
func (r *Router) route(tenant string, dst net.IP) *siteEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	dstV4 := dst.To4() != nil
	var best *siteEntry
	bestOnes := -1
	for _, e := range r.byTenant[tenant] {
		for _, c := range e.cidrs {
			if (c.IP.To4() != nil) != dstV4 {
				continue // 只在同地址族内比前缀长度(避免 v4/v6 的 ones 混比)
			}
			if c.Contains(dst) {
				ones, _ := c.Mask.Size()
				if ones > bestOnes {
					bestOnes, best = ones, e
				}
			}
		}
	}
	return best
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

// Serve 在 conn 上收 UDP 数据报、经 Router 转发,直到 ctx 取消。
func (r *Router) Serve(ctx context.Context, conn net.PacketConn) {
	go func() { <-ctx.Done(); _ = conn.Close() }()
	buf := make([]byte, maxDatagram)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[dptunnel] PoP 读 UDP: %v", err)
			return
		}
		for _, o := range r.Handle(append([]byte(nil), buf[:n]...), src) {
			if _, err := conn.WriteTo(o.Data, o.Addr); err != nil {
				log.Printf("[dptunnel] PoP 转发: %v", err)
			}
		}
	}
}
