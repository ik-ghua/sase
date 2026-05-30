package ztnaterm

import (
	"context"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/pop/pep"
)

// maxDatagram 单次 UDP 读缓冲上限(与 dptunnel 一致:容内层 MTU + 封装开销)。
const maxDatagram = 1 << 16

// Serve 启动终结器数据面:① UDP 收 Agent 隧道数据报(worker pool 并发解封 → 逐流 PEP → 写 PoP-TUN);
// ② PoP-TUN 回程 pump(读内核回程包 → 定位 session → Seal → UDP 写回 Agent)。阻塞到 ctx 取消。
//
// 并发安全:UDP conn.ReadFrom 多 goroutine 安全(每次一个完整数据报);每 worker 独立 buf;终结表经
// RWMutex + 每 session 独立 mu;TUN ReadPacket/WritePacket 经独立 pump goroutine 串行(同 dptunnel.Endpoint)。
func (tm *Terminator) Serve(ctx context.Context, conn net.PacketConn) {
	go func() { <-ctx.Done(); _ = conn.Close(); _ = tm.tun.Close() }()

	var wg sync.WaitGroup
	// 回程 pump:从 PoP-TUN 读内核回程包(dst=Agent 内层 IP)→ Seal → UDP 写回 Agent。
	wg.Add(1)
	go func() { defer wg.Done(); tm.returnPump(ctx, conn) }()

	// 入向 worker pool:解封 + 逐流 PEP + 写 TUN。
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, maxDatagram)
			for {
				n, src, err := conn.ReadFrom(buf)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("[ztnaterm] 读 UDP: %v", err)
					return
				}
				// 拷贝独立切片(并发 ReadFrom 复用 buf;Handle 内还要解封)。
				tm.handleDatagram(append([]byte(nil), buf[:n]...), src)
			}
		}()
	}
	wg.Wait()
}

// handleDatagram 处理一个 Agent 数据报:解复用 → 解封内层包 → 逐流裁决 → allow 写 PoP-TUN。
// 全程 fail-soft:任何坏包/解析失败/裁决 deny → 计数丢弃,绝不 panic、不影响其它流。
func (tm *Terminator) handleDatagram(datagram []byte, src net.Addr) {
	tm.mu.RLock()
	ts := tm.bySrc[src.String()]
	tm.mu.RUnlock()
	if ts == nil {
		tm.drop(reasonNoSession) // 未注册源(握手未完成 / 已拆 / 伪造源)
		return
	}
	// 兜底闸:session deadline 到期 → 拆 session(强制重握手),本数据报丢弃。
	if !tm.now().Before(ts.deadline) {
		tm.evictSession(src.String(), ts, reasonExpired)
		return
	}
	inners, err := ts.session.Open(datagram) // AEAD 解封(伪造源无密钥 → 失败)
	if err != nil {
		tm.drop(reasonDecryptFail)
		return
	}
	for _, pkt := range inners {
		tm.forwardInner(ts, pkt)
	}
}

// forwardInner 对一个解封出的内层 L3 包:解 5 元组 → 逐流裁决(allow/deny + 缓存)→ allow 写 PoP-TUN。
func (tm *Terminator) forwardInner(ts *termSession, pkt []byte) {
	t, ok := parse5Tuple(pkt)
	if !ok {
		tm.drop(reasonParseFail)
		return
	}
	// 记下 Agent 内层源 IP → 本 session(回程定位)。首见即建索引(同租户域内 IP 不重叠假设,§5)。
	tm.learnInnerIP(ts, t.SrcIP)

	allow, reason := tm.decide(ts, t)
	if !allow {
		tm.drop(reason)
		return
	}
	// allow:把内层包写入 PoP-TUN → 内核 SNAT + 路由到 app(出站后端 = §3.4 b)。
	if err := tm.tun.WritePacket(pkt); err != nil {
		log.Printf("[ztnaterm] 写 PoP-TUN 失败: %v", err)
		tm.drop(reasonTUNWrite)
	}
}

// decide 逐流裁决:命中流缓存复用;首流(或缓存过期)→ appResolver 解析目的 → decideResource
// (新流闸查吊销 + pep.Decide)→ 缓存(allow/deny + TTL)。返回 (allow, dropReason)。
// **inspect 第一刀 = allow**(注明:SWG/DLP 在包路径需 TCP 重组,留后续刀;该拒的已被 PEP deny 拦下,
// 对齐 ingress 非对称哲学)。
func (tm *Terminator) decide(ts *termSession, t fiveTuple) (bool, string) {
	key := keyOf(t)
	now := tm.now()

	ts.mu.Lock()
	if v, ok := ts.flows[key]; ok && now.Before(v.expire) {
		ts.mu.Unlock()
		if v.allow {
			return true, ""
		}
		return false, reasonPEPDeny
	}
	ts.mu.Unlock()

	// 首流(或缓存过期):appResolver 解析目的为 resource(本租户域内;无匹配 → 无可授权资源 → deny,默认拒绝)。
	appKey, ok := tm.apps.Resolve(ts.tenant, t.DstIP, t.DstPort)
	if !ok {
		// 不缓存 deny(目的可能后续被 appResolver 配置;且无 appKey 即无流定义)。计 ztna_no_app。
		// 顺序说明(reviewer B2):本路径 resolve 先于吊销检查——已撤销 session 若只发往 no-app 目的,
		// 不在此被新流闸拆除(该流本就 deny、数据不出);撤销的权威拆除靠 EvictRevoked 主路径(撤销下发回调
		// 遍历全表)+ session deadline 兜底,二者不依赖"恰有一个 no-app 新流来触发"。发往有效 app 的新流仍
		// 在下方 decideResource 第①步命中吊销并拆 session。故顺序调整非安全回归。
		return false, reasonNoApp
	}

	// 新流闸查吊销 + PEP 裁决(与透明代理路径同一逻辑 decideResource,零行为漂移)。
	allow, effect, reason := tm.decideResource(ts, appKey)
	if reason == reasonRevoked {
		// 撤销命中已在 decideResource 拆 session;不缓存(session 已亡)。
		return false, reasonRevoked
	}

	ts.mu.Lock()
	ts.flows[key] = flowVerdict{allow: allow, expire: now.Add(flowCacheTTL)}
	ts.mu.Unlock()

	if !allow {
		log.Printf("[ztnaterm] DENY tenant=%s sub=%s app=%s dst=%s:%d", ts.tenant, ts.claims.Subject, appKey, t.DstIP, t.DstPort)
		return false, reasonPEPDeny
	}
	log.Printf("[ztnaterm] %s tenant=%s sub=%s app=%s dst=%s:%d", effect, ts.tenant, ts.claims.Subject, appKey, t.DstIP, t.DstPort)
	return true, ""
}

// decideResource 是「新流闸查吊销 + pep.Decide」的连接级授权裁决(§3.4.1 安全核心):
// 包路径(decide)与透明代理路径(RunRedirectProxy)共用此函数,**同一逻辑零行为漂移**。
//
// 流程:① 新流闸(§3.1)查吊销(复用握手时存的 ts.claims.JTI;同 session 内 jti 不变,不重解析凭证)
// → 命中即主动拆 session(长连权威闭合的兜底,返 reasonRevoked);② pep.Decide(复用纯函数,权威在 PoP,
// 默认拒绝)→ inspect 第一刀 = allow。返回 (allow, effect, dropReason);effect 供调用方日志(与重构前一致)。
//
// 注:**不做流缓存**(缓存是包路径 decide 的职责;透明代理是 OS 级连接,每连接调一次,无需 mux 内缓存)。
func (tm *Terminator) decideResource(ts *termSession, appKey string) (allow bool, effect, reason string) {
	// ① 新流闸:查吊销。命中 → 主动拆 session(不只拒本流)——长连权威闭合的兜底(主路径是 EvictRevoked 回调)。
	if tm.revoked != nil && tm.revoked.IsRevoked(ts.tenant, ts.claims.JTI) {
		tm.mu.RLock()
		srcKey := ts.srcAddr.String()
		tm.mu.RUnlock()
		tm.evictSession(srcKey, ts, reasonRevoked)
		return false, "", reasonRevoked
	}

	// ② PEP 裁决(复用 pep.Decide;权威在 PoP,默认拒绝)。
	bundle, has := tm.bundles.Get(ts.tenant)
	var bp *xdsv1.PolicyBundle
	if has {
		bp = &bundle
	}
	effect = pep.Decide(bp, ts.claims, appKey, "connect")
	allow = effect != xdsv1.EffectDeny // inspect 第一刀 = allow
	if !allow {
		return false, effect, reasonPEPDeny
	}
	return true, effect, ""
}

// learnInnerIP 记录 Agent 内层源 IP → session(回程定位)。已记录则 no-op。
func (tm *Terminator) learnInnerIP(ts *termSession, srcIP net.IP) {
	if srcIP == nil {
		return
	}
	ip := srcIP.String()
	ts.mu.Lock()
	known := ts.innerIPs[ip]
	if !known {
		ts.innerIPs[ip] = true
	}
	ts.mu.Unlock()
	if known {
		return
	}
	tm.mu.Lock()
	if prev, exists := tm.byInnerIP[ip]; exists && prev != ts {
		// 内层 IP 冲突(Slice77 B1/B2 可观测):单 PoP 共享回程 TUN + 按内层 IP 定位 session 是固有约束——
		// 两个不同 session 用了相同内层 IP(同租户重叠地址池,或跨租户撞 IP)时回程会错投。
		// 响亮记日志使「内层 IP 唯一」假设的违反可观测;真正硬化(PoP 分配唯一内层 IP / per-tenant 回程 TUN)留后续刀。
		log.Printf("[ztnaterm] ⚠️ 内层 IP 冲突 ip=%s(原 tenant=%s → 新 tenant=%s):回程路由有歧义,生产须 PoP 分配唯一内层 IP",
			ip, prev.tenant, ts.tenant)
	}
	tm.byInnerIP[ip] = ts
	tm.mu.Unlock()
}

// returnPump 读 PoP-TUN 的内核回程包(dst = Agent 内层 IP)→ 按 dst 定位 session → Seal → UDP 写回 Agent。
// 阻塞到 ctx 取消(TUN 关 → ReadPacket 出错退出)。
func (tm *Terminator) returnPump(ctx context.Context, conn net.PacketConn) {
	for {
		pkt, err := tm.tun.ReadPacket()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("[ztnaterm] 回程 pump 退出(读 PoP-TUN): %v", err)
			}
			return
		}
		t, ok := parse5Tuple(pkt)
		if !ok {
			tm.drop(reasonParseFail)
			continue
		}
		dst := t.DstIP.String()
		tm.mu.RLock()
		ts := tm.byInnerIP[dst]
		tm.mu.RUnlock()
		if ts == nil {
			tm.drop(reasonNoSession) // 回程目的不对应任何 Agent(conntrack 未建 / session 已拆)
			continue
		}
		frames, err := ts.session.Seal(pkt)
		if err != nil {
			tm.drop(reasonSealFail) // 含 ErrRekeyRequired(计数器达阈值 → fail-closed 停发)
			continue
		}
		for _, f := range frames {
			if _, err := conn.WriteTo(f, ts.srcAddr); err != nil {
				log.Printf("[ztnaterm] 回程 UDP 写: %v", err)
			}
		}
	}
}

// evictSession 从终结表移除一个 session(撤销命中 / deadline 到期):删 bySrc + byInnerIP 索引。
// dptunnel.Session 无外部资源(无 fd/conn),GC 回收即可;不需显式 Close。幂等(已删则 no-op)。
func (tm *Terminator) evictSession(srcKey string, ts *termSession, reason string) {
	tm.mu.Lock()
	cur, ok := tm.bySrc[srcKey]
	if !ok || cur != ts { // 已被替换/删除(并发重握手)→ 不重复删,避免误删新 session
		tm.mu.Unlock()
		return
	}
	delete(tm.bySrc, srcKey)
	tm.dropInnerIPsLocked(ts)
	tm.mu.Unlock()
	tm.drop(reason)
	log.Printf("[ztnaterm] 拆除 session tenant=%s sub=%s jti=%s src=%s(%s)",
		ts.tenant, ts.claims.Subject, ts.claims.JTI, srcKey, reason)
}

// EvictRevoked 是 RevocationStore 更新后的主撤销路径回调(§3.1 主撤销路径,长连权威闭合):
// 遍历终结表,某 session 的 claims.JTI 在该租户撤销集命中 → 立即拆 session(关解复用项 + 断回程流)。
// 已建、不再新建流的长连(SSH/DB)经此被驱逐 → 与 HTTP 路径每请求重查吊销达成同等秒级时效。
func (tm *Terminator) EvictRevoked(tenant string) {
	tm.mu.RLock()
	var victims []struct {
		key string
		ts  *termSession
	}
	for key, ts := range tm.bySrc {
		if ts.tenant != tenant {
			continue
		}
		if tm.revoked != nil && tm.revoked.IsRevoked(ts.tenant, ts.claims.JTI) {
			victims = append(victims, struct {
				key string
				ts  *termSession
			}{key, ts})
		}
	}
	tm.mu.RUnlock()
	// 锁外逐个 evict(evictSession 自取写锁;避免读锁内升级写锁死锁)。
	for _, v := range victims {
		tm.evictSession(v.key, v.ts, reasonRevoked)
	}
}

// sweepExpired 是可选的过期清扫(deadline 到期 session;主路径是 handleDatagram 内惰性检查,本函数供
// 周期 ticker 主动回收不再来包的过期 session)。返回清扫数。
func (tm *Terminator) sweepExpired() int {
	now := tm.now()
	tm.mu.RLock()
	var victims []struct {
		key string
		ts  *termSession
	}
	for key, ts := range tm.bySrc {
		if !now.Before(ts.deadline) {
			victims = append(victims, struct {
				key string
				ts  *termSession
			}{key, ts})
		}
	}
	tm.mu.RUnlock()
	for _, v := range victims {
		tm.evictSession(v.key, v.ts, reasonExpired)
	}
	return len(victims)
}

// RunExpirySweep 周期清扫过期 session(deadline 兜底闸的主动回收;惰性检查已覆盖来包路径)。
// interval<=0 用默认 1min。阻塞到 ctx 取消。
func (tm *Terminator) RunExpirySweep(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := tm.sweepExpired(); n > 0 {
				log.Printf("[ztnaterm] 周期清扫过期 session %d 个", n)
			}
		}
	}
}
