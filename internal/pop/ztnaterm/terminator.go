// Package ztnaterm 是 PoP 侧 ZTNA-over-packet 终结器(Slice77,L2 docs/sase-l2-pop-ztna-termination.md):
// 终结真 OS Agent 经 dptunnel 送来的 L3 包隧道 → 解封内层包 → 按会话凭证 principal 逐流 PEP 授权 →
// 出站到内部应用(本刀出站后端 = PoP-TUN + 内核 SNAT,§3.4 b)。
//
// 与 SD-WAN dptunnel.Router 平级、共享下层件(dptunnel.Session / tunhandshake / pep / verifier /
// BundleStore / RevocationStore / metrics),**不复用 Router**(其语义是站点间 LPM 转发、无 principal/PEP)。
//
// 安全锚点(§3.1 四道闸,缺一不可):
//   - (入口闸)握手验 cred:tunhandshake 的 verifyCred hook 验签 + 有效期 + 交叉核对租户(claims.TenantID
//     == 证书 Org)+ 查吊销;失败拒握手(Claims 不可信必丢弃,绝不以未验 Claims 透出)。
//   - (主撤销路径)RevocationStore 更新回调 → EvictRevoked 遍历终结表,jti 命中即拆 session(秒级,长连权威闭合)。
//   - (兜底闸)session deadline = min(claims.Exp-now, 上限):到期拆 session 强制重握手。
//   - (新流闸)每新流建连时再查吊销(复用表项 jti),拦撤销命中后才发起的新流。
//
// 数据面铁律:坏包/短读/解析失败 → 降级丢弃 + 可观测计数,绝不 panic;nonce 复用(Slice75 H1)绝不重建
// 归零计数器(终结表项原地保留 session);跨租户 session/flow/appResolver 全按 tenant 分域。
package ztnaterm

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/pop"
	"github.com/ikuai8/sase/internal/revtunnel"
)

// defaultSessionCap 是 session deadline 上限(claims.Exp 与本上限取小)。参照 SD-WAN connMaxAge=1h:
// 强制周期重握手,使撤销/姿态/风险突变在有界窗口内经"重握手带新 cred"反映(§3.1 兜底闸)。
const defaultSessionCap = time.Hour

// drop 原因(低基数,供 metrics.TunnelDrop;复用 SD-WAN 的有界 reason 命名空间 + ZTNA 专属)。
const (
	reasonNoSession   = "no_session"    // 未注册源(握手未完成 / 已拆)
	reasonDecryptFail = "decrypt_fail"  // AEAD 解封失败(伪造源无密钥)
	reasonParseFail   = "parse_fail"    // 5 元组解析失败(坏包)
	reasonNoApp       = "ztna_no_app"   // 目的解析不出 resource(无 appResolver 规则)
	reasonPEPDeny     = "ztna_pep_deny" // 逐流 PEP 裁决 deny
	reasonRevoked     = "ztna_revoked"  // 新流闸查吊销命中
	reasonExpired     = "ztna_expired"  // session deadline 到期
	reasonTUNWrite    = "ztna_tun_write"
	reasonSealFail    = "seal_fail" // 回程 Seal 失败

	// 透明代理(Slice78 零暴露面出站)专属 reason(低基数)。
	reasonProxyNoSession   = "ztna_proxy_no_session"   // accept 后 lookupInnerIP 找不到(无握手 → fail-closed)
	reasonProxyOrigDstFail = "ztna_proxy_origdst_fail" // SO_ORIGINAL_DST 取原目的失败
	reasonProxyNoApp       = "ztna_proxy_no_app"       // 原目的解析不出 resource(本租户域内无规则)
	reasonProxyDeny        = "ztna_proxy_deny"         // 透明代理处连接级 PEP deny
	reasonNoConnector      = "ztna_no_connector"       // 无已注册 connector(OpenStream 返 ErrNoConnector)
	reasonProxyEstablished = "ztna_proxy_established"  // 透明代理流建立(出站成功;非 drop,经 TunnelDrop 复用计数)
)

// flowVerdict 是一条流的缓存裁决(连接级缓存,避免逐包重判;§3.3)。
type flowVerdict struct {
	allow  bool
	expire time.Time
}

// flowCacheTTL 是流裁决缓存有效期(到期后下一包重判 → 重查吊销,即"每新流查吊销"的退化兜底)。
const flowCacheTTL = 30 * time.Second

// termSession 是终结表一项:一个 Agent 的隧道会话状态(§3.2,srcAddr → {session, claims, tenant, deadline})。
type termSession struct {
	srcAddr  net.Addr          // Agent 数据面 UDP 地址(回程目的 + 入向解复用键)
	session  *dptunnel.Session // 与该 Agent 的 dptunnel 会话(握手注入,**绝不重建归零计数器**)
	claims   cred.Claims       // 握手时验过的会话凭证声明(含 JTI;运行期复用,不重 Verify)
	tenant   string            // 租户(= claims.TenantID = 证书 Org,握手已交叉核对)
	deadline time.Time         // session deadline = min(claims.Exp, now+cap)
	innerIPs map[string]bool   // 已见的 Agent 内层源 IP(回程 byInnerIP 索引,过期/拆时清理)
	flows    map[flowKey]flowVerdict
	mu       sync.Mutex // 守 flows / innerIPs(每 session 独立,降低锁竞争)
}

// Terminator 是 PoP 侧 ZTNA 终结器。
type Terminator struct {
	verifier *cred.Verifier
	bundles  *pop.BundleStore
	revoked  *pop.RevocationStore
	apps     *AppResolver
	tun      dptunnel.PacketIO   // PoP 侧 TUN(allow 内层包写入 → 内核 SNAT 出站;回程从此读)
	reg      *revtunnel.Registry // 连接器注册表(Slice78 零暴露面出站:透明代理经 OpenStream 反向送 app);可 nil
	rec      *metrics.Recorder
	now      func() time.Time
	cap      time.Duration

	mu        sync.RWMutex
	bySrc     map[string]*termSession // srcAddr.String() → session(入向解复用)
	byInnerIP map[string]*termSession // Agent 内层源 IP → session(回程定位;同租户域内 IP 不重叠假设)
}

// New 构造终结器。verifier/bundles/revoked 与 cmd/pop-agent 单实例共享(§3.2);tun=PoP 侧 TUN;
// rec 可为 nil(no-op 指标)。sessionCap<=0 用默认上限(1h)。
func New(verifier *cred.Verifier, bundles *pop.BundleStore, revoked *pop.RevocationStore, apps *AppResolver, tun dptunnel.PacketIO, rec *metrics.Recorder, sessionCap time.Duration) *Terminator {
	if sessionCap <= 0 {
		sessionCap = defaultSessionCap
	}
	return &Terminator{
		verifier:  verifier,
		bundles:   bundles,
		revoked:   revoked,
		apps:      apps,
		tun:       tun,
		rec:       rec,
		now:       time.Now,
		cap:       sessionCap,
		bySrc:     map[string]*termSession{},
		byInnerIP: map[string]*termSession{},
	}
}

// WithRegistry 挂 connector 注册表(Slice78 零暴露面出站):透明代理对 connector-backed 流经
// reg.OpenStream 反向送内部 app(私网零入站开口)。返回自身便于链式。reg 可为 nil(则透明代理对所有
// 流因无 connector 关连接)。
func (tm *Terminator) WithRegistry(reg *revtunnel.Registry) *Terminator {
	tm.reg = reg
	return tm
}

// lookupInnerIP 按 Agent 内层源 IP 查终结表项(透明代理 accept 后的 fail-closed 定位,§3.4.1)。
// 找不到 → (nil, false):无有效 dptunnel 握手 → 无 byInnerIP 表项 → 无 principal → 调用方关连接。
func (tm *Terminator) lookupInnerIP(ip net.IP) (*termSession, bool) {
	if ip == nil {
		return nil, false
	}
	tm.mu.RLock()
	ts, ok := tm.byInnerIP[ip.String()]
	tm.mu.RUnlock()
	return ts, ok
}

// VerifyCred 是供 tunhandshake.NewServerWithCred 的 hook(§3.1 入口闸):验签 + 有效期(cred.Verify)+
// **交叉核对 claims.TenantID == 证书租户**(防 A 租户证书拼 B 租户凭证)+ 查吊销。任一不过 → 返 error
// (fail-closed,握手被拒)。**绝不在 Verify 失败时返回非零 Claims**:cred.Verify 失败返零值 Claims+error,
// 本函数也只在全部检查通过后返回 claims,error 路径一律返回零值。
func (tm *Terminator) VerifyCred(certTenant, token string, now time.Time) (cred.Claims, error) {
	claims, err := tm.verifier.Verify(token, now) // 验签 + exp(失败返零值 Claims + error,不可绕)
	if err != nil {
		return cred.Claims{}, err
	}
	if claims.TenantID != certTenant {
		return cred.Claims{}, errTenantMismatch
	}
	if tm.revoked != nil && tm.revoked.IsRevoked(claims.TenantID, claims.JTI) {
		return cred.Claims{}, errRevoked
	}
	return claims, nil
}

// OnEstablished 是 tunhandshake 握手成功回调:建 dptunnel.Session,登入终结表(§3.1 第 4 步)。
// claims 已在 VerifyCred 验过 + 交叉核对租户;此处再断言 e.Tenant==claims.TenantID(纵深,防 wiring 错)。
func (tm *Terminator) OnEstablished(e established) {
	if e.Claims.TenantID != e.Tenant {
		// 不应发生(VerifyCred 已核对);纵深兜底拒绝登记,绝不建立未对齐的会话。
		log.Printf("[ztnaterm] 拒绝登记:证书租户 %s 与凭证租户 %s 不符", e.Tenant, e.Claims.TenantID)
		return
	}
	sess, err := e.Session()
	if err != nil {
		log.Printf("[ztnaterm] 建会话失败 tenant=%s jti=%s: %v", e.Tenant, e.Claims.JTI, err)
		return
	}
	deadline := tm.computeDeadline(e.Claims)
	ts := &termSession{
		srcAddr:  e.CPEDataAddr,
		session:  sess,
		claims:   e.Claims,
		tenant:   e.Tenant,
		deadline: deadline,
		innerIPs: map[string]bool{},
		flows:    map[flowKey]flowVerdict{},
	}
	tm.mu.Lock()
	// 同 srcAddr 重握手:替换旧项(新握手 = 新 cred + 新会话密钥;旧项的 innerIP 索引一并清理避免悬挂)。
	if old, ok := tm.bySrc[e.CPEDataAddr.String()]; ok {
		tm.dropInnerIPsLocked(old)
	}
	tm.bySrc[e.CPEDataAddr.String()] = ts
	tm.mu.Unlock()
	log.Printf("[ztnaterm] Agent 接入 tenant=%s sub=%s jti=%s src=%s deadline=%s",
		e.Tenant, e.Claims.Subject, e.Claims.JTI, e.CPEDataAddr, deadline.Format(time.RFC3339))
}

// computeDeadline 取 min(claims.Exp, now+cap)。claims.Exp 为 0(无 exp,理论不应出现)时用 now+cap 兜底。
func (tm *Terminator) computeDeadline(c cred.Claims) time.Time {
	capDL := tm.now().Add(tm.cap)
	if c.ExpireAt <= 0 {
		return capDL
	}
	exp := time.Unix(c.ExpireAt, 0)
	if exp.Before(capDL) {
		return exp
	}
	return capDL
}

// established 镜像 tunhandshake.Established 的必要字段(本包不直接 import tunhandshake 以保终结器
// 与握手层解耦;cmd/pop-agent 装配时经 Establish 适配 tunhandshake.Established → 本类型)。
type established struct {
	Tenant      string
	Site        string
	Alg         string
	Key         []byte
	CPEDataAddr *net.UDPAddr
	Claims      cred.Claims
	mkSession   func() (*dptunnel.Session, error)
}

func (e established) Session() (*dptunnel.Session, error) { return e.mkSession() }

// Establish 是装配层桥接:把握手产物(租户/凭证声明/CPE 数据地址/建会话闭包)登入终结表(等价 OnEstablished)。
// cmd/pop-agent 在 tunhandshake.NewServerWithCred 的 onEstablished 回调里调本函数(传 e.Tenant /
// e.Claims / e.CPEDataAddr / e.Session)。会话由调用方经握手产物构造(方向已是 PoP 侧:send=PoP→Agent)。
func (tm *Terminator) Establish(tenant string, claims cred.Claims, cpeDataAddr *net.UDPAddr, mkSession func() (*dptunnel.Session, error)) {
	tm.OnEstablished(established{
		Tenant:      tenant,
		Claims:      claims,
		CPEDataAddr: cpeDataAddr,
		mkSession:   mkSession,
	})
}

// drop 记一次丢弃原因(可观测;nil rec → no-op)。
func (tm *Terminator) drop(reason string) { tm.rec.TunnelDrop(reason) }

// dropInnerIPsLocked 从 byInnerIP 移除某 session 的全部内层 IP 索引(调用方持写锁)。
func (tm *Terminator) dropInnerIPsLocked(ts *termSession) {
	ts.mu.Lock()
	for ip := range ts.innerIPs {
		if tm.byInnerIP[ip] == ts { // 仅当仍指向本 session(防覆盖他 session 的索引)
			delete(tm.byInnerIP, ip)
		}
	}
	ts.mu.Unlock()
}
