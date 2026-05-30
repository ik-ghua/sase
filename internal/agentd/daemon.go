package agentd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ikuai8/sase/internal/agent"
	"github.com/ikuai8/sase/internal/dptunnel"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/tunhandshake"
)

// State 是守护进程生命周期状态(L2 §3.1,可观测)。流转:
//
//	StateEnrolling → StateSessionUp → StateTunnelUp → StateRunning
//	任一阶段失败/隧道断 → StateDegraded(可观测降级,守护进程不退出,重试),恢复后回 StateRunning。
//	ctx 取消 → StateStopped。
type State string

const (
	StateEnrolling State = "enrolling"  // 入网中(取租户绑定证书)
	StateSessionUp State = "session-up" // 已有证书 + 会话凭证,实时通道已连
	StateTunnelUp  State = "tunnel-up"  // 已选 PoP + 握手 + dptunnel 会话建立
	StateRunning   State = "running"    // TUN 已开 + 分流配置 + 数据面 pump 运行
	StateDegraded  State = "degraded"   // 降级(隧道断/选址失败/采集失败),重试中
	StateStopped   State = "stopped"    // ctx 取消,已退出
)

// EnrollMode 选入网方式(Slice80)。
const (
	EnrollModeZTP = "ztp" // 激活码 ZTP(默认;Connector/CPE/现有 demo;enroll.DeviceTLS)
	EnrollModeIDP = "idp" // 真 OS 级 ZTNA Agent per-user IdP 入网(loopback + PKCE + /agent/enroll 编排)
)

// Config 是守护进程装配配置(对齐 cmd/cpe 的 env 风格;由 cmd/agent 从 env 注入)。
type Config struct {
	// 身份与入网(ztp=激活码;idp=IdP 用户认证,Slice80 LZ11 定夺)
	Tenant   string // 租户 UUID(本端身份;权威以证书 Org 为准,与 site/identity 交叉核对)
	Identity string // 设备身份(证书 CN;Agent 形态 = 本地稳定随机 device-id,本刀由配置给)
	ZTPCode  string // 激活码(ztp 模式:非空走 ZTP 取租户绑定证书;空则用 dev 共享 role:device 证书兜底)

	// IdP 入网(EnrollMode=idp,Slice80;ztp 模式忽略)
	EnrollMode      string // "ztp"(默认)| "idp";idp 走 loopback + PKCE + /agent/enroll 编排
	IDPID           string // IdPConfig ID(idp 模式必填)
	AgentEnrollURL  string // 管理面 /api/v1/agent/enroll 绝对 URL(idp 模式必填)
	IDPAuthorizeURL string // IdP authorize 端点 + client_id + scope 的公开 URL(idp 模式;daemon 据此拼 loopback+PKCE)

	// 端点地址(去硬编码:PoP 候选由 SetCandidates 注入,本配置给入网/管理面地址)
	MgmtURL    string // 管理面 HTTPS(入网 /enroll)
	DeviceURL  string // 设备 mTLS 端点(续期 /renew)
	ServerName string // 服务端证书 SAN(dev = localhost)
	TLSDir     string // 证书目录(ca.crt + dev 证书 + ZTP 写入处)

	// 数据面
	Alg          string         // 隧道算法档(dev env 默认;生产应取控制面下发租户档,见 cmd/cpe 注释)
	DataAddr     string         // 本地数据面 UDP 监听(默认 "0.0.0.0:0" ephemeral;通告给 PoP)
	DataAdvAddr  string         // 通告给 PoP 的本端数据面地址(NAT/容器须显式设;空=取本地监听地址)
	Candidates   []PoPCandidate // 初始候选 PoP 列表(入网前的引导,运行期可经 config_update 更新)
	InternalCIDR []string       // split-tunnel 接管 CIDR(白名单;空=不接管任何流量)
	InternalDNS  []string       // split-DNS 内部域名后缀

	// 凭证 / 实时通道
	ControlAddr string        // 控制面实时通道 gRPC 地址(空=不连实时通道,降级:仅靠短 TTL)
	SessionTok  string        // 会话凭证(本刀由配置给;真实从入网/令牌交换取,刷新调度 = 子块7)
	SessionJTI  string        // 会话凭证 jti(撤销匹配用)
	RenewLead   time.Duration // 设备证书续期提前量(默认 8h,同 cmd/cpe)

	// 姿态
	PostureInterval time.Duration // 姿态周期采集间隔(默认 5min)
	AgentVersion    string        // Agent 版本(编译期注入;填入 PostureFacts.AgentVersion)
}

func (c *Config) withDefaults() {
	if c.EnrollMode == "" {
		c.EnrollMode = EnrollModeZTP // 向后兼容:默认激活码 ZTP(Connector/CPE/现有 demo 不破)
	}
	if c.Alg == "" {
		c.Alg = dptunnel.AlgChaCha20Poly1305
	}
	if c.DataAddr == "" {
		c.DataAddr = "0.0.0.0:0"
	}
	if c.ServerName == "" {
		c.ServerName = "localhost"
	}
	if c.TLSDir == "" {
		c.TLSDir = "./certs"
	}
	if c.MgmtURL == "" {
		c.MgmtURL = "https://localhost:8443"
	}
	if c.DeviceURL == "" {
		c.DeviceURL = "https://localhost:8444"
	}
	if c.RenewLead <= 0 {
		c.RenewLead = 8 * time.Hour
	}
	if c.PostureInterval <= 0 {
		c.PostureInterval = 5 * time.Minute
	}
}

// Daemon 是 Agent 守护进程共享核心(平台无关):组装入网/凭证/隧道/实时通道/分流/选址/姿态,长驻运行。
// 三窄壳接口(NetCapture/PostureProbe/SystemIntegration)由构造时注入(平台无关核心 + 壳实现分离,L2 §3.1)。
type Daemon struct {
	cfg   Config
	net   NetCapture
	probe PostureProbe
	sys   SystemIntegration

	flow     *FlowManager
	selector *PoPSelector
	posture  *PostureScheduler

	mu    sync.RWMutex
	state State

	// retryBackoff:降级后重试退避(可被测试覆盖为 0)。
	retryBackoff time.Duration
}

// rttProberFunc 是把函数适配为 RTTProber 的便捷类型(默认用 TCP 握手端口连通耗时测 RTT)。
type rttProberFunc func(ctx context.Context, c PoPCandidate) (time.Duration, error)

func (f rttProberFunc) ProbeRTT(ctx context.Context, c PoPCandidate) (time.Duration, error) {
	return f(ctx, c)
}

// tcpRTTProbe 用 TCP 连握手地址的耗时近似 RTT(不依赖 ICMP,L2 §3.7)。轻量、不发应用数据。
func tcpRTTProbe(ctx context.Context, c PoPCandidate) (time.Duration, error) {
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "tcp", c.HandshakeAddr)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

// New 构造守护进程。net/probe/sys 为平台壳(经 NewPlatformShells 跨平台装配:Linux/macOS 真壳,其余返 unsupported 桩)。
// prober 为 nil 时用默认 TCP RTT 探测(不依赖 ICMP)。
func New(cfg Config, ncap NetCapture, probe PostureProbe, sys SystemIntegration, prober RTTProber) *Daemon {
	cfg.withDefaults()
	if prober == nil {
		prober = rttProberFunc(tcpRTTProbe)
	}
	d := &Daemon{
		cfg:          cfg,
		net:          ncap,
		probe:        probe,
		sys:          sys,
		flow:         NewFlowManager(),
		selector:     NewPoPSelector(prober),
		state:        StateEnrolling,
		retryBackoff: 3 * time.Second,
	}
	d.selector.SetCandidates(cfg.Candidates)
	return d
}

// State 返回当前生命周期状态(可观测)。
func (d *Daemon) State() State {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.state
}

func (d *Daemon) setState(s State) {
	d.mu.Lock()
	prev := d.state
	d.state = s
	d.mu.Unlock()
	if prev != s {
		log.Printf("[agentd] 状态 %s → %s", prev, s)
		if d.sys != nil {
			_ = d.sys.Notify("SASE Agent", fmt.Sprintf("状态:%s", s))
		}
	}
}

// FlowManager / Selector / Posture 暴露给 cmd/测试观测与运行期更新(config_update 入口)。
func (d *Daemon) FlowManager() *FlowManager  { return d.flow }
func (d *Daemon) Selector() *PoPSelector     { return d.selector }
func (d *Daemon) Posture() *PostureScheduler { return d.posture }

// Run 长驻运行守护进程:enroll → 凭证/实时通道 → 选址/握手/隧道 → TUN/分流/数据面 pump;
// 阻塞到 ctx 取消。任一阶段失败 → 进 StateDegraded 退避重试(绝不退出/崩溃,数据面坏包降级)。
// 返回 nil 当 ctx 正常取消;返回非 nil 仅当装配前置(无壳)不可恢复。
func (d *Daemon) Run(ctx context.Context) error {
	if d.net == nil {
		return fmt.Errorf("agentd: 未提供 NetCapture 壳(平台不支持?)")
	}

	// EnrollMode=idp(Slice80):IdP 用户认证 per-user 入网(loopback + PKCE + /agent/enroll 编排)。
	// 取得设备证书 + per-user 会话凭证(填运行态),再进 runWithCert(其余阶段与 ztp 完全一致)。
	if d.cfg.EnrollMode == EnrollModeIDP {
		return d.runIDPMode(ctx)
	}

	// EnrollMode=ztp(默认,向后兼容):激活码 ZTP 取租户绑定证书 + 续期循环(复用 enroll.DeviceTLS / RunRenewLoop)。
	d.setState(StateEnrolling)
	tlsConf, rotator, err := enroll.DeviceTLS(ctx, d.cfg.TLSDir, d.cfg.MgmtURL, d.cfg.ServerName, d.cfg.ZTPCode, d.cfg.Identity)
	if err != nil {
		// 入网失败不可恢复地缺证书 → 仍长驻重试(进降级),不直接退出(守护进程语义)。
		log.Printf("[agentd] 入网失败(降级重试): %v", err)
		d.setState(StateDegraded)
		return d.retryLoop(ctx, func(c context.Context) error {
			cfg, rot, e := enroll.DeviceTLS(c, d.cfg.TLSDir, d.cfg.MgmtURL, d.cfg.ServerName, d.cfg.ZTPCode, d.cfg.Identity)
			if e != nil {
				return e
			}
			return d.runWithCert(c, cfg, rot)
		})
	}
	return d.runWithCert(ctx, tlsConf, rotator)
}

// runIDPMode 跑 per-user IdP 入网(Slice80):idpEnroll 取证书 + 会话凭证 → 填运行态 SessionTok/JTI → runWithCert。
// 入网失败(用户没及时登录/IdP 拒/网络)→ 长驻降级重试(守护进程语义,绝不退出/崩)。
func (d *Daemon) runIDPMode(ctx context.Context) error {
	d.setState(StateEnrolling)
	res, err := d.idpEnroll(ctx)
	if err != nil {
		log.Printf("[agentd] IdP 入网失败(降级重试): %v", err)
		d.setState(StateDegraded)
		return d.retryLoop(ctx, func(c context.Context) error {
			r, e := d.idpEnroll(c)
			if e != nil {
				return e
			}
			d.cfg.SessionTok, d.cfg.SessionJTI = r.sessionTok, r.sessionJTI
			return d.runWithCert(c, r.tlsConf, r.rotator)
		})
	}
	// IdP 模式的会话凭证来自入网(非 env);填运行态供实时通道 + 撤销匹配(子块7 完整刷新调度为后续刀)。
	d.cfg.SessionTok, d.cfg.SessionJTI = res.sessionTok, res.sessionJTI
	return d.runWithCert(ctx, res.tlsConf, res.rotator)
}

// runWithCert 在已拿到设备 mTLS 配置后运行其余阶段(选址→握手→隧道→pump),失败进降级重试循环。
func (d *Daemon) runWithCert(ctx context.Context, tlsConf *tls.Config, rotator *enroll.CertRotator) error {
	// 守护进程退出(ctx 取消 → retryLoop 返回)时让壳清理路由/DNS,防留下断网态(壳 Close 幂等;
	// TUN 设备本身由每轮 pio.Close 关闭,本 Close 收口壳承诺的「防崩溃断网」清理,Slice76 S4)。
	defer func() { _ = d.net.Close() }()

	// 设备证书续期(transport 层,复用 RunRenewLoop;rotator==nil 表示 dev 兜底证书,无续期)。
	if rotator != nil {
		go enroll.RunRenewLoop(ctx, rotator, d.cfg.DeviceURL, d.cfg.TLSDir, d.cfg.ServerName, d.cfg.Identity, d.cfg.RenewLead)
	}

	// 会话状态 + 实时通道(复用 agent.Session;收 revoke/recheck_posture/reauth)。
	sess := agent.NewSession(d.cfg.SessionJTI, "")

	// 姿态采集调度(周期 + Recheck 事件;version 编译期注入填入)。onUpdate 把最新姿态摘要同步进会话
	// (供实时通道 recheck_posture 上报 + 凭证刷新填 claim,子块7,largely 复用)。闭包**直接捕获已建的
	// sess**(稳定指针)——不经可变中转变量,杜绝 onUpdate(posture goroutine)与主 goroutine 对裸指针
	// 的并发读写(Slice76 H1);Session.SetPosture 自身 RWMutex 守,多 goroutine 写安全。
	d.posture = NewPostureScheduler(d.probe, d.cfg.PostureInterval, d.cfg.AgentVersion, func(f PostureFacts) {
		sess.SetPosture(f.Summary())
	})
	go d.posture.Run(ctx)
	if f, ok := d.posture.Latest(); ok {
		sess.SetPosture(f.Summary())
	}
	d.startControlChannel(ctx, sess, tlsConf)

	// split-tunnel / split-DNS 规则装载(入网/config_update 下发;本刀由 Config 给初值)。
	if accepted, rejected := d.flow.SetRoutesFromStrings(d.cfg.InternalCIDR); len(rejected) > 0 {
		log.Printf("[agentd] split-tunnel 忽略非法 CIDR %v(已接管 %d 条)", rejected, len(accepted))
	}
	d.flow.SetInternalDomains(d.cfg.InternalDNS)

	d.setState(StateSessionUp)

	// 隧道生命周期循环:选址→握手→建会话→开 TUN→配路由/DNS→数据面 pump;断开/失败进降级重连。
	return d.retryLoop(ctx, func(c context.Context) error {
		return d.runTunnelOnce(c, tlsConf)
	})
}

// retryLoop 反复跑 fn,fn 返回(隧道断/失败)即进降级退避重试,直到 ctx 取消。绝不崩。
// ctx 取消时统一返回 nil(守护进程干净退出语义,非错误)。
func (d *Daemon) retryLoop(ctx context.Context, fn func(context.Context) error) error {
	for {
		if ctxDone(ctx) {
			d.setState(StateStopped)
			return nil
		}
		if err := fn(ctx); err != nil && !ctxDone(ctx) {
			log.Printf("[agentd] 运行阶段中断(降级重试): %v", err)
		}
		if ctxDone(ctx) {
			d.setState(StateStopped)
			return nil
		}
		d.setState(StateDegraded)
		if sleepCtx(ctx, d.retryBackoff) {
			d.setState(StateStopped)
			return nil
		}
	}
}

// ctxDone 报告 ctx 是否已取消(避免 ctx.Err() 触发 nilerr 误报)。
func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// runTunnelOnce 完成一次「选址→握手→隧道→pump」,阻塞到隧道断或 ctx 取消;返回触发重连的原因。
// 实时通道/撤销由 startControlChannel 独立维护(复用 agent.Session),故本方法不持会话引用。
func (d *Daemon) runTunnelOnce(ctx context.Context, tlsConf *tls.Config) error {
	// 选址(RTT 实测选最近,L2 §3.7)。
	pop, err := d.selector.Select(ctx)
	if err != nil {
		return fmt.Errorf("选址: %w", err)
	}
	log.Printf("[agentd] 选定 PoP %s(%s)", pop.Name, pop.HandshakeAddr)

	// 本地数据面 UDP socket(通告给 PoP:回程目的 + 入向解复用键)。
	dataConn, err := net.ListenPacket("udp", d.cfg.DataAddr)
	if err != nil {
		return fmt.Errorf("监听本地数据面 UDP: %w", err)
	}
	defer dataConn.Close()
	advAddr := d.cfg.DataAdvAddr
	if advAddr == "" {
		advAddr = dataConn.LocalAddr().String()
	}

	// 握手(复用 tunhandshake.DialWithCred:互认证 TLS1.3 + RFC5705 派生 dptunnel.Session;防降级校验 alg)。
	// **ZTNA 形态(Slice77)**:携会话凭证 SessionTok → PoP 终结器(ZTNA_TUNNEL_ADDR)经 verifyCred hook
	// 验签 + 交叉核对租户 + 查吊销,验过的 principal(组/姿态/风险)供逐流 PEP。SessionTok 空(未配)时
	// 等价裸 Dial(连 SD-WAN 形态 PoP 不验 cred,行为不变)。
	res, err := tunhandshake.DialWithCred(ctx, pop.HandshakeAddr, tlsConf, d.cfg.Alg, advAddr, d.cfg.Tenant, d.cfg.Identity, d.cfg.SessionTok)
	if err != nil {
		return fmt.Errorf("握手 PoP %s: %w", pop.Name, err)
	}
	tunSess, err := res.Session()
	if err != nil {
		return fmt.Errorf("建隧道会话: %w", err)
	}
	d.setState(StateTunnelUp)

	// 开 TUN(壳 OpenAdapter,Linux=dptunnel.OpenTUN;非 Linux 返 unsupported)。
	pio, ifinfo, err := d.net.OpenAdapter()
	if err != nil {
		return fmt.Errorf("打开虚拟网卡: %w", err)
	}
	defer pio.Close()
	log.Printf("[agentd] 虚拟网卡 %s(MTU=%d)就绪", ifinfo.Name, ifinfo.MTU)

	// 配路由(split-tunnel 白名单:只把接管 CIDR 路由进 TUN,L2 §3.3)+ DNS(split-DNS 基础)。
	if err := d.net.ConfigureRoutes(d.flow.Routes()); err != nil {
		log.Printf("[agentd] 配路由失败(降级,继续 pump 已开 TUN): %v", err)
	}
	if err := d.net.ConfigureDNS(d.flow.DNSRules()); err != nil {
		log.Printf("[agentd] 配 split-DNS 失败(降级): %v", err)
	}

	// 数据面 pump(复用 dptunnel.Endpoint 双 pump:TUN↔Session↔UDP;阻塞到 ctx 取消或 pump 出错)。
	// 用本轮独立可取消子 ctx:Endpoint.Run 内有个 `<-ctx.Done()` watcher goroutine,只在 ctx 取消时退;
	// 若 pump 因断线自身退出而父 ctx 未取消,Run 返回后该 watcher 仍 parked → retryLoop 反复重连会累积
	// 泄漏(Slice76 H2)。本轮结束即 cancel() 让 watcher 随本轮收尾退出(父 ctx 取消时子 ctx 亦取消,
	// 关闭路径不变)。
	tunCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.setState(StateRunning)
	dptunnel.NewEndpoint(tunSess, pio, dataConn, res.PoPDataAddr).Run(tunCtx)
	return fmt.Errorf("数据面 pump 退出(隧道断/ctx 取消)")
}

// startControlChannel 起实时通道客户端(复用 agent.Session.RunControlChannel,收 revoke/recheck/reauth)。
// ControlAddr 空 → 不连(降级:仅靠短 TTL 兜底,权威在 PoP)。SessionTok 空 → 同样不连(无凭证)。
//
// 诚实定界(本刀 largely 复用既有 agent.Session,以下端侧动作未接,均后续刀):
//   - recheck_posture:Session 仅回发**当前缓存**姿态摘要;**未**触发壳 d.posture.Recheck() 重新 Collect
//     (事件驱动重采为后续刀——需 Session 暴露 recheck 回调由 daemon 注入 d.posture.Recheck)。
//   - revoke:Session 置 revoked 标志,但 daemon **未**消费 sess.Revoked() 去主动停 pump/撤路由/重认证;
//     秒级本地阻断「端提速」(ZTNA 硬化 L2 §3.4 层②)本刀为空转,权威仍靠 PoP + 短 TTL 兜底(后续刀)。
//   - reauth:既有件仅 log,daemon 未重走令牌交换(LZ11,后续刀)。
func (d *Daemon) startControlChannel(ctx context.Context, sess *agent.Session, tlsConf *tls.Config) {
	if d.cfg.ControlAddr == "" || d.cfg.SessionTok == "" {
		log.Printf("[agentd] 未配实时通道(ControlAddr/SessionTok),撤销仅靠短 TTL 兜底(权威在 PoP)")
		return
	}
	go func() {
		for ctx.Err() == nil {
			err := sess.RunControlChannel(ctx, d.cfg.ControlAddr, tlsConf, d.cfg.SessionTok)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				log.Printf("[agentd] 实时通道断开,重连: %v", err)
			}
			if sleepCtx(ctx, d.retryBackoff) {
				return
			}
		}
	}()
}

// sleepCtx 睡 d 或 ctx 取消;返回 true 表示 ctx 已取消。
func sleepCtx(ctx context.Context, dur time.Duration) bool {
	if dur <= 0 {
		return ctx.Err() != nil
	}
	select {
	case <-ctx.Done():
		return true
	case <-time.After(dur):
		return false
	}
}
