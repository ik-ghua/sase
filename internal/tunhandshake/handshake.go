// Package tunhandshake 是 SD-WAN 数据面隧道的**握手**(L2 `sase-l2-tunnel-handshake.md` 形态 A):
// CPE 与 PoP 用 ZTP 设备证书做**互认证 TLS1.3**(短控制连接),经 RFC5705 密钥导出派生
// `dptunnel.Session` 所需会话密钥——**密钥协商+互认证零自研**(复用 TLS1.3 成熟件)。PoP 从已认证的
// 对端证书取 (tenant, site),据此登记 `dptunnel.Router`,使**隔离权威落在密钥+证书身份而非 UDP 源地址**。
//
// 本刀范围(其余待第三方密码学审查 / 后续刀,见 L2 §7/§8):
//   - **仅非国密档**(TLS1.3 + RFC5705 exporter)。国密档(TLCP/铜锁 + SM3-KDF 导出)待铜锁 exporter 实测(L2 §7.3)。
//   - **单密钥 + 方向字节**复用现 `dptunnel.Session`(已 nonce-safe);tx/rx 双密钥 + epoch 演进待审查(L2 §4.3)。
//   - **入向解复用沿用 srcAddr**(非 NAT/dev 可行);NAT 下 receiver-index 待审查(L2 §4.4)。
//   - **rekey = 重握手**:本刀握手一次产长期会话密钥;周期 rekey/epoch 编排待审查(L2 §4.6)。
package tunhandshake

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dptunnel"
)

// 方向字节:CPE↔PoP 每会话单共享密钥下,两方向用不同 dir 防 nonce 复用(dptunnel.NewSession 约定)。
const (
	dirCPEToPoP = 1
	dirPoPToCPE = 2
)

// exporterLabel 是 RFC5705 TLS Exporter 的 label(用途绑定;tls-exporter 命名空间)。
const exporterLabel = "EXPORTER-sase-sdwan-tunnel"

// handshakeTimeout 限握手控制连接的 TLS 握手 + 消息往返时长。
const handshakeTimeout = 10 * time.Second

// clientHello 是 CPE→PoP 控制消息:CPE 的数据面 UDP 地址(PoP 回程目的)。
// 注:tenant/site 不信任本消息,以已认证证书为准(site 仅供交叉核对)。
//
// Cred 是可选的会话凭证 token(ZTNA 形态:Agent 携 SessionTok,PoP 经 verifyCred hook 验签 + 交叉核对
// 租户绑定;见 NewServerWithCred / Slice77 L2 §3.1)。SD-WAN CPE 不填(空)、PoP 不设 hook → 旧行为不变。
type clientHello struct {
	DataAddr string `json:"data_addr"`
	Site     string `json:"site"`
	Cred     string `json:"cred,omitempty"`
}

// serverHello 是 PoP→CPE 控制消息:PoP 数据面 UDP 地址 + 算法档 + epoch(防降级:档由控制面定,CPE 校验)。
type serverHello struct {
	DataAddr string `json:"data_addr"`
	Alg      string `json:"alg"`
	Epoch    uint32 `json:"epoch"`
}

// deriveKey 经 RFC5705 TLS Exporter 派生数据面会话密钥(用途/档/epoch 绑进 label+context)。
// 同一 TLS 连接两端、同 label/context/length → 同密钥(RFC5705 保证)。
func deriveKey(cs tls.ConnectionState, alg string, epoch uint32) ([]byte, error) {
	n, err := dptunnel.KeyLen(alg)
	if err != nil {
		return nil, err
	}
	ctx := make([]byte, 4+len(alg)) // epoch(4) || alg —— 把档与 epoch 绑进导出上下文
	binary.BigEndian.PutUint32(ctx[:4], epoch)
	copy(ctx[4:], alg)
	key, err := cs.ExportKeyingMaterial(exporterLabel, ctx, n)
	if err != nil {
		return nil, fmt.Errorf("tunhandshake: 密钥导出失败(TLS exporter): %w", err)
	}
	return key, nil
}

// peerIdentity 从已认证对端证书取 (tenant, site):tenant=Subject.Organization(W9)、site=CommonName。
func peerIdentity(cs tls.ConnectionState) (tenant, site string, err error) {
	if len(cs.PeerCertificates) == 0 {
		return "", "", fmt.Errorf("tunhandshake: 对端无证书(须 mutual TLS)")
	}
	peer := cs.PeerCertificates[0]
	t, ok := devpki.TenantFromCert(peer)
	if !ok || t == "" {
		return "", "", fmt.Errorf("tunhandshake: 对端证书无租户(非 ZTP 绑定证书)")
	}
	if peer.Subject.CommonName == "" {
		return "", "", fmt.Errorf("tunhandshake: 对端证书无 site(CommonName 空)")
	}
	return t, peer.Subject.CommonName, nil
}

// Established 是 PoP 侧一次成功握手的产物(供建 Session + 登记 Router)。
type Established struct {
	Tenant      string
	Site        string
	Alg         string
	Key         []byte
	CPEDataAddr *net.UDPAddr // CPE 数据面 UDP 地址(PoP 回程目的;非 NAT 下 == 数据报 srcAddr)

	// Claims 是握手时刻验过的会话凭证声明(仅 ZTNA 形态:Server 配了 verifyCred hook 才填;
	// SD-WAN 形态 hook 为 nil → 零值)。终结器据此连同 session/srcAddr 存入终结表(Slice77 L2 §3.1)。
	// **安全契约**:此字段仅在 Server 成功 Verify(签名+有效期)+ 交叉核对租户后才有值;Verify 失败的
	// 握手已被拒(连接关闭),绝不会以零值/未验证 Claims 透出。
	Claims cred.Claims
}

// Session 用本端方向构造 dptunnel 会话(PoP 侧:send=PoP→CPE、recv=CPE→PoP)。
func (e Established) Session() (*dptunnel.Session, error) {
	aead, err := dptunnel.NewAEAD(e.Alg, e.Key)
	if err != nil {
		return nil, err
	}
	return dptunnel.NewSession(aead, 0, dirPoPToCPE, dirCPEToPoP), nil // fecK=0:FEC 经 SiteConfig 下发,待后续刀
}

// Server 是 PoP 侧握手服务:接受 CPE 的 mutual-TLS 控制连接,认证身份、派生密钥,回调上层建会话/登记 Router。
type Server struct {
	popDataAddr   string            // 通告给 CPE 的 PoP 数据面 UDP 地址
	alg           string            // 算法档(控制面据租户策略定;不在握手协商,防降级)
	epoch         uint32            // 本刀恒 0;rekey/epoch 为后续刀(派生与 serverHello 通告须同源,见 handle 注释 B1)
	onEstablished func(Established) // 握手成功回调(上层建 Session + Router.Register)

	// verifyCred 是可选的会话凭证验证 hook(ZTNA 形态,Slice77):非 nil 时,handle 在取证书身份后、
	// onEstablished 前,用它对 clientHello.Cred 验签 + 有效期 + 撤销;返回的 Claims 须已与证书租户交叉核对、
	// fail-closed(返 error 即拒握手关连接)。nil(SD-WAN 形态)→ 不验 cred、行为与旧 NewServer 完全一致。
	// 入参 certTenant = 已认证证书的租户(Org/W9),供 hook 内交叉核对 claims.TenantID == certTenant。
	verifyCred func(certTenant, token string, now time.Time) (cred.Claims, error)
}

// NewServer 构造握手服务(SD-WAN 形态:不验 cred)。popDataAddr=PoP 数据面 UDP 地址;alg=算法档;
// onEstablished=成功回调。**保持现有 SD-WAN 调用点(cmd/pop-agent / cmd/cpe)编译/运行零改**。
func NewServer(popDataAddr, alg string, onEstablished func(Established)) *Server {
	return &Server{popDataAddr: popDataAddr, alg: alg, epoch: 0, onEstablished: onEstablished}
}

// NewServerWithCred 构造带会话凭证验证的握手服务(ZTNA 形态,Slice77 L2 §3.1)。
// verifyCred 不可为 nil(否则用 NewServer);它须 fail-closed 验签 + 有效期 + 撤销 + 交叉核对租户,
// 返 error 即拒握手。验过的 Claims 随 Established 透出供终结器逐流 PEP。
func NewServerWithCred(popDataAddr, alg string, onEstablished func(Established), verifyCred func(certTenant, token string, now time.Time) (cred.Claims, error)) *Server {
	return &Server{popDataAddr: popDataAddr, alg: alg, epoch: 0, onEstablished: onEstablished, verifyCred: verifyCred}
}

// Serve 在 ln(已配 mutual-TLS server 配置)上接受握手连接,直到 ctx 取消。
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("tunhandshake: accept: %w", err)
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	tc, ok := conn.(*tls.Conn)
	if !ok {
		return // ln 必须是 TLS listener
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return // TLS/证书校验失败(含撤销→证书过期→握手失败,有界撤销);conn 关闭使对端快速失败
	}
	cs := tc.ConnectionState()
	tenant, site, err := peerIdentity(cs)
	if err != nil {
		log.Printf("[tunhandshake] 拒绝握手(身份):%v", err) // 失败留痕,便于 SD-WAN 接入排障(B5)
		return
	}

	var ch clientHello
	if err := json.NewDecoder(conn).Decode(&ch); err != nil {
		log.Printf("[tunhandshake] 拒绝握手 site=%s:读 hello: %v", site, err)
		return
	}
	// 交叉核对:clientHello.Site 若提供,须与证书 CN 一致(权威仍是证书;不一致即拒,防客户端自述与身份矛盾,B2)。
	if ch.Site != "" && ch.Site != site {
		log.Printf("[tunhandshake] 拒绝握手:hello.site=%q 与证书 CN=%q 不符", ch.Site, site)
		return
	}
	// ZTNA 形态(Slice77 §3.1 入口闸):配了 verifyCred 即必须验会话凭证 —— 验签 + 有效期 + 交叉核对租户 +
	// 查吊销,全部 fail-closed(hook 返 error 即拒握手关连接,绝不以未验/零值 Claims 透出)。
	// SD-WAN 形态(verifyCred==nil)跳过本块,行为与旧 NewServer 一致;此时即便 CPE 误带 Cred 也不被消费。
	var claims cred.Claims
	if s.verifyCred != nil {
		c, verr := s.verifyCred(tenant, ch.Cred, time.Now())
		if verr != nil {
			// 失败不泄漏细节(签名/过期/撤销/租户不符统一拒),仅本地留痕便于排障。
			log.Printf("[tunhandshake] 拒绝 ZTNA 握手 tenant=%s site=%s:会话凭证校验失败: %v", tenant, site, verr)
			return
		}
		claims = c
	}
	cpeAddr, err := net.ResolveUDPAddr("udp", ch.DataAddr)
	if err != nil {
		log.Printf("[tunhandshake] 拒绝握手 tenant=%s site=%s:CPE 数据地址 %q 非法: %v", tenant, site, ch.DataAddr, err)
		return
	}
	// epoch 单一来源:本端派生与 serverHello 通告用同一 epoch(本刀恒 0;rekey/epoch 编排为后续刀,
	// 届时两端须仍同源,否则 KDF context 不一致→密钥不符→静默丢包,见 L2 §4.6,B1)。
	epoch := s.epoch
	key, err := deriveKey(cs, s.alg, epoch)
	if err != nil {
		log.Printf("[tunhandshake] 拒绝握手 tenant=%s site=%s:密钥导出: %v", tenant, site, err)
		return
	}
	// 先登记会话(Router.Register)再回 serverHello:确保 CPE 收到 hello 开始发数据时,PoP 已可解复用该会话,
	// 否则 CPE 早发的包因 bySrc 未命中被丢(竞态)。
	s.onEstablished(Established{Tenant: tenant, Site: site, Alg: s.alg, Key: key, CPEDataAddr: cpeAddr, Claims: claims})
	if err := json.NewEncoder(conn).Encode(serverHello{DataAddr: s.popDataAddr, Alg: s.alg, Epoch: epoch}); err != nil {
		return
	}
}

// Result 是 CPE 侧一次成功握手的产物(供建 Session + Endpoint)。
type Result struct {
	Tenant      string
	Site        string
	Alg         string
	Key         []byte
	PoPDataAddr *net.UDPAddr // PoP 数据面 UDP 地址(CPE 数据报目的)
}

// Session 用本端方向构造 dptunnel 会话(CPE 侧:send=CPE→PoP、recv=PoP→CPE)。
func (r Result) Session() (*dptunnel.Session, error) {
	aead, err := dptunnel.NewAEAD(r.Alg, r.Key)
	if err != nil {
		return nil, err
	}
	return dptunnel.NewSession(aead, 0, dirCPEToPoP, dirPoPToCPE), nil
}

// Dial 是 CPE 侧(SD-WAN 形态):用 ZTP 设备证书向 PoP 发起 mutual-TLS 握手,派生数据面密钥。
//
//	handshakeAddr = PoP 握手 TCP 地址;tlsConf = 设备 mTLS 客户端配置(含 ZTP 证书 + 验 PoP);
//	alg = 期望算法档(控制面下发,与 PoP 校验防降级);myDataAddr = CPE 数据面 UDP 本地地址;
//	tenant/site = 本端身份(供 PoP 交叉核对;权威仍是证书)。
//
// **SD-WAN 调用点(cmd/cpe / agentd SD-WAN 路径)签名零改**:不携会话凭证(PoP 也不验)。
func Dial(ctx context.Context, handshakeAddr string, tlsConf *tls.Config, alg, myDataAddr, tenant, site string) (Result, error) {
	return DialWithCred(ctx, handshakeAddr, tlsConf, alg, myDataAddr, tenant, site, "")
}

// DialWithCred 是 CPE/Agent 侧:同 Dial,但在 clientHello 携带会话凭证 token(ZTNA 形态,Slice77)。
// PoP 端配了 verifyCred hook 时会对其验签 + 有效期 + 交叉核对租户 + 查吊销;cred 空 → 等价 Dial(SD-WAN)。
func DialWithCred(ctx context.Context, handshakeAddr string, tlsConf *tls.Config, alg, myDataAddr, tenant, site, sessionTok string) (Result, error) {
	d := tls.Dialer{Config: tlsConf}
	dctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", handshakeAddr)
	if err != nil {
		return Result{}, fmt.Errorf("tunhandshake.Dial: 连 PoP %s: %w", handshakeAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	tc := conn.(*tls.Conn)
	cs := tc.ConnectionState()

	if err := json.NewEncoder(conn).Encode(clientHello{DataAddr: myDataAddr, Site: site, Cred: sessionTok}); err != nil {
		return Result{}, fmt.Errorf("tunhandshake.Dial: 发 hello: %w", err)
	}
	var sh serverHello
	if err := json.NewDecoder(conn).Decode(&sh); err != nil {
		return Result{}, fmt.Errorf("tunhandshake.Dial: 收 hello: %w", err)
	}
	if sh.Alg != alg { // 防降级:PoP 通告档须与控制面下发档一致(攻击者无法把国密租户降到非国密)
		return Result{}, fmt.Errorf("tunhandshake.Dial: 算法档不符(期望 %q,PoP 通告 %q)", alg, sh.Alg)
	}
	popAddr, err := net.ResolveUDPAddr("udp", sh.DataAddr)
	if err != nil {
		return Result{}, fmt.Errorf("tunhandshake.Dial: 解析 PoP 数据地址 %q: %w", sh.DataAddr, err)
	}
	key, err := deriveKey(cs, sh.Alg, sh.Epoch)
	if err != nil {
		return Result{}, err
	}
	return Result{Tenant: tenant, Site: site, Alg: sh.Alg, Key: key, PoPDataAddr: popAddr}, nil
}
