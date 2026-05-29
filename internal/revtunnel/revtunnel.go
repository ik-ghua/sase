// Package revtunnel 是 App Connector 的出站反向通道(客户端 Agent/Connector L2:连接器出站反向)。
//
// 动机:私网侧的 App Connector 主动**拨出**连到 PoP 并保持长连;PoP 经这条已建立的连接把
// 用户请求**反向**送进私网到达应用——私网无需任何入站开口(零暴露面)。
//
// Slice 3 协议(最小):连接器拨出 → 发 Hello{tenant,app} 注册 → 之后该连接承载
// 请求/响应帧(PoP→连接器 Request,连接器→PoP Response),JSON 编码、串行往返(每连接一次一请求)。
// 加厚目标:多路复用(并发请求)、mTLS 认证连接器、国密隧道(待 PoC-G);本包协议形态可保留。
package revtunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/ikuai8/sase/internal/devpki"
)

// Hello 是连接器拨出后的注册信息。
type Hello struct {
	Tenant string `json:"tenant"`
	App    string `json:"app"`
}

// Request 是 PoP 经反向通道发给连接器的请求(slice:GET 语义,无 body)。
type Request struct {
	ID     uint64            `json:"id"`
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Header map[string]string `json:"header,omitempty"`
}

// Response 是连接器回给 PoP 的响应。
type Response struct {
	ID     uint64 `json:"id"`
	Status int    `json:"status"`
	Body   string `json:"body"`
	Err    string `json:"err,omitempty"`
}

var ErrNoConnector = errors.New("revtunnel: 该 (tenant,app) 无已注册连接器")

// ---- 连接器侧(出站) ----

// Serve 拨出连到 PoP 的连接器注册地址,注册 hello,然后循环处理 PoP 发来的请求,直到 ctx 取消或连接断开。
// handler 把反向请求代理到本地上游应用(返回响应)。tlsConf 非 nil 时走 mTLS(连接器设备级认证)。
func Serve(ctx context.Context, addr string, tlsConf *tls.Config, hello Hello, handler func(Request) Response) error {
	conn, err := dial(ctx, addr, tlsConf)
	if err != nil {
		return fmt.Errorf("revtunnel: 拨出 PoP %s: %w", addr, err)
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }() // ctx 取消即断连,解除阻塞读

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(hello); err != nil {
		return fmt.Errorf("revtunnel: 注册: %w", err)
	}
	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil // PoP 断开
		}
		resp := handler(req)
		resp.ID = req.ID
		if err := enc.Encode(resp); err != nil {
			return nil
		}
	}
}

// dial 按 tlsConf 选择明文/mTLS 拨号。
func dial(ctx context.Context, addr string, tlsConf *tls.Config) (net.Conn, error) {
	if tlsConf != nil {
		return (&tls.Dialer{Config: tlsConf}).DialContext(ctx, "tcp", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

// ---- PoP 侧(接受注册 + 反向请求) ----

// Registry 持各 (tenant,app) 的已注册连接器连接,供 PoP 反向 RoundTrip。
type Registry struct {
	mu                sync.Mutex
	routes            map[string]*connector
	requireCertTenant bool // 见 WithRequireCertTenant
}

// Option 配置 Registry。
type Option func(*Registry)

// WithRequireCertTenant 开启"证书必须带租户"的 fail-closed 模式(W9):拒绝任何 mTLS 证书未携租户
// (Subject.Organization 空)的注册。默认关闭(dev:容忍无租户的共享证书,向后兼容)。
//
// 生产必须开启——否则持本 CA 签发的任意无租户客户端证书(如 dev 共享 client.crt)即可注册任意
// hello.Tenant,W9 的注册身份绑定形同虚设。开启后,设备只能用 ZTP 签发(带租户)的证书注册。
func WithRequireCertTenant() Option {
	return func(r *Registry) { r.requireCertTenant = true }
}

func NewRegistry(opts ...Option) *Registry {
	r := &Registry{routes: map[string]*connector{}}
	for _, o := range opts {
		o(r)
	}
	return r
}

type connector struct {
	mu     sync.Mutex // 串行化往返(slice:一次一请求)
	enc    *json.Encoder
	dec    *json.Decoder
	conn   net.Conn
	nextID uint64
}

func key(tenant, app string) string { return tenant + "/" + app }

// peerCertTenant 从对端 mTLS 证书(已经 ServerTLS RequireAndVerifyClientCert 校验)提取所属租户。
// 非 TLS 连接或证书无租户标记(dev 共享证书)→ (",false),调用方不施加约束。
func peerCertTenant(conn net.Conn) (string, bool) {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "", false
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", false
	}
	return devpki.TenantFromCert(certs[0])
}

// Accept 在 lis 上接受连接器注册,直到 ctx 取消。每个连接读 Hello 后登记到 registry。
func (r *Registry) Accept(ctx context.Context, lis net.Listener) error {
	go func() { <-ctx.Done(); lis.Close() }()
	for {
		conn, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go r.register(conn)
	}
}

func (r *Registry) register(conn net.Conn) {
	dec := json.NewDecoder(conn)
	var hello Hello
	if err := dec.Decode(&hello); err != nil { // 读 Hello 同时完成 TLS 握手
		conn.Close()
		return
	}
	// W9:注册身份(Hello.Tenant)须 ⊆ mTLS 证书所属租户。ZTP 签发的 Connector/CPE 证书把 tenant
	// 编进 Subject.Organization;此处从已校验的对端证书取租户,拒绝自报租户与证书不符的注册,
	// 把注册身份从"客户端自报"收到"证书绑定"。
	certTenant, ok := peerCertTenant(conn)
	if !ok {
		// 证书无租户标记(dev 共享证书)。requireCertTenant 下 fail-closed 拒绝;否则向后兼容放行。
		if r.requireCertTenant {
			log.Printf("[revtunnel] 拒绝注册:mTLS 证书未携租户(require-cert-tenant 模式),Hello.tenant=%q", hello.Tenant)
			conn.Close()
			return
		}
	} else if certTenant != hello.Tenant {
		log.Printf("[revtunnel] 拒绝注册:Hello.tenant=%q 与 mTLS 证书租户=%q 不符", hello.Tenant, certTenant)
		conn.Close()
		return
	}
	c := &connector{enc: json.NewEncoder(conn), dec: dec, conn: conn}
	r.mu.Lock()
	if old := r.routes[key(hello.Tenant, hello.App)]; old != nil {
		old.conn.Close() // 替换旧连接器
	}
	r.routes[key(hello.Tenant, hello.App)] = c
	r.mu.Unlock()
}

// RoundTrip 把请求经 (tenant,app) 的连接器反向送达并取回响应。无连接器 → ErrNoConnector。
func (r *Registry) RoundTrip(tenant, app string, req Request) (Response, error) {
	r.mu.Lock()
	c := r.routes[key(tenant, app)]
	r.mu.Unlock()
	if c == nil {
		return Response{}, ErrNoConnector
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	req.ID = c.nextID
	if err := c.enc.Encode(req); err != nil {
		r.evict(tenant, app, c)
		return Response{}, fmt.Errorf("revtunnel: 发请求: %w", err)
	}
	var resp Response
	if err := c.dec.Decode(&resp); err != nil {
		r.evict(tenant, app, c)
		return Response{}, fmt.Errorf("revtunnel: 读响应: %w", err)
	}
	return resp, nil
}

// evict 在连接出错时摘除该连接器(下次 RoundTrip 返回 ErrNoConnector)。
func (r *Registry) evict(tenant, app string, c *connector) {
	r.mu.Lock()
	if r.routes[key(tenant, app)] == c {
		delete(r.routes, key(tenant, app))
	}
	r.mu.Unlock()
	c.conn.Close()
}
