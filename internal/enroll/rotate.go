package enroll

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/ikuai8/sase/internal/devpki"
)

// CertRotator 持设备当前 ZTP 证书,供 tls.Config.GetClientCertificate 每次握手取用。续期后 Set 原子替换,
// 在用连接不受影响、下次重连即用新证书(热轮换)。
type CertRotator struct {
	mu   sync.RWMutex
	cert tls.Certificate
	leaf *x509.Certificate
}

// NewCertRotator 用初始证书/密钥 PEM 构造。
func NewCertRotator(certPEM, keyPEM []byte) (*CertRotator, error) {
	r := &CertRotator{}
	if err := r.Set(certPEM, keyPEM); err != nil {
		return nil, err
	}
	return r, nil
}

// Set 原子**整体替换**当前证书(永不就地改 r.cert 的字段)。GetClientCertificate 返回的旧快照因此
// 不会被并发改动,无 data race——此不变量勿破(切勿为省分配而复用底层切片)。
func (r *CertRotator) Set(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("enroll.CertRotator: 证书/密钥配对: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("enroll.CertRotator: 解析叶证书: %w", err)
	}
	r.mu.Lock()
	r.cert, r.leaf = cert, leaf
	r.mu.Unlock()
	return nil
}

// GetClientCertificate 供 tls.Config 回调,返回当前证书(每次握手调用 → 重连自动用最新证书)。
func (r *CertRotator) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c := r.cert
	return &c, nil
}

// NotAfter 返回当前证书到期时刻。
func (r *CertRotator) NotAfter() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.leaf.NotAfter
}

// RotatingClientTLS 产以 CertRotator 为客户端证书来源的 mTLS 配置(信任锚取自 dir/ca.crt)。
func RotatingClientTLS(rotator *CertRotator, dir, serverName string) (*tls.Config, error) {
	cfg, err := devpki.ClientTLSServerOnly(dir, serverName) // 复用:RootCAs + ServerName
	if err != nil {
		return nil, err
	}
	cfg.GetClientCertificate = rotator.GetClientCertificate
	return cfg, nil
}

// DeviceTLS 为设备产 mTLS 配置:code 非空走 ZTP(取租户绑定证书,返回 CertRotator 支持热轮换),
// 否则回退 dev 共享证书(返回 rotator=nil,无轮换)。serverName 须匹配服务端证书 SAN(dev 均 localhost)。
func DeviceTLS(ctx context.Context, tlsDir, mgmtURL, serverName, code, cn string) (*tls.Config, *CertRotator, error) {
	if code == "" {
		cfg, err := devpki.LoadDeviceClientTLS(tlsDir, serverName) // 边缘设备角色证书(role:device);非 ZTP 兜底
		return cfg, nil, err
	}
	bootTLS, err := devpki.ClientTLSServerOnly(tlsDir, serverName) // 入网前以预置 CA 验管理面服务端
	if err != nil {
		return nil, nil, err
	}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: bootTLS}}
	certPEM, keyPEM, err := FetchCert(ctx, mgmtURL, hc, code, cn)
	if err != nil {
		return nil, nil, err
	}
	rotator, err := NewCertRotator(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := RotatingClientTLS(rotator, tlsDir, serverName)
	if err != nil {
		return nil, nil, err
	}
	return cfg, rotator, nil
}

// RunRenewLoop 在 ctx 存活期间周期性续期:当证书剩余有效期 < lead 时,经 mTLS(出示当前证书)续期并热替换。
// renewURL 为设备 mTLS 端点(如 https://host:8444);失败重试(下个周期),不退出。
func RunRenewLoop(ctx context.Context, rotator *CertRotator, renewURL, tlsDir, serverName, cn string, lead time.Duration) {
	renewTLS, err := RotatingClientTLS(rotator, tlsDir, serverName)
	if err != nil {
		log.Printf("[enroll] 续期循环初始化失败: %v", err)
		return
	}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: renewTLS}}
	for {
		// 睡到"剩余=lead"时刻;已不足 lead 则尽快续期(最短等 1 分钟,避免失败时打满)
		wait := time.Until(rotator.NotAfter().Add(-lead))
		if wait < time.Minute {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		certPEM, keyPEM, err := RenewCert(ctx, renewURL, hc, cn)
		if err != nil {
			log.Printf("[enroll] %s 续期失败(下周期重试): %v", cn, err)
			continue
		}
		if err := rotator.Set(certPEM, keyPEM); err != nil {
			log.Printf("[enroll] %s 续期证书装载失败: %v", cn, err)
			continue
		}
		log.Printf("[enroll] %s 证书已续期,新到期 %s", cn, rotator.NotAfter().Format(time.RFC3339))
	}
}
