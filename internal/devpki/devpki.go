// Package devpki 是开发/测试用最小 PKI:自签 CA + 签发 server/client 证书,产 mTLS 的 tls.Config。
//
// 用途:Slice 4 让 PoP↔xds-server 走 mTLS(xDS server L2 3.9:PoP 经 mTLS 接入)。
// 仅开发/测试;生产 PoP 证书由 PoP CA 签发、私钥经 KMS/HSM(L1 3.5),非本包职责。
package devpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CA 是自签根。
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// NewCA 生成自签 CA。
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sase-dev-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// CertPEM 返回 CA 证书 PEM(供对端做信任根)。
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// issue 签发叶子证书,返回 cert/key PEM。
func (ca *CA) issue(cn string, isServer bool, dnsNames []string, role string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	subj := pkix.Name{CommonName: cn}
	if role != "" {
		subj.OrganizationalUnit = []string{rolePrefix + role} // 角色绑定(W11),供服务端按角色授权
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subj,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     dnsNames,
	}
	if isServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func (ca *CA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(ca.certPEM)
	return p
}

// ServerTLS 产 xds-server 的 mTLS 配置:出示 server 证书 + 强制校验 client 证书(由本 CA 签发)。
func (ca *CA) ServerTLS(dnsNames ...string) (*tls.Config, error) {
	certPEM, keyPEM, err := ca.issue("xds-server", true, dnsNames, "")
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool(),
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ServerTLSServerOnly 产**单向** server-TLS 配置(不要求客户端证书),用于管理面 HTTPS:
// 客户端为控制台/操作员(浏览器),transport 验服务端、身份由 app 层(RBAC/会话)认证,非设备 mTLS。
func (ca *CA) ServerTLSServerOnly(dnsNames ...string) (*tls.Config, error) {
	certPEM, keyPEM, err := ca.issue("admin-server", true, dnsNames, "")
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLS 产 PoP 的 mTLS 配置:出示 client 证书 + 以本 CA 验 server。serverName 须与 server 证书 SAN 匹配。
func (ca *CA) ClientTLS(serverName string) (*tls.Config, error) {
	certPEM, keyPEM, err := ca.issue("pop-agent", false, nil, "")
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca.pool(),
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// WritePEM 把 CA/server/client 材料写到目录(供 cmd 用文件加载;返回错误便于脚本化)。
func (ca *CA) WritePEM(dir string, writer func(name string, pemBytes []byte) error) error {
	srvCert, srvKey, err := ca.issue("xds-server", true, []string{"localhost", "xds-server"}, "")
	if err != nil {
		return err
	}
	cliCert, cliKey, err := ca.issue("pop-agent", false, nil, "")
	if err != nil {
		return err
	}
	// PoP 角色客户端证书(role:pop):pop-agent 连遥测端点用(W11 角色门控 require-pop-role 开启时须持此证书)。
	// dev 用;生产应由 PoP 入网/provisioning 签发(角色化 PKI),CA 私钥入 HSM。
	popCert, popKey, err := ca.issue("pop-agent", false, nil, RolePoP)
	if err != nil {
		return err
	}
	// 设备角色客户端证书(role:device):边缘 Connector/CPE/Agent 用(把共享 client.crt 按角色拆开)。
	// 生产边缘走 ZTP 签发(带租户的 role:device);此为 dev 非 ZTP 兜底。
	devCert, devKey, err := ca.issue("device", false, nil, RoleDevice)
	if err != nil {
		return err
	}
	// 持久化 CA 私钥,供控制面 ZTP 端点签发设备证书(LoadCA);dev 用,生产 CA 私钥应入 HSM 永不导出。
	caKey, err := ca.CAKeyPEM()
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"ca.crt": ca.certPEM, "ca.key": caKey, "server.crt": srvCert, "server.key": srvKey,
		"client.crt": cliCert, "client.key": cliKey, // role-less,仅兜底(角色拆分后由 pop/device 取代)
		"pop.crt": popCert, "pop.key": popKey, // role:pop(PoP 基础设施)
		"device.crt": devCert, "device.key": devKey, // role:device(边缘 Connector/CPE/Agent)
	}
	for name, b := range files {
		if err := writer(fmt.Sprintf("%s/%s", dir, name), b); err != nil {
			return err
		}
	}
	return nil
}
