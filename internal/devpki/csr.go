package devpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ZTP 证书把租户编进 Subject.Organization、身份(site_key/connector)编进 CommonName,
// PoP 侧从对端 mTLS 证书提取租户做注册身份校验(W9)。私钥由设备本地生成(CSR 流程),永不离开。

// GenerateCSR 在设备侧本地生成密钥对 + CSR(CommonName=身份),返回 csr/key PEM。私钥不离开设备。
func GenerateCSR(cn string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// ValidateCSR 解析并校验 CSR 自签名(供签发前预检,使无效 CSR 不浪费一次性激活码)。
func ValidateCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		return nil, fmt.Errorf("devpki: CSR PEM 解析失败")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("devpki: 解析 CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("devpki: CSR 自签名校验失败: %w", err)
	}
	return csr, nil
}

// 节点角色(编进证书 Subject.OU,前缀 role:)。基础设施(PoP)绑角色、客户边缘(CPE/Connector)绑角色+租户。
// 角色用于服务端按角色授权(W11:遥测端点只收 PoP 角色),与 tenant 绑定(W9)是两个正交维度。
const (
	RolePoP    = "pop"    // 多租户共享基础设施节点(受信代任意租户上报/操作)
	RoleDevice = "device" // 客户边缘设备(CPE/Connector,单租户)
	rolePrefix = "role:"
)

// RoleFromCert 从证书 Subject.OU 提取角色(无 role: 标记 → ("",false))。
func RoleFromCert(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if len(ou) > len(rolePrefix) && ou[:len(rolePrefix)] == rolePrefix {
			return ou[len(rolePrefix):], true
		}
	}
	return "", false
}

// SignCSR 签发**设备角色**客户端证书(ZTP:CPE/Connector):tenant 进 Organization、cn 进 CN、role:device 进 OU。
func (ca *CA) SignCSR(csrPEM []byte, tenant, cn string) (certPEM []byte, err error) {
	return ca.signClient(csrPEM, tenant, cn, RoleDevice)
}

// SignPoP 签发 **PoP 角色**客户端证书(基础设施节点,无租户绑定):cn 进 CN、role:pop 进 OU。
func (ca *CA) SignPoP(csrPEM []byte, cn string) (certPEM []byte, err error) {
	return ca.signClient(csrPEM, "", cn, RolePoP)
}

// signClient 签发客户端证书:校验 CSR 自签名;tenant 非空进 Organization、role 非空进 OU(role:<role>)、cn 进 CN。
func (ca *CA) signClient(csrPEM []byte, tenant, cn, role string) ([]byte, error) {
	csr, err := ValidateCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	subj := pkix.Name{CommonName: cn}
	if tenant != "" {
		subj.Organization = []string{tenant} // 租户绑定(W9)
	}
	if role != "" {
		subj.OrganizationalUnit = []string{rolePrefix + role} // 角色绑定(W11)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subj,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("devpki: 签发证书: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// TenantFromCert 从证书 Subject.Organization 提取租户(ZTP 证书有,dev 共享证书无)。
func TenantFromCert(cert *x509.Certificate) (string, bool) {
	if cert == nil || len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] == "" {
		return "", false
	}
	return cert.Subject.Organization[0], true
}

// LoadCA 从目录加载 ca.crt + ca.key,供控制面 ZTP 签发(生产应改 PoP CA + HSM)。
func LoadCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("devpki: 读 ca.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("devpki: 读 ca.key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("devpki: ca.crt/ca.key PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("devpki: ca.key 非 ecdsa")
	}
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// CAKeyPEM 返回 CA 私钥 PKCS8 PEM(供 WritePEM 持久化;dev 用,生产 CA 私钥应入 HSM 永不导出)。
func (ca *CA) CAKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
