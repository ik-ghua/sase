package devpki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// LoadServerTLS 从目录加载 server.crt/server.key + ca.crt,产 mTLS 服务端配置(强制校验客户端证书)。
func LoadServerTLS(dir string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(dir+"/server.crt", dir+"/server.key")
	if err != nil {
		return nil, fmt.Errorf("devpki: 加载 server 证书: %w", err)
	}
	pool, err := loadPool(dir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// LoadServerTLSServerOnly 从目录加载 server.crt/server.key,产**单向** server-TLS 配置(不要求客户端证书),
// 用于管理面 HTTPS(客户端为控制台/操作员,身份由 app 层认证)。
func LoadServerTLSServerOnly(dir string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(dir+"/server.crt", dir+"/server.key")
	if err != nil {
		return nil, fmt.Errorf("devpki: 加载 server 证书: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// LoadClientTLS 从目录加载 client.crt/client.key + ca.crt,产 mTLS 客户端配置。
func LoadClientTLS(dir, serverName string) (*tls.Config, error) {
	return loadClientTLSFiles(dir, "client", serverName)
}

// LoadPoPClientTLS 加载 PoP 角色客户端证书(pop.crt/pop.key,role:pop)+ ca.crt,产 mTLS 配置。
// PoP 连遥测端点用——W11 角色门控开启时,控制面据此证书的 role:pop 授权(LoadClientTLS 的共享证书无角色会被拒)。
func LoadPoPClientTLS(dir, serverName string) (*tls.Config, error) {
	return loadClientTLSFiles(dir, "pop", serverName)
}

// LoadDeviceClientTLS 加载设备角色客户端证书(device.crt/device.key,role:device)+ ca.crt,产 mTLS 配置。
// 边缘 Connector/CPE/Agent 的非 ZTP 兜底用(生产边缘走 ZTP 签发的 role:device 证书)。
func LoadDeviceClientTLS(dir, serverName string) (*tls.Config, error) {
	return loadClientTLSFiles(dir, "device", serverName)
}

func loadClientTLSFiles(dir, base, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(dir+"/"+base+".crt", dir+"/"+base+".key")
	if err != nil {
		return nil, fmt.Errorf("devpki: 加载 %s 证书: %w", base, err)
	}
	pool, err := loadPool(dir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSFromPEM 用 ZTP 兑换得到的证书 PEM + 设备本地私钥 PEM 产 mTLS 客户端配置(CA 信任锚取自 dir/ca.crt)。
// 与 LoadClientTLS 区别:证书来自 ZTP 签发(带租户),而非目录里的共享 client.crt。
func ClientTLSFromPEM(certPEM, keyPEM []byte, dir, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("devpki: ZTP 证书/私钥配对: %w", err)
	}
	pool, err := loadPool(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSServerOnly 产**单向**客户端配置(只校验服务端,不出示客户端证书),用于设备 ZTP 入网前
// 连管理面 /enroll 取证书的引导连接——此时设备尚无 mTLS 证书,仅以预置的 CA 信任锚验管理面服务端。
func ClientTLSServerOnly(dir, serverName string) (*tls.Config, error) {
	pool, err := loadPool(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}, nil
}

func loadPool(caPath string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("devpki: 读 CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("devpki: CA 解析失败")
	}
	return pool, nil
}
