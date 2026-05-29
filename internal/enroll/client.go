package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ikuai8/sase/internal/devpki"
)

// FetchCert 是设备侧(Connector/CPE)的 ZTP 入网客户端:本地生成密钥对 + CSR(私钥永不离开设备),
// 凭激活码 POST 管理面 /api/v1/enroll 换取租户绑定证书,返回签发证书 PEM 与本地私钥 PEM。
//
// hc 须为已配好信任锚的 HTTPS 客户端(设备入网前以预置 CA 验管理面服务端,见 devpki.ClientTLSServerOnly)。
// baseURL 形如 https://<mgmt-host>:8443;cn 为设备身份(connector app / cpe site_key),须与入网记录一致。
func FetchCert(ctx context.Context, baseURL string, hc *http.Client, code, cn string) (certPEM, keyPEM []byte, err error) {
	csrPEM, keyPEM, err := devpki.GenerateCSR(cn) // 密钥+CSR 本地生成
	if err != nil {
		return nil, nil, fmt.Errorf("enroll.FetchCert 生成 CSR: %w", err)
	}
	body, err := json.Marshal(map[string]string{"activation_code": code, "csr_pem": string(csrPEM)})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll.FetchCert 请求: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("enroll.FetchCert: 管理面返回 %d(激活码无效/已兑换/CSR 非法)", resp.StatusCode)
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("enroll.FetchCert 解析响应: %w", err)
	}
	if out.CertPEM == "" {
		return nil, nil, fmt.Errorf("enroll.FetchCert: 响应无证书")
	}
	return []byte(out.CertPEM), keyPEM, nil
}

// RenewCert 是设备侧 ZTP 证书续期:本地生成新密钥+CSR(密钥轮换),经已建好的 mTLS 客户端(出示当前
// 有效证书)POST 管理面 /api/v1/renew 换取延期证书。tenant/identity 由服务端从出示的证书提取,故 hc
// 必须出示设备当前 ZTP 证书(见 RotatingClientTLS)。激活码不参与续期。
func RenewCert(ctx context.Context, renewURL string, hc *http.Client, cn string) (certPEM, keyPEM []byte, err error) {
	csrPEM, keyPEM, err := devpki.GenerateCSR(cn)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll.RenewCert 生成 CSR: %w", err)
	}
	body, err := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, renewURL+"/api/v1/renew", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll.RenewCert 请求: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("enroll.RenewCert: 管理面返回 %d(证书失效/设备已撤销/CSR 非法)", resp.StatusCode)
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("enroll.RenewCert 解析响应: %w", err)
	}
	if out.CertPEM == "" {
		return nil, nil, fmt.Errorf("enroll.RenewCert: 响应无证书")
	}
	return []byte(out.CertPEM), keyPEM, nil
}
