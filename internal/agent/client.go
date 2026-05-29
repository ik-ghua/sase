// Package agent 是客户端 Agent 的最小实现(Slice 3:携凭证向 PoP 接入面发起应用访问)。
// 后续刀(客户端 Agent/Connector L2)接 enroll/姿态采集/选路/隧道(加密栈待 PoC-G)。
package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Access 携凭证向 PoP 接入面请求访问应用 app 的资源 path(path 空则 "/"),返回 HTTP 状态码与响应体。
// tlsConf 为到 PoP 的 mTLS 客户端配置(设备级 transport 认证;凭证为 app 层认证)。
func Access(ctx context.Context, popURL string, tlsConf *tls.Config, token, app, path string) (int, string, error) {
	u, err := url.Parse(popURL)
	if err != nil {
		return 0, "", fmt.Errorf("agent: 解析 PoP url: %w", err)
	}
	u.Path = "/access"
	q := url.Values{"app": {app}}
	if path != "" {
		q.Set("path", path)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, "", fmt.Errorf("agent: 构造请求: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("agent: 请求 PoP: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("agent: 读响应: %w", err)
	}
	return resp.StatusCode, string(body), nil
}
