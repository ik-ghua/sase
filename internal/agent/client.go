// Package agent 是客户端 Agent 的最小实现(携凭证向 PoP 接入面发起应用访问)。
// 后续刀(客户端 Agent/Connector L2)接 enroll/姿态采集/选路/隧道(加密栈待 PoC-G)。
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// maxRespBody 是 Agent 读 PoP 响应体的上限,防超大响应撑爆内存(本刀非流式)。
const maxRespBody = 16 << 20 // 16 MiB

// Result 是一次 ZTNA 访问的完整响应(状态码 + 头 + 体)。
type Result struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Request 描述一次 ZTNA 应用访问:目标 app、目标 path、HTTP 方法、请求头、请求体。
// Method 空则 GET;Path 空则 "/"。Header/Body 透传到内网上游(PoP 剥除 Authorization/逐跳头)。
type Request struct {
	App    string
	Path   string
	Method string
	Header http.Header
	Body   []byte
}

// Do 携凭证 token 向 PoP 接入面发起任意 HTTP 方法 + 头 + 体的应用访问,返回完整响应(状态码/头/体)。
// tlsConf 为到 PoP 的 mTLS 客户端配置(设备级 transport 认证;token 为 app 层会话凭证认证)。
func Do(ctx context.Context, popURL string, tlsConf *tls.Config, token string, ar Request) (Result, error) {
	u, err := url.Parse(popURL)
	if err != nil {
		return Result{}, fmt.Errorf("agent: 解析 PoP url: %w", err)
	}
	u.Path = "/access"
	q := url.Values{"app": {ar.App}}
	if ar.Path != "" {
		q.Set("path", ar.Path)
	}
	u.RawQuery = q.Encode()

	method := ar.Method
	if method == "" {
		method = http.MethodGet
	}
	var reqBody io.Reader
	if len(ar.Body) > 0 {
		reqBody = bytes.NewReader(ar.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return Result{}, fmt.Errorf("agent: 构造请求: %w", err)
	}
	// 透传应用请求头(PoP 侧会剥 Authorization/逐跳头);随后设 SASE 凭证(覆盖任何同名头)。
	for k, vals := range ar.Header {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("agent: 请求 PoP: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if err != nil {
		return Result{StatusCode: resp.StatusCode, Header: resp.Header}, fmt.Errorf("agent: 读响应: %w", err)
	}
	return Result{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// Access 是 Do 的 GET 便捷封装(向后兼容:携凭证 GET app 的 path,返回状态码与响应体字符串)。
func Access(ctx context.Context, popURL string, tlsConf *tls.Config, token, app, path string) (int, string, error) {
	res, err := Do(ctx, popURL, tlsConf, token, Request{App: app, Path: path})
	if err != nil {
		return res.StatusCode, string(res.Body), err
	}
	return res.StatusCode, string(res.Body), nil
}
