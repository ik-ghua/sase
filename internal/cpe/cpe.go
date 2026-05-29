// Package cpe 是 SD-WAN 软件 CPE(客户分支站点边缘,跑客户硬件/虚机的 Go agent,L2 sdwan-cpe)。
//
// Slice 范围(薄边缘):订阅 SiteConfig 知对端站点(SiteStore)+ 向对端站点发流量(SendToSite,经 PoP overlay)。
// 站点的「终结侧」(收 PoP 反向流量并交本地 LAN)复用 revtunnel.Serve(以 site_key 注册为连接器)。
// WAN 多链路探测/亚秒切换/FEC/ZTP-CSR/隧道国密加密等留后续刀(L2 sdwan-cpe 3.2-3.6,加密待 PoC-G)。
package cpe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/ikuai8/sase/internal/pop"
)

// SiteStore 持本 CPE 已知的同租户对端站点(由 SiteConfig 订阅回调整体替换;真实 CPE 据此对 LAN 流量选路)。
type SiteStore struct {
	mu    sync.RWMutex
	sites []pop.SiteInfo
}

func NewSiteStore() *SiteStore { return &SiteStore{} }

// Set 整体替换站点清单。
func (s *SiteStore) Set(sites []pop.SiteInfo) {
	s.mu.Lock()
	s.sites = sites
	s.mu.Unlock()
}

// Sites 返回当前站点清单副本。
func (s *SiteStore) Sites() []pop.SiteInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]pop.SiteInfo, len(s.sites))
	copy(out, s.sites)
	return out
}

// SendToSite 把流量经 PoP overlay 发往对端站点 destSite 的资源 path(模拟站点 LAN 出向流量的 overlay 转发)。
// tlsConf 为到 PoP 的 mTLS;token 为 CPE 会话凭证(ZTP 签发,标识本站点)。
func SendToSite(ctx context.Context, popURL string, tlsConf *tls.Config, token, destSite, path string) (int, string, error) {
	u, err := url.Parse(popURL)
	if err != nil {
		return 0, "", fmt.Errorf("cpe: 解析 PoP url: %w", err)
	}
	u.Path = "/site"
	q := url.Values{"dest": {destSite}}
	if path != "" {
		q.Set("path", path)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, "", fmt.Errorf("cpe: 构造请求: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("cpe: 请求 PoP overlay: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("cpe: 读响应: %w", err)
	}
	return resp.StatusCode, string(body), nil
}
