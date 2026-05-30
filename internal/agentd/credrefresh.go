package agentd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// credStore 持守护进程当前会话凭证(token/jti/到期时刻),供 runTunnelOnce 每次握手取最新 + 刷新环阈值判定。
// RWMutex 原子整体替换(类比 enroll.CertRotator):Set 写锁、Token/ExpiresAt 读锁,多 goroutine 安全。
type credStore struct {
	mu        sync.RWMutex
	token     string
	jti       string
	expiresAt time.Time // 会话凭证到期时刻(刷新阈值 = expiresAt - refreshLead)
}

// Set 原子替换当前凭证(刷新成功 / 入网后填入)。
func (c *credStore) Set(token, jti string, expiresAt time.Time) {
	c.mu.Lock()
	c.token, c.jti, c.expiresAt = token, jti, expiresAt
	c.mu.Unlock()
}

// Token 返回当前会话凭证(每次握手取最新;空=未入网/无凭证)。
func (c *credStore) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// JTI 返回当前凭证 jti(撤销匹配用)。
func (c *credStore) JTI() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.jti
}

// ExpiresAt 返回当前凭证到期时刻(零值=未设)。
func (c *credStore) ExpiresAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.expiresAt
}

// refreshResponse 镜像 /api/v1/agent/session/refresh 的 JSON 响应。
type refreshResponse struct {
	SessionToken string `json:"session_token"`
	SessionJTI   string `json:"session_jti"`
	ExpiresIn    int    `json:"expires_in"`
}

// refreshCred 经设备 mTLS(出示当前租户绑定设备证书)POST /api/v1/agent/session/refresh,带当前 cred + 最新姿态
// (**body 不带 groups**:重签 groups 由控制面从验签 cred 取,防提权,§3.6.1)。类比 enroll.RenewCert。
// hc 须为出示设备证书的 mTLS 客户端(RotatingClientTLS,与续期同源)。
func refreshCred(ctx context.Context, refreshURL string, hc *http.Client, currentToken, posture string) (*refreshResponse, error) {
	body, err := json.Marshal(map[string]string{
		"current_cred_token": currentToken,
		"posture":            posture,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL+"/api/v1/agent/session/refresh", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agentd/cred 刷新请求: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 401(cred 失效)/403(设备撤销/用户停用):刷新失败,旧凭证将到 deadline 自然失效(权威在 PoP)。
		return nil, fmt.Errorf("agentd/cred 刷新返回 %d(凭证失效/设备撤销/用户停用)", resp.StatusCode)
	}
	var out refreshResponse
	if derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); derr != nil {
		return nil, fmt.Errorf("agentd/cred 解析刷新响应: %w", derr)
	}
	if out.SessionToken == "" {
		return nil, fmt.Errorf("agentd/cred 刷新响应缺会话凭证")
	}
	return &out, nil
}

// runCredRefreshLoop 在 ctx 存活期间周期性刷新会话凭证(类比 enroll.RunRenewLoop;仅 idp 模式启,ztp 不启)。
// 阈值触发(剩余 < refreshLead)→ refreshCred 成功 → store.Set(新 token/jti/exp) → **触发重握手**(向 reconnect
// 发信号,让当前 runTunnelOnce 返回 → retryLoop 用新 cred 重连)。失败重试不退出(降级:旧凭证到 deadline 失效)。
//
// posture 取自 d.posture.Latest()(最新姿态摘要;姿态非唯一门禁)。reconnect 缓冲为 1 的信号通道,非阻塞发
// (若上一信号未被消费,本次跳过——避免在 runTunnelOnce 未及消费时阻塞刷新 goroutine)。
func (d *Daemon) runCredRefreshLoop(ctx context.Context, store *credStore, hc *http.Client, refreshURL string, refreshLead time.Duration, reconnect chan<- struct{}) {
	if refreshLead <= 0 {
		refreshLead = 10 * time.Minute // 默认提前 10min(短于会话 TTL 30min)
	}
	// 失败/已过阈值的重试退避(防刷新端点不可达时打满)。测试可经 d.refreshRetryBackoff 缩短。
	retry := d.refreshRetryBackoff
	if retry <= 0 {
		retry = 30 * time.Second
	}
	for {
		// 睡到「剩余=refreshLead」时刻;已到/已过阈值(wait<=0)→ 用 retry 间隔兜底(防新凭证 TTL 异常短时打满)。
		wait := time.Until(store.ExpiresAt().Add(-refreshLead))
		if wait <= 0 {
			wait = retry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		posture := ""
		if d.posture != nil {
			if f, ok := d.posture.Latest(); ok {
				posture = f.Summary()
			}
		}
		resp, err := refreshCred(ctx, refreshURL, hc, store.Token(), posture)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[agentd/cred] 会话凭证刷新失败(退避后重试,旧凭证到期自然失效): %v", err)
			if sleepCtx(ctx, retry) { // 失败退避(防打满);ctx 取消即退
				return
			}
			continue
		}
		exp := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
		store.Set(resp.SessionToken, resp.SessionJTI, exp)
		log.Printf("[agentd/cred] 会话凭证已刷新 jti=%s,新到期 %s,触发重握手", resp.SessionJTI, exp.Format(time.RFC3339))
		// 触发重握手(非阻塞:让当前 runTunnelOnce select 到信号后返回,retryLoop 用新 cred 重连)。
		select {
		case reconnect <- struct{}{}:
		default: // 上一信号未消费 → 跳过(下次 runTunnelOnce 已会读最新 Token)
		}
	}
}

// expiresAtFromIn 据入网/刷新响应的 expires_in(秒)算到期时刻(<=0 → 用默认 30min 兜底,避免立即触发刷新风暴)。
func expiresAtFromIn(expiresIn int) time.Time {
	d := time.Duration(expiresIn) * time.Second
	if d <= 0 {
		d = 30 * time.Minute
	}
	return time.Now().Add(d)
}

// mTLSHTTPClient 用给定 tls.Config(出示设备证书)造刷新用 HTTP 客户端(类比 RunRenewLoop 内的 hc)。
func mTLSHTTPClient(tlsConf *tls.Config) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConf}}
}
