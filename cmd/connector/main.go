// Command connector 是 App Connector(出站反向):拨出连到 PoP 注册 (tenant,app),
// 把 PoP 反向送来的请求代理到本地上游应用。私网无入站开口。
// 用法:POP_CONNECTOR_ADDR=127.0.0.1:7000 SASE_TLS_DIR=./certs TENANT=<uuid> APP=app1 UPSTREAM_URL=http://127.0.0.1:9000 connector
//
// ZTP 入网(推荐):设 ZTP_CODE=<激活码>(+ MGMT_URL=https://<mgmt>:8443),则本地生成密钥+CSR 向管理面
// 换取租户绑定证书(私钥永不离开),证书租户即 TENANT;不设则回退 dev 共享证书。
package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/revtunnel"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("connector: %v", err)
	}
}

func run() error {
	popAddr := envMust("POP_CONNECTOR_ADDR")
	tenant := envMust("TENANT")
	app := envMust("APP")
	upstream := envMust("UPSTREAM_URL")
	tlsDir := envOr("SASE_TLS_DIR", "./certs")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ZTP_CODE 非空走 ZTP 取租户绑定证书(身份=app),否则回退 dev 共享证书
	ztpCode := os.Getenv("ZTP_CODE")
	mgmtURL := envOr("MGMT_URL", "https://localhost:8443")
	tlsConf, rotator, err := enroll.DeviceTLS(ctx, tlsDir, mgmtURL, "localhost", ztpCode, app)
	if err != nil {
		return err
	}
	if rotator != nil {
		log.Printf("[connector] tenant=%s app=%s 已 ZTP 取证书(租户绑定),启动自动续期", tenant, app)
		renewURL := envOr("DEVICE_URL", "https://localhost:8444")
		go enroll.RunRenewLoop(ctx, rotator, renewURL, tlsDir, "localhost", app, 8*time.Hour)
	}
	log.Printf("[connector] tenant=%s app=%s 拨出 PoP %s(mTLS),上游 %s", tenant, app, popAddr, upstream)
	handler := func(req revtunnel.Request) revtunnel.Response {
		return proxy(ctx, upstream, req)
	}
	// 重连循环 + 每连接最长存活(< 证书有效期):周期性重握手,使续期后的新证书生效、且设备被撤销后
	// 旧证书过期即在重握手时被拒(撤销在 ≤连接寿命+证书剩余期内生效;否则长连接永不重握手会绕过撤销)。
	serveLoop(ctx, connMaxAge(), func(connCtx context.Context) error {
		return revtunnel.Serve(connCtx, popAddr, tlsConf, revtunnel.Hello{Tenant: tenant, App: app}, handler)
	})
	return nil
}

// serveLoop 反复拨出:每条连接限活 maxAge(到点主动断开重连,强制重握手取最新证书),断开后退避重连,
// 直到父 ctx 取消。
func serveLoop(ctx context.Context, maxAge time.Duration, serve func(context.Context) error) {
	for ctx.Err() == nil {
		connCtx, cancel := context.WithTimeout(ctx, maxAge)
		err := serve(connCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("[connector] 连接断开,重连: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second): // 退避,避免拨号失败时空转
		}
	}
}

// connMaxAge 取每连接最长存活(默认 1h,须 < ZTP 证书有效期以保证撤销有界生效)。
func connMaxAge() time.Duration {
	if v := os.Getenv("CONN_MAX_AGE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

// proxy 把反向请求(全 HTTP:方法 + 头 + 体)转发到本地上游应用,回填完整响应(状态码 + 头 + 体)。
// body 整包缓冲(本刀非流式)。method 缺省 GET(兼容旧帧)。
func proxy(ctx context.Context, upstream string, req revtunnel.Request) revtunnel.Response {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	var reqBody io.Reader
	if len(req.Body) > 0 {
		reqBody = bytes.NewReader(req.Body)
	}
	r, err := http.NewRequestWithContext(ctx, method, upstream+req.Path, reqBody)
	if err != nil {
		return revtunnel.Response{Status: http.StatusBadGateway, Err: err.Error()}
	}
	// 透传请求头:优先多值 HeaderFull,回退单值 Header(旧帧/站点 overlay)。
	if len(req.HeaderFull) > 0 {
		for k, vals := range req.HeaderFull {
			for _, v := range vals {
				r.Header.Add(k, v)
			}
		}
	} else {
		for k, v := range req.Header {
			r.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return revtunnel.Response{Status: http.StatusBadGateway, Err: err.Error()}
	}
	defer resp.Body.Close()
	// 上游响应体限额缓冲,防恶意/超大上游响应撑爆连接器内存(对称 PoP 侧 16 MiB)。
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody))
	if err != nil {
		return revtunnel.Response{Status: http.StatusBadGateway, Err: err.Error()}
	}
	// 回填完整响应:StatusCode/Header/BodyBytes(全 HTTP);保留 Body=string(body) 兼容旧读取方。
	return revtunnel.Response{
		Status:    resp.StatusCode,
		Header:    resp.Header.Clone(),
		BodyBytes: body,
		Body:      string(body),
	}
}

// maxProxyBody 是连接器缓冲上游响应体的上限(本刀非流式)。
const maxProxyBody = 16 << 20 // 16 MiB

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envMust(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("connector: 须设环境变量 %s", k)
	}
	return v
}
