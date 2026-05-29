// Package booting 提供进程引导:依赖容器 + HTTP + 生命周期(优雅退出)。
// 后续按 Builder 扩展 WithDB/WithCache/WithProm(控制面 L2 总览 3.5)。
package booting

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"
)

// App 是进程级容器(Builder 风格)。承载 HTTP(可选 TLS)mux 与生命周期。
type App struct {
	name    string
	mux     *http.ServeMux
	tlsConf *tls.Config
}

// Option 配置 App。
type Option func(*App)

// WithTLS 让 Run 以 HTTPS 提供服务(管理面 TLS 收口)。
func WithTLS(conf *tls.Config) Option { return func(a *App) { a.tlsConf = conf } }

// New 构造容器。
func New(name string, opts ...Option) *App {
	a := &App{name: name, mux: http.NewServeMux()}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Mux 暴露路由注册点给各模块的 handler(模块边界:handler 只拿 Service 接口)。
func (a *App) Mux() *http.ServeMux { return a.mux }

// Run 启动 HTTP 服务并阻塞,收到 SIGINT/SIGTERM 后优雅退出。
func (a *App) Run(addr string) error {
	a.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{Addr: addr, Handler: a.mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: a.tlsConf}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownErr := make(chan error, 1)
	go func() {
		<-ctx.Done()
		// 优雅退出的超时 ctx 必须独立于已取消的信号 ctx(否则 Shutdown 立即中止)
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownErr <- srv.Shutdown(shutCtx) //nolint:contextcheck // 退出 ctx 独立于已取消的信号 ctx
	}()

	var serveErr error
	if a.tlsConf != nil {
		log.Printf("[%s] listening on %s (HTTPS)", a.name, addr)
		serveErr = srv.ListenAndServeTLS("", "") // 证书取自 TLSConfig
	} else {
		log.Printf("[%s] listening on %s", a.name, addr)
		serveErr = srv.ListenAndServe()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return <-shutdownErr
}
