// Command xds-server 是控制面单元②(配置分发):go-control-plane ADS/Delta over mTLS gRPC,
// 读 DB 激活 PolicyBundle 下发给订阅的 PoP;LISTEN/NOTIFY 触发增量重建(xDS server L2)。
// 用法:SASE_DB_RW_DSN=... SASE_DB_RO_DSN=... SASE_TLS_DIR=./certs XDS_ADDR=:9090 xds-server
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/metrics"
	"github.com/ikuai8/sase/internal/xds"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("xds-server: %v", err)
	}
}

func run() error {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		return fmt.Errorf("须设 SASE_DB_RW_DSN/SASE_DB_RO_DSN")
	}
	tlsDir := envOr("SASE_TLS_DIR", "./certs")
	addr := envOr("XDS_ADDR", ":9090")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("接 DB: %w", err)
	}
	defer store.Close()

	tlsConf, err := devpki.LoadServerTLS(tlsDir)
	if err != nil {
		return fmt.Errorf("加载 mTLS(%s): %w", tlsDir, err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
	srv := xds.NewServer(ctx, store)
	rec := metrics.NewControlRecorder()
	srv.SetMetrics(rec)
	srv.Register(gs)

	// 可观测:/metrics(明文内部抓取,xDS 下发健康,运维 L2 3.10)
	go serveMetrics(ctx, envOr("METRICS_ADDR", ":9102"), rec.Handler())

	// LISTEN/NOTIFY:策略 bundle 变更 + 撤销变更 → 重读入对应缓存,增量下发(撤销走独立流)
	go func() {
		_ = data.ListenNotify(ctx, cfg.RWConnString, data.NotifyChannelPolicyBundle, srv.OnNotify)
	}()
	go func() {
		_ = data.ListenNotify(ctx, cfg.RWConnString, data.NotifyChannelRevocation, srv.OnRevocationNotify)
	}()
	go func() {
		_ = data.ListenNotify(ctx, cfg.RWConnString, data.NotifyChannelSWG, srv.OnSWGNotify)
	}()
	go func() {
		_ = data.ListenNotify(ctx, cfg.RWConnString, data.NotifyChannelSite, srv.OnSiteNotify)
	}()
	go func() {
		_ = data.ListenNotify(ctx, cfg.RWConnString, data.NotifyChannelFW, srv.OnFWNotify)
	}()
	go func() {
		_ = data.ListenNotify(ctx, cfg.RWConnString, data.NotifyChannelDLP, srv.OnDLPNotify)
	}()

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", addr, err)
	}
	go func() { <-ctx.Done(); gs.GracefulStop() }()
	log.Printf("[xds-server] ADS(mTLS)监听 %s", addr)
	return gs.Serve(lis)
}

func serveMetrics(ctx context.Context, addr string, h http.Handler) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", h)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Printf("[xds-server] /metrics 监听 %s", addr)
	if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
		log.Printf("[xds-server] /metrics 退出: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
