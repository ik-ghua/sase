// Command agent 是客户端 Agent(携凭证向 PoP 接入面请求访问应用,经 mTLS;打印结果)。
// 用法:POP_URL=https://127.0.0.1:8081 SASE_TLS_DIR=./certs TOKEN=<cred> APP=app1 agent
package main

import (
	"context"
	"log"
	"os"

	"github.com/ikuai8/sase/internal/agent"
	"github.com/ikuai8/sase/internal/devpki"
)

func main() {
	popURL := envOr("POP_URL", "https://127.0.0.1:8081")
	tlsDir := envOr("SASE_TLS_DIR", "./certs")
	token := os.Getenv("TOKEN")
	app := envOr("APP", "app1")
	path := envOr("PATH_", "/")
	if token == "" {
		log.Fatal("agent: 须设 TOKEN=<会话凭证>")
	}

	tlsConf, err := devpki.LoadDeviceClientTLS(tlsDir, "localhost") // 边缘设备角色证书(role:device)
	if err != nil {
		log.Fatalf("agent: 加载 mTLS(%s): %v", tlsDir, err)
	}
	status, body, err := agent.Access(context.Background(), popURL, tlsConf, token, app, path)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	log.Printf("[agent] app=%s → HTTP %d: %s", app, status, body)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
