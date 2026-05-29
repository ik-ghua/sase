// Command echo-app 是 Slice 3 端到端的目标应用(私网内最小 HTTP 应用)。
// 用法:ADDR=:9000 NAME=app1 echo-app
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/ikuai8/sase/internal/echo"
)

func main() {
	addr := envOr("ADDR", ":9000")
	name := envOr("NAME", "app")
	log.Printf("[echo-app] %s listening on %s", name, addr)
	if err := http.ListenAndServe(addr, echo.Handler(name)); err != nil { //nolint:gosec // dev echo,无超时要求
		log.Fatalf("echo-app exited: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
