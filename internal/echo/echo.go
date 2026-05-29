// Package echo 是 Slice 3 端到端的目标应用(私网内的最小 HTTP 应用,被 Connector 代理)。
package echo

import (
	"fmt"
	"net/http"
)

// Handler 返回一个回显请求行的最小应用,用于验证数据路径确实抵达应用。
func Handler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "echo[%s]: %s %s", name, r.Method, r.URL.Path)
	})
}
