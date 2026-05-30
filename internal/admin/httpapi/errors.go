package httpapi

import (
	"log"
	"net/http"
)

// writeInternalErr 统一收敛 5xx 内部错误的脱敏处理(承接 Slice71 P2 reviewer B1:listSites 范本)。
//
// 背景:此前各 handler 直接 `http.Error(w, err.Error(), 500)`,把原始内部错误
// (可能含 DB schema / pgx 细节 / RLS 内幕)直接回给客户端,构成信息泄漏面。
//
// 处理:
//   - 服务端 `log.Printf` 保留真实 err(带 where 上下文供排障定位);
//   - 客户端只得通用文案 "internal error",不泄漏任何内部细节。
//
// where 给出可定位的 handler/动作名(如 "createTenant" / "listUsers")。
// 仅用于 500 路径;4xx(回显校验/sentinel)与 503(依赖未就绪)保持各自原有文案。
func writeInternalErr(w http.ResponseWriter, where string, err error) {
	log.Printf("[admin] %s 内部错误: %v", where, err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
