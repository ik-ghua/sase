package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/ikuai8/sase/internal/data"
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

// writeValidationOr500 为 create handler 收敛 4xx/5xx 错误码治理(Slice73,接续 Slice72 5xx 脱敏):
//
// 背景:createSite/createApp/createConnector 此前对 svc 返回的**所有**错误一律
// `http.Error(w, err.Error(), 400)` —— ① 把 DB 错误也误报 400;② err.Error() 直出可能泄漏内层细节。
//
// 分流(参照 Slice66 writeRuleError 模式):
//   - errors.Is(err, invalid) → 400 + 回显该校验文案(校验信息对调用方有用且安全);
//   - data.IsUniqueViolation(err) → 409 + 安全通用文案(site_key / app_key 等唯一冲突);
//   - 其余(DB/内部错)→ writeInternalErr(500 脱敏:log 保留细节,响应只给通用文案)。
//
// invalid 为各模块的输入校验哨兵(site.ErrInvalidSite / resource.ErrInvalidResource)。
// where 给出可定位的 handler 名(如 "createSite")。
//
// ⚠️ 安全契约(显式化):400 分支回显完整 err.Error()(含校验细节如非法 CIDR 字面量,对调用方有用)。
// 这只在「invalid 哨兵的错误链内永不含 DB/内部错(pgx/SQLSTATE/schema)」前提下安全——
// 故各模块务必只对**触达 DB 之前**的纯输入校验错 wrap invalid 哨兵,DB 错绝不 wrap(留给 default→500 脱敏)。
// 若未来有人把某类 DB/约束违例包进 invalid 哨兵想当 400 回显,err.Error() 直出即泄漏底层细节——禁止。
func writeValidationOr500(w http.ResponseWriter, where string, err error, invalid error) {
	switch {
	case errors.Is(err, invalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case data.IsUniqueViolation(err):
		http.Error(w, "资源已存在(唯一键冲突)", http.StatusConflict)
	default:
		writeInternalErr(w, where, err)
	}
}
