package audit

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/ikuai8/sase/internal/authz"
	"github.com/ikuai8/sase/internal/data"
)

// ActorMiddleware 把已认证 Principal 转成中性 data.Actor 注入 ctx,使业务事务(data.InTx)能设
// per-tx GUC app.current_actor[_role],供审计触发器 audit_row() 在业务事务内归因(审计事务化 L2 4.2)。
// 须置于 authz(注入 Principal)之后、业务 handler 之前;无 Principal 则不注入(触发器记 system)。
func ActorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := authz.FromContext(r.Context()); ok {
			ctx := data.WithActor(r.Context(), data.Actor{Subject: p.Subject, Role: p.Role})
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

const maxCaptureBytes = 4096

// Middleware 在 authz 之后记录**已授权的变更操作**(非 GET),source='api'。读取(GET)不记;失败鉴权请求由
// authz 在本中间件之前拒绝,故此处只见已授权请求(失败鉴权审计为后续项)。审计写用独立 ctx(不随请求取消)。
//
// 两层审计分工(审计事务化 L2 4.4):本中间件 = **API 动作级、best-effort 层**,记 HTTP 动作 + 结果码,
// 覆盖触发器看不到的「失败/无变更尝试」与「2xx 零变更」(故对所有变更请求都记,2xx/4xx/5xx 皆记 →
// 无 2xx-零变更盲区)。**原子的「凡变更必留痕」由 DB 触发器(source='data')保证**(migration 0012,
// 审计与业务同事务,业务回滚则审计回滚)——本层的「业务已提交但审计写失败」窗口对数据变更已被触发器消除,
// 本层 best-effort 失败仅丢失 API 动作视图(非权威),可接受。handler panic 路径不到此处(待最外层 recover 补)。
func Middleware(svc Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet { // 只审计变更
				next.ServeHTTP(w, r)
				return
			}
			cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r)

			p, ok := authz.FromContext(r.Context())
			if !ok {
				return // authz 必先于本中间件注入 principal;缺失则不记(防御性)
			}
			tid := tenantForAudit(r, cw.status, cw.body.String())
			if tid == "" {
				return // 无法归属租户(如失败的建租户)→ 跳过
			}
			e := Entry{
				TenantID:     tid,
				ActorSubject: p.Subject,
				ActorRole:    p.Role,
				Action:       r.Method + " " + r.URL.Path,
				Result:       cw.status,
				Source:       SourceAPI,
			}
			//nolint:contextcheck // 审计写独立于请求 ctx(客户端断开不应丢审计)
			if err := svc.Record(context.Background(), e); err != nil {
				log.Printf("[audit] 记录失败 action=%q tenant=%s: %v", e.Action, tid, err)
			}
		})
	}
}

// tenantForAudit 归属租户:租户作用域路径取 {tid}(成功失败均记,失败变更尝试也留痕);
// 建租户(POST /tenants)仅在 2xx 时从响应体取新建 id(失败建租户无可归属租户,跳过)。
func tenantForAudit(r *http.Request, status int, body string) string {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	if strings.HasPrefix(rest, "tenants/") {
		return strings.SplitN(rest[len("tenants/"):], "/", 2)[0]
	}
	if rest == "tenants" { // 建租户:仅成功(2xx)时按响应体新建 id 归属
		if status < 200 || status >= 300 {
			return ""
		}
		var t struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(body), &t)
		return t.ID
	}
	return ""
}

// captureWriter 截获响应状态码与(有上限的)响应体,响应体仅供建租户归属取 id(不落审计 detail)。
type captureWriter struct {
	http.ResponseWriter
	status      int
	body        strings.Builder
	wroteHeader bool
}

func (w *captureWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true // 隐式 200
	}
	if w.body.Len() < maxCaptureBytes {
		room := maxCaptureBytes - w.body.Len()
		if room > len(b) {
			room = len(b)
		}
		w.body.Write(b[:room])
	}
	return w.ResponseWriter.Write(b)
}
