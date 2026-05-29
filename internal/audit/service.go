// Package audit 是管理面操作审计:记录已授权的变更操作(谁/目标租户/动作/结果),供合规留痕。
// 上承控制面 L2(横切 audit)、运维/部署 L2(审计留存)、L1 等保合规。租户作用域、经 data 层 RLS。
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// 审计来源(source 列,审计事务化 L2 4.4 两层分工):
//
//	SourceAPI  = HTTP 中间件写(API 动作级、best-effort;含失败/无变更尝试,result=HTTP 码)
//	SourceData = DB 触发器写(数据变更级、原子、权威;result=0 哨兵,本服务不直接写,读时区分)
const (
	SourceAPI  = "api"
	SourceData = "data"
)

// Entry 是一条审计记录。
type Entry struct {
	TenantID     string    `json:"tenant_id"`
	Ts           time.Time `json:"ts"`
	ActorSubject string    `json:"actor_subject"`
	ActorRole    string    `json:"actor_role"`
	Action       string    `json:"action"`
	Result       int       `json:"result"`
	Detail       string    `json:"detail,omitempty"`
	Source       string    `json:"source"` // api(中间件)/ data(触发器);空写默认 api
}

// Service 是 audit 模块对外接口。
type Service interface {
	Record(ctx context.Context, e Entry) error
	ListByTenant(ctx context.Context, tenantID string, limit int) ([]Entry, error)
}

type service struct {
	store data.Store
}

// NewService 构造 audit 服务。
func NewService(store data.Store) Service { return &service{store: store} }

// Record append 一条审计(租户作用域写,RLS WITH CHECK 保证 tenant_id 一致)。
func (s *service) Record(ctx context.Context, e Entry) error {
	if e.TenantID == "" {
		return fmt.Errorf("audit.Record: tenant_id 必填")
	}
	src := e.Source
	if src == "" {
		src = SourceAPI // 经本服务显式写的都是 API 动作级;data 源由 DB 触发器直接写
	}
	return s.store.InTx(ctx, e.TenantID, func(q data.Queries) error {
		_, err := q.Exec(ctx,
			`INSERT INTO audit_log (id, tenant_id, actor_subject, actor_role, action, result, detail, source)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			uuid.NewString(), e.TenantID, e.ActorSubject, e.ActorRole, e.Action, e.Result, e.Detail, src)
		if err != nil {
			return fmt.Errorf("audit.Record insert: %w", err)
		}
		return nil
	})
}

// ListByTenant 读租户审计(按时间倒序,RLS 保证只见本租户)。limit<=0 用默认 100。
func (s *service) ListByTenant(ctx context.Context, tenantID string, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []Entry
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(ctx,
			`SELECT tenant_id, ts, actor_subject, actor_role, action, result, detail, source
			 FROM audit_log ORDER BY ts DESC LIMIT $1`, limit)
		if err != nil {
			return fmt.Errorf("audit.ListByTenant query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if err := rows.Scan(&e.TenantID, &e.Ts, &e.ActorSubject, &e.ActorRole, &e.Action, &e.Result, &e.Detail, &e.Source); err != nil {
				return fmt.Errorf("audit.ListByTenant scan: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Entry{}
	}
	return out, nil
}
