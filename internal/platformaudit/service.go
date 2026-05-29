// Package platformaudit 是平台级操作审计(与 internal/audit tenant-scoped 对称,但**无 tenant_id**)。
//
// 适用范围:PoP CRUD(Slice38a)、未来平台 RBAC(Slice38c)、CA·KEK 双人控制(Slice38d)等
// 不归属任何租户的"平台运维"操作;Slice38c 之前的硬要求(诚实标注:Slice38a 评审 S3 留 TODO 锚)。
//
// 双层审计(与 audit.audit_row Slice29 同模式):
//   - source=data  DB 触发器 platform_audit_row(挂 pop_nodes/未来平台白名单表)业务事务内原子写,result=0 哨兵
//   - source=api   handler 显式写(含失败/2xx-零变更),result=HTTP 码
//
// 写路径走 data.InPlatformTxRW(app_platform_rw,Slice38a 已建);读走 data.InPlatformTx(app_platform_ro)。
package platformaudit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// 审计来源(source 列,与 audit.SourceAPI/SourceData 同形态)。
const (
	SourceAPI  = "api"
	SourceData = "data"
)

// Entry 是一条平台审计记录。
type Entry struct {
	ID             string    `json:"id"`
	Ts             time.Time `json:"ts"`
	ActorSubject   string    `json:"actor_subject"`
	ActorRole      string    `json:"actor_role"`
	Action         string    `json:"action"`
	Result         int       `json:"result"` // HTTP 码(api 源)或 0(data 源哨兵)
	Detail         string    `json:"detail,omitempty"`
	Source         string    `json:"source"`                     // api / data
	TargetTenantID string    `json:"target_tenant_id,omitempty"` // 可选(平台对某租户操作时关联)
}

// Service 是平台审计模块对外接口。
type Service interface {
	// Record append 一条平台审计(默认 source=api;走 InPlatformTxRW 写)。
	Record(ctx context.Context, e Entry) error
	// List 列平台审计(按 ts 倒序;走 InPlatformTx 只读,limit<=0 用默认 100)。
	List(ctx context.Context, limit int) ([]Entry, error)
}

type service struct {
	store data.Store
}

// NewService 构造平台审计服务。
func NewService(store data.Store) Service { return &service{store: store} }

// Record 写一条平台审计。actor_subject 为空时记 'system'(无主体场景,如启动自检);
// source 为空时默认 SourceAPI(本服务显式写的都是 API 动作级;data 源由 DB 触发器直接写)。
func (s *service) Record(ctx context.Context, e Entry) error {
	subject := e.ActorSubject
	if subject == "" {
		subject = "system"
	}
	role := e.ActorRole
	if role == "" {
		role = "system"
	}
	src := e.Source
	if src == "" {
		src = SourceAPI
	}
	if src != SourceAPI && src != SourceData {
		return fmt.Errorf("platformaudit.Record: 非法 source %q", src)
	}
	var tgt any
	if e.TargetTenantID != "" {
		tgt = e.TargetTenantID
	}
	return s.store.InPlatformTxRW(ctx, func(q data.Queries) error {
		_, err := q.Exec(ctx,
			`INSERT INTO platform_audit_log (id, actor_subject, actor_role, action, result, detail, source, target_tenant_id)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			uuid.NewString(), subject, role, e.Action, e.Result, e.Detail, src, tgt)
		if err != nil {
			return fmt.Errorf("platformaudit.Record insert: %w", err)
		}
		return nil
	})
}

// List 读平台审计(平台只读路径,InPlatformTx 经 app_platform_ro)。
func (s *service) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}
	out := []Entry{}
	err := s.store.InPlatformTx(ctx, func(q data.Queries) error {
		rows, qerr := q.Query(ctx,
			`SELECT id, ts, actor_subject, actor_role, action, result, detail, source, COALESCE(target_tenant_id::text, '')
			 FROM platform_audit_log
			 ORDER BY ts DESC
			 LIMIT $1`, limit)
		if qerr != nil {
			return fmt.Errorf("platformaudit.List query: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if err := rows.Scan(&e.ID, &e.Ts, &e.ActorSubject, &e.ActorRole, &e.Action, &e.Result, &e.Detail, &e.Source, &e.TargetTenantID); err != nil {
				return fmt.Errorf("platformaudit.List scan: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrNotImplemented 备用 sentinel。
var ErrNotImplemented = errors.New("platformaudit: 未实现")
