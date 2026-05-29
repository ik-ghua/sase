// Package platformrbac 是平台管理员持久化 RBAC(Slice38c)。
//
// 与现有 authz/identity 分工:
//   - identity.IssueAdminToken 签发 admin 令牌(claims.Role + TenantID);
//   - authz.Guard 经签名验证 token 拿 Principal;
//   - **本包持久化 platform_admin 主体集**:`/platform/admin-tokens` 端点签发 role=platform_admin
//     的 token 时必查 IsActive(subject);**bootstrap 路径绕过本表**(应急通道,运维约定立即登记)。
//
// 写经 data.InPlatformTxRW(app_platform_rw,同 Slice38a/39 路径);读经 InPlatformTx(app_platform_ro)。
// 双层审计已自动接入:平台审计触发器 platform_audit_tr 挂 platform_admins(migrations/0022)。
package platformrbac

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// 错误 sentinel。
var (
	ErrAdminNotFound      = errors.New("platformrbac: 管理员不存在")
	ErrAdminAlreadyExists = errors.New("platformrbac: subject 已存在")
	ErrInvalidAdminPatch  = errors.New("platformrbac: 请求字段非法")
	// ErrLastActiveAdmin:停用/删除会使 active 平台管理员归零(锁死)→ 拒。
	// 与 handler 的自禁/自删保护互补:自保护防"误操作自己",本保护防"表内最后一枚 active 被任何人(含 bootstrap)停用/删"。
	ErrLastActiveAdmin = errors.New("platformrbac: 不能停用/删除最后一枚 active 平台管理员")
)

// guardLastActive 在写事务内锁定所有 active 行(`FOR UPDATE` 序列化并发停用/删除,防 TOCTOU:
// 否则并发停用两枚不同 active 各见 count=2 均放行 → 归零),若 targetID 当前 active 且为最后一枚 → ErrLastActiveAdmin。
// 须紧邻 DELETE/UPDATE 前调用,且在同一 q(同事务)。注:count(*) 不能 FOR UPDATE,故取 active id 集合在 Go 侧计数。
func guardLastActive(ctx context.Context, q data.Queries, targetID string) error {
	rows, err := q.Query(ctx, `SELECT id FROM platform_admins WHERE status='active' FOR UPDATE`)
	if err != nil {
		return fmt.Errorf("platformrbac.guardLastActive: %w", err)
	}
	active := map[string]bool{}
	for rows.Next() {
		var id string
		if e := rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		active[id] = true
	}
	if e := rows.Err(); e != nil {
		rows.Close()
		return e
	}
	rows.Close() // 必须在后续 q.Exec/QueryRow 前关闭(同事务单连接)
	if active[targetID] && len(active) <= 1 {
		return ErrLastActiveAdmin
	}
	return nil
}

// Admin 是 platform_admin 持久化模型。
type Admin struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	Status    string    `json:"status"` // active / disabled
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by"`
}

// CreateRequest 是新建 platform_admin 入参。
type CreateRequest struct {
	Subject   string `json:"subject"`
	Email     string `json:"email,omitempty"`
	CreatedBy string `json:"-"` // 内部填(handler 取 actor.Subject),不来自客户端 JSON
}

// Patch 是部分更新(PATCH 语义:nil=不改)。**故意不含 Subject**(主键级,改名= 删后重建)。
type Patch struct {
	Status *string `json:"status,omitempty"`
	Email  *string `json:"email,omitempty"`
}

// Service 是 platformrbac 对外接口。
type Service interface {
	Create(ctx context.Context, req CreateRequest) (*Admin, error)
	Get(ctx context.Context, id string) (*Admin, error)
	GetBySubject(ctx context.Context, subject string) (*Admin, error)
	List(ctx context.Context) ([]Admin, error)
	Update(ctx context.Context, id string, patch Patch) (*Admin, error)
	Delete(ctx context.Context, id string) error
	// IsActive 是签发 platform_admin token 时的 RBAC 闸:subject 在表里且 status=active 才返 true。
	// **bootstrap 路径不查本接口**(应急通道直接走 identity.IssueAdminToken,见 cmd/api-server 注释)。
	IsActive(ctx context.Context, subject string) (bool, error)
}

type service struct {
	store data.Store
}

// NewService 构造。
func NewService(store data.Store) Service { return &service{store: store} }

// adminColumns 是 Admin 列序的单一来源(与 scanAdmin 同源,防 RETURNING 列序漂移)。
const adminColumns = "id, subject, email, status, created_at, updated_at, created_by"

func scanAdmin(row interface {
	Scan(dest ...any) error
}, a *Admin) error {
	return row.Scan(&a.ID, &a.Subject, &a.Email, &a.Status, &a.CreatedAt, &a.UpdatedAt, &a.CreatedBy)
}

// validStatuses 与 OpenAPI enum 同源。
var validStatuses = map[string]bool{"active": true, "disabled": true}

func (s *service) Create(ctx context.Context, req CreateRequest) (*Admin, error) {
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		return nil, fmt.Errorf("%w: subject 必填", ErrInvalidAdminPatch)
	}
	id := uuid.NewString()
	var a Admin
	err := s.store.InPlatformTxRW(ctx, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`INSERT INTO platform_admins (id, subject, email, status, created_by)
			 VALUES ($1, $2, $3, 'active', $4)
			 RETURNING `+adminColumns,
			id, subject, req.Email, req.CreatedBy)
		return scanAdmin(row, &a)
	})
	if err != nil {
		// subject UNIQUE 冲突 → ErrAdminAlreadyExists(data.IsUniqueViolation 类型化判定,同 popreg)
		if data.IsUniqueViolation(err) {
			return nil, ErrAdminAlreadyExists
		}
		return nil, fmt.Errorf("platformrbac.Create: %w", err)
	}
	return &a, nil
}

func (s *service) Get(ctx context.Context, id string) (*Admin, error) {
	if id == "" {
		return nil, errors.New("platformrbac.Get: id 必填")
	}
	var a Admin
	err := s.store.InPlatformTx(ctx, func(q data.Queries) error {
		row := q.QueryRow(ctx, `SELECT `+adminColumns+` FROM platform_admins WHERE id=$1`, id)
		if e := scanAdmin(row, &a); e != nil {
			if errors.Is(e, data.ErrNoRows) {
				return ErrAdminNotFound
			}
			return e
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *service) GetBySubject(ctx context.Context, subject string) (*Admin, error) {
	if subject == "" {
		return nil, errors.New("platformrbac.GetBySubject: subject 必填")
	}
	var a Admin
	err := s.store.InPlatformTx(ctx, func(q data.Queries) error {
		row := q.QueryRow(ctx, `SELECT `+adminColumns+` FROM platform_admins WHERE subject=$1`, subject)
		if e := scanAdmin(row, &a); e != nil {
			if errors.Is(e, data.ErrNoRows) {
				return ErrAdminNotFound
			}
			return e
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *service) List(ctx context.Context) ([]Admin, error) {
	out := []Admin{}
	err := s.store.InPlatformTx(ctx, func(q data.Queries) error {
		rows, qerr := q.Query(ctx, `SELECT `+adminColumns+` FROM platform_admins ORDER BY created_at`)
		if qerr != nil {
			return fmt.Errorf("platformrbac.List: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			var a Admin
			if e := scanAdmin(rows, &a); e != nil {
				return e
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (s *service) Update(ctx context.Context, id string, patch Patch) (*Admin, error) {
	if id == "" {
		return nil, errors.New("platformrbac.Update: id 必填")
	}
	if patch.Status != nil && !validStatuses[*patch.Status] {
		return nil, fmt.Errorf("%w: status 须为 active|disabled,得 %q", ErrInvalidAdminPatch, *patch.Status)
	}
	var sets []string
	var args []any
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s=$%d", col, len(args)))
	}
	if patch.Status != nil {
		add("status", *patch.Status)
	}
	if patch.Email != nil {
		add("email", *patch.Email)
	}
	if len(sets) == 0 {
		return nil, fmt.Errorf("%w: 无可更新字段", ErrInvalidAdminPatch)
	}
	args = append(args, id)
	sqlText := fmt.Sprintf(`UPDATE platform_admins SET %s WHERE id=$%d RETURNING %s`,
		strings.Join(sets, ", "), len(args), adminColumns)
	var a Admin
	err := s.store.InPlatformTxRW(ctx, func(q data.Queries) error {
		// last-admin 保护:停用(status→disabled)前若目标是最后一枚 active → 拒(防锁死)。
		if patch.Status != nil && *patch.Status == "disabled" {
			if e := guardLastActive(ctx, q, id); e != nil {
				return e
			}
		}
		row := q.QueryRow(ctx, sqlText, args...)
		if e := scanAdmin(row, &a); e != nil {
			if errors.Is(e, data.ErrNoRows) {
				return ErrAdminNotFound
			}
			return e
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *service) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("platformrbac.Delete: id 必填")
	}
	return s.store.InPlatformTxRW(ctx, func(q data.Queries) error {
		// last-admin 保护:删除最后一枚 active 管理员 → 拒(防锁死)。删 disabled 的不受限。
		if e := guardLastActive(ctx, q, id); e != nil {
			return e
		}
		ct, err := q.Exec(ctx, `DELETE FROM platform_admins WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("platformrbac.Delete: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return ErrAdminNotFound
		}
		return nil
	})
}

// IsActive:subject 在表 + status=active → true;不存在 → false(nil err);DB 错 → err。
// 设计取舍:**不存在 ≠ 错误**,让 caller(`/platform/admin-tokens` 端点)统一拒签发即可。
func (s *service) IsActive(ctx context.Context, subject string) (bool, error) {
	if subject == "" {
		return false, nil
	}
	a, err := s.GetBySubject(ctx, subject)
	if err != nil {
		if errors.Is(err, ErrAdminNotFound) {
			return false, nil
		}
		return false, err
	}
	return a.Status == "active", nil
}
