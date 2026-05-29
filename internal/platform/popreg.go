package platform

// PoP 节点注册(Slice38a,PC-API-3 — 平台后端铺路)。
//
// 角色定位:PoP 是**平台级共享基础设施**(非租户数据,无 tenant_id;租户/PoP 是 N:M 调度)。
// 数据治理:`pop_nodes` 表**无 RLS**(没有租户维度可隔离);访问治理靠**专用平台写池**最小权限——
//   写经 `data.Store.InPlatformTxRW`(app_platform_rw,仅平台白名单表 GRANT);
//   读经 `data.Store.InPlatformTx`(app_platform_ro,只读)。
//
// **本刀范围**:Admin CRUD(Create/Get/List/Update)。Heartbeat(role:pop mTLS 设备面上报)= 后续刀;
// soft-delete 状态机(类似 tenants offboarding)= 后续刀。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// PoP 节点状态(状态机:active ⇄ draining → down;终态可重新 active 起死)。
const (
	PopStatusActive   = "active"   // 在用,可被调度
	PopStatusDraining = "draining" // 下线中,**不调度新会话**,旧会话自然消散
	PopStatusDown     = "down"     // 故障/已下线
)

var validPopStatuses = map[string]bool{
	PopStatusActive:   true,
	PopStatusDraining: true,
	PopStatusDown:     true,
}

// PoP 节点视图(L1 3.7 单元 / 3.13 部署)。
type PoP struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`         // 运营标识(机房代号/编号,unique 防重)
	Region     string     `json:"region"`       // 地域(用于调度/合规分区)
	Endpoint   string     `json:"endpoint"`     // PoP 入口公网地址(host:port 或 URL)
	MaxUsers   *int       `json:"max_users"`    // 容量上限;nil = 未设
	Status     string     `json:"status"`       // active|draining|down
	LastSeenAt *time.Time `json:"last_seen_at"` // PoP heartbeat 最近时间(Slice38a 暂不写,留字段)
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// CreatePopRequest 是新建 PoP 的入参(状态默认 active;LastSeenAt 由 heartbeat 后续刀填)。
type CreatePopRequest struct {
	Name     string `json:"name"`
	Region   string `json:"region"`
	Endpoint string `json:"endpoint"`
	MaxUsers *int   `json:"max_users,omitempty"`
}

// PopPatch 是 PATCH 入参(PATCH 语义:nil 字段不改)。
//
// 设计取舍:**name/region/endpoint 故意不可改**(运营标识与地址变化属"另起新节点"而非"改名",
// 防 ID 漂移引发的调度/审计断链);如需迁移,新增一个 PoP + 旧 PoP draining→down。
type PopPatch struct {
	Status   *string `json:"status,omitempty"`
	MaxUsers *int    `json:"max_users,omitempty"`
}

// 错误 sentinel。
var (
	ErrPopNotFound      = errors.New("popreg: PoP 不存在")
	ErrPopAlreadyExists = errors.New("popreg: PoP name 已存在")
	ErrInvalidPopPatch  = errors.New("popreg: 请求字段非法")
)

// PopRegistry 是 PoP 注册的对外接口(独立于 tenant Service,避免混平台层不同子领域)。
type PopRegistry interface {
	Create(ctx context.Context, req CreatePopRequest) (*PoP, error)
	Get(ctx context.Context, id string) (*PoP, error)
	List(ctx context.Context) ([]PoP, error)
	Update(ctx context.Context, id string, patch PopPatch) (*PoP, error)
}

// popRegistry 是 PopRegistry 实现。
type popRegistry struct {
	store data.Store
}

// NewPopRegistry 构造。
func NewPopRegistry(store data.Store) PopRegistry { return &popRegistry{store: store} }

// popColumns 是 PoP 列序的单一来源(与 scanPop 同源)。
const popColumns = "id, name, region, endpoint, max_users, status, last_seen_at, created_at, updated_at"

// scanPop 把 popColumns 顺序的一行扫进 p。
func scanPop(row interface {
	Scan(dest ...any) error
}, p *PoP) error {
	return row.Scan(&p.ID, &p.Name, &p.Region, &p.Endpoint, &p.MaxUsers, &p.Status, &p.LastSeenAt, &p.CreatedAt, &p.UpdatedAt)
}

func (r *popRegistry) Create(ctx context.Context, req CreatePopRequest) (*PoP, error) {
	name := strings.TrimSpace(req.Name)
	region := strings.TrimSpace(req.Region)
	endpoint := strings.TrimSpace(req.Endpoint)
	if name == "" || region == "" || endpoint == "" {
		return nil, fmt.Errorf("%w: name/region/endpoint 均必填", ErrInvalidPopPatch)
	}
	if req.MaxUsers != nil && *req.MaxUsers < 0 {
		return nil, fmt.Errorf("%w: max_users 须 ≥ 0", ErrInvalidPopPatch)
	}
	id := uuid.NewString()
	var p PoP
	err := r.store.InPlatformTxRW(ctx, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`INSERT INTO pop_nodes (id, name, region, endpoint, max_users, status)
			 VALUES ($1, $2, $3, $4, $5, 'active')
			 RETURNING `+popColumns,
			id, name, region, endpoint, req.MaxUsers)
		return scanPop(row, &p)
	})
	if err != nil {
		// SQLSTATE 23505 = unique_violation(name UNIQUE);data.IsUniqueViolation 统一类型化判定(S2)。
		if data.IsUniqueViolation(err) {
			return nil, ErrPopAlreadyExists
		}
		return nil, fmt.Errorf("popreg.Create: %w", err)
	}
	return &p, nil
}

func (r *popRegistry) Get(ctx context.Context, id string) (*PoP, error) {
	if id == "" {
		return nil, errors.New("popreg.Get: id 必填")
	}
	var p PoP
	err := r.store.InPlatformTx(ctx, func(q data.Queries) error {
		row := q.QueryRow(ctx, `SELECT `+popColumns+` FROM pop_nodes WHERE id = $1`, id)
		if err := scanPop(row, &p); err != nil {
			if errors.Is(err, data.ErrNoRows) {
				return ErrPopNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *popRegistry) List(ctx context.Context) ([]PoP, error) {
	out := []PoP{}
	err := r.store.InPlatformTx(ctx, func(q data.Queries) error {
		rows, qerr := q.Query(ctx, `SELECT `+popColumns+` FROM pop_nodes ORDER BY region, name`)
		if qerr != nil {
			return fmt.Errorf("popreg.List query: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			var p PoP
			if e := scanPop(rows, &p); e != nil {
				return fmt.Errorf("popreg.List scan: %w", e)
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *popRegistry) Update(ctx context.Context, id string, patch PopPatch) (*PoP, error) {
	if id == "" {
		return nil, errors.New("popreg.Update: id 必填")
	}
	if patch.Status != nil && !validPopStatuses[*patch.Status] {
		return nil, fmt.Errorf("%w: status 须为 active|draining|down,得 %q", ErrInvalidPopPatch, *patch.Status)
	}
	if patch.MaxUsers != nil && *patch.MaxUsers < 0 {
		return nil, fmt.Errorf("%w: max_users 须 ≥ 0", ErrInvalidPopPatch)
	}
	// 动态 SET
	var sets []string
	var args []any
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s=$%d", col, len(args)))
	}
	if patch.Status != nil {
		add("status", *patch.Status)
	}
	if patch.MaxUsers != nil {
		add("max_users", *patch.MaxUsers)
	}
	if len(sets) == 0 {
		return nil, fmt.Errorf("%w: 无可更新字段", ErrInvalidPopPatch)
	}
	args = append(args, id)
	sql := fmt.Sprintf(`UPDATE pop_nodes SET %s WHERE id=$%d RETURNING %s`, strings.Join(sets, ", "), len(args), popColumns)
	var p PoP
	err := r.store.InPlatformTxRW(ctx, func(q data.Queries) error {
		row := q.QueryRow(ctx, sql, args...)
		if err := scanPop(row, &p); err != nil {
			if errors.Is(err, data.ErrNoRows) {
				return ErrPopNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}
