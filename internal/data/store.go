// Package data 是数据访问层:统一入口 + RLS 租户上下文 + 事务。
// 业务模块只经 InTx(读写,app_rw)/ InTxRO(只读,app_ro)访问,不持裸连接
// (数据访问层 L2 3.5:misuse-resistant,从 API 形态杜绝裸查询/漏设上下文)。
package data

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotImplemented 表示 Slice 0 桩未接真实 DB(Slice 1 接 RLS Postgres)。
var ErrNotImplemented = errors.New("data: 未接 DB(Slice 0 桩;待 Slice 1 接 RLS Postgres)")

// ErrNoTenantContext 表示事务缺租户上下文 —— fail-loud(数据访问层 L2 3.1/3.3)。
var ErrNoTenantContext = errors.New("data: 事务缺租户上下文(app.current_tenant 必须设置)")

// ErrNoPlatformPath 表示未配置平台连接池(app_platform_ro)—— InPlatformTx 不可用(fail-loud)。
var ErrNoPlatformPath = errors.New("data: 未配置平台跨租户路径(SASE_DB_PLATFORM_DSN 未设)")

// ErrNoPlatformRWPath 表示未配置平台写池(app_platform_rw)—— InPlatformTxRW 不可用(fail-loud)。
// Slice38a 平台写端点首用;调用方可经 errors.Is 判定后返 503(端点存在但未配置)。
var ErrNoPlatformRWPath = errors.New("data: 未配置平台写路径(SASE_DB_PLATFORM_RW_DSN 未设)")

// ErrNoRows 是「查询无行」哨兵(转出底层驱动错误),业务模块用 errors.Is 判定,无需各自 import pgx。
var ErrNoRows = pgx.ErrNoRows

// IsUniqueViolation 判定底层错误是否为 PG SQLSTATE 23505(unique_violation)。
// 业务模块借此把 UNIQUE 冲突转为模块级 sentinel(如 ErrAlreadyExists)而无需各自字符串嗅探
// (评审 Slice38a S2:首处 unique violation 处理在 popreg.Create;后续刀 38c/d 等复用此 helper)。
// 若需精确区分某个表的多个 unique 索引,调用方可在 IsUniqueViolation 通过后再嗅探约束名。
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Queries 是事务内可用的查询句柄(窄面:只暴露执行/查询,不暴露 Commit/Rollback)。
// 业务模块拿到的是已设好 RLS 租户上下文的事务句柄,无法越权管理事务(misuse-resistant,
// 数据访问层 L2 3.5)。pgx.Tx 天然满足本接口。Slice 1 手写 SQL;后续可换 sqlc 生成。
type Queries interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store 是数据访问层入口。
type Store interface {
	// InTx 单租户读写事务(app_rw):acquire → BEGIN → set_config(app.current_tenant, tenantID, true)
	// → fn → COMMIT/ROLLBACK(数据访问层 L2 3.3 事务级 RLS 上下文,绑事务自动失效)。
	InTx(ctx context.Context, tenantID string, fn func(q Queries) error) error
	// InTxRO 单租户只读事务(app_ro,SELECT-only)。供只读消费者(如 xDS server 按租户读)。
	InTxRO(ctx context.Context, tenantID string, fn func(q Queries) error) error
	// InPlatformTx 平台级跨租户只读事务(app_platform_ro):**不注入 app.current_tenant**,
	// 权限由 authz 平台 RBAC 控制(非 RLS),只能读平台视图(如 tenant_summary)/无 tenant_id 平台表
	// (数据访问层 L2 3.6 / 平台控制台 L2 3.1)。未配置平台连接池则 fail-loud(ErrNoPlatformPath)。
	InPlatformTx(ctx context.Context, fn func(q Queries) error) error
	// InPlatformTxRW 平台级读写事务(app_platform_rw):**不注入 app.current_tenant**;
	// 该角色仅获**平台白名单表(无 RLS)** GRANT(如 pop_nodes),租户表无授权 → 误写 permission denied 兜底
	// (Slice38a PoP 注册首用,38c/d CA·KEK 等高敏感平台写复用)。未配置池 → fail-loud(ErrNoPlatformRWPath)。
	InPlatformTxRW(ctx context.Context, fn func(q Queries) error) error
	// Close 释放连接池(stub 为 no-op)。
	Close()
}

// stubStore 是 Slice 0 占位实现(无真实 DB),用于打通分层与模块装配。
type stubStore struct{}

// NewStubStore 返回 Slice 0 占位 Store。
func NewStubStore() Store { return &stubStore{} }

func (s *stubStore) InTx(_ context.Context, tenantID string, _ func(Queries) error) error {
	if tenantID == "" {
		return ErrNoTenantContext
	}
	return ErrNotImplemented
}

func (s *stubStore) InTxRO(ctx context.Context, tenantID string, fn func(Queries) error) error {
	return s.InTx(ctx, tenantID, fn)
}

func (s *stubStore) InPlatformTx(_ context.Context, _ func(Queries) error) error {
	return ErrNoPlatformPath // Slice 0 桩无平台路径
}

func (s *stubStore) InPlatformTxRW(_ context.Context, _ func(Queries) error) error {
	return ErrNoPlatformRWPath // Slice 0 桩无平台写路径
}

func (s *stubStore) Close() {}
