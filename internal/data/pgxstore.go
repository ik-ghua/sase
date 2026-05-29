package data

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgxStore 是 Store 的真实实现:四路连接池 + 事务级 RLS 租户上下文(数据访问层 L2 3.5/3.6)。
//
//   - rw          app_rw           租户读写(InTx,GUC app.current_tenant)
//   - ro          app_ro           租户只读(InTxRO)
//   - platform    app_platform_ro  平台跨租户只读(InPlatformTx,无 GUC,经策展视图/平台白名单表)
//   - platformRW  app_platform_rw  平台写池(InPlatformTxRW,**仅平台白名单表 GRANT**,
//     租户表无授权 → 误写 permission denied 兜底;Slice38a PoP 注册首用,38c/d CA·KEK 复用)
type pgxStore struct {
	rw         *pgxpool.Pool
	ro         *pgxpool.Pool
	platform   *pgxpool.Pool // 可选;nil → InPlatformTx 不可用
	platformRW *pgxpool.Pool // 可选;nil → InPlatformTxRW 不可用(平台写端点 503)
}

// NewPgxStore 建立 rw/ro(+ 可选 platform)连接池并探活。
func NewPgxStore(ctx context.Context, cfg Config) (Store, error) {
	rw, err := pgxpool.New(ctx, cfg.RWConnString)
	if err != nil {
		return nil, fmt.Errorf("data: 建 app_rw 连接池: %w", err)
	}
	ro, err := pgxpool.New(ctx, cfg.ROConnString)
	if err != nil {
		rw.Close()
		return nil, fmt.Errorf("data: 建 app_ro 连接池: %w", err)
	}
	pools := map[string]*pgxpool.Pool{"app_rw": rw, "app_ro": ro}
	var platform *pgxpool.Pool
	if cfg.PlatformConnString != "" {
		platform, err = pgxpool.New(ctx, cfg.PlatformConnString)
		if err != nil {
			rw.Close()
			ro.Close()
			return nil, fmt.Errorf("data: 建 app_platform_ro 连接池: %w", err)
		}
		pools["app_platform_ro"] = platform
	}
	var platformRW *pgxpool.Pool
	if cfg.PlatformRWConnString != "" {
		platformRW, err = pgxpool.New(ctx, cfg.PlatformRWConnString)
		if err != nil {
			rw.Close()
			ro.Close()
			if platform != nil {
				platform.Close()
			}
			return nil, fmt.Errorf("data: 建 app_platform_rw 连接池: %w", err)
		}
		pools["app_platform_rw"] = platformRW
	}
	closeAll := func() {
		rw.Close()
		ro.Close()
		if platform != nil {
			platform.Close()
		}
		if platformRW != nil {
			platformRW.Close()
		}
	}
	for name, p := range pools {
		if err := p.Ping(ctx); err != nil {
			closeAll()
			return nil, fmt.Errorf("data: 探活 %s: %w", name, err)
		}
	}
	return &pgxStore{rw: rw, ro: ro, platform: platform, platformRW: platformRW}, nil
}

// InPlatformTx 在 app_platform_ro 上跑只读事务,**不注入 app.current_tenant**(平台跨租户路径,
// 数据访问层 L2 3.6)。该角色仅能读平台视图(tenant_summary)/无 tenant_id 平台表;授权由 authz 平台 RBAC
// 在 API 层把关(非 RLS)。未配置平台池 → ErrNoPlatformPath(fail-loud)。
func (s *pgxStore) InPlatformTx(ctx context.Context, fn func(Queries) error) (err error) {
	if s.platform == nil {
		return ErrNoPlatformPath
	}
	tx, err := s.platform.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("data: 平台 BEGIN: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(ctx); rbErr != nil && err == nil && rbErr != pgx.ErrTxClosed {
			err = fmt.Errorf("data: 平台 ROLLBACK: %w", rbErr)
		}
	}()
	// 不设 app.current_tenant:平台路径按定义跨租户;不可越界到业务路径(它只连 app_platform_ro,基表无授权)。
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("data: 平台 COMMIT: %w", err)
	}
	return nil
}

// InPlatformTxRW 在 app_platform_rw 上跑读写事务,**不注入 app.current_tenant**(平台路径)。
// 该角色仅获**平台白名单表(无 RLS)** GRANT(如 pop_nodes;后续 ca_ops/secops_events 等);
// 租户表无任何授权 → 误写 permission denied 兜底(纵深)。授权由 authz `/platform/*` 在 API 层把关。
// 未配置平台 RW 池 → ErrNoPlatformRWPath(fail-loud)。
//
// **审计归因**(Slice39 platform_audit_log):虽然不设 app.current_tenant,但**仍设 actor GUC**——
// 平台审计触发器 platform_audit_row 从 app.current_actor / app.current_actor_role 读;
// 无主体时不设,触发器记 'system'(同 audit.audit_row Slice29 模式)。
func (s *pgxStore) InPlatformTxRW(ctx context.Context, fn func(Queries) error) (err error) {
	if s.platformRW == nil {
		return ErrNoPlatformRWPath
	}
	tx, err := s.platformRW.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		return fmt.Errorf("data: 平台RW BEGIN: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(ctx); rbErr != nil && err == nil && rbErr != pgx.ErrTxClosed {
			err = fmt.Errorf("data: 平台RW ROLLBACK: %w", rbErr)
		}
	}()
	// 不设 app.current_tenant:平台路径按定义跨租户;租户表 RLS 在无 GUC 时 deny(平台 RW 角色亦 NOBYPASSRLS)。
	// 设 actor GUC 供 platform_audit_log 触发器读(无主体则不设,触发器兜底 'system')。
	if a, ok := actorFromContext(ctx); ok {
		if _, err = tx.Exec(ctx,
			"SELECT set_config('app.current_actor', $1, true), set_config('app.current_actor_role', $2, true)",
			a.Subject, a.Role); err != nil {
			return fmt.Errorf("data: 平台RW 设审计归因上下文: %w", err)
		}
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("data: 平台RW COMMIT: %w", err)
	}
	return nil
}

func (s *pgxStore) InTx(ctx context.Context, tenantID string, fn func(Queries) error) error {
	return s.runTx(ctx, s.rw, tenantID, pgx.ReadWrite, fn)
}

func (s *pgxStore) InTxRO(ctx context.Context, tenantID string, fn func(Queries) error) error {
	return s.runTx(ctx, s.ro, tenantID, pgx.ReadOnly, fn)
}

// runTx:BEGIN → 设租户上下文 → fn → COMMIT(出错 ROLLBACK)。
func (s *pgxStore) runTx(ctx context.Context, pool *pgxpool.Pool, tenantID string, mode pgx.TxAccessMode, fn func(Queries) error) (err error) {
	if tenantID == "" {
		return ErrNoTenantContext // fail-loud:绝不在无上下文时跑业务查询
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: mode})
	if err != nil {
		return fmt.Errorf("data: BEGIN: %w", err)
	}
	defer func() {
		// COMMIT 后 Rollback 为 no-op(ErrTxClosed);仅在 fn/COMMIT 出错时真正回滚。
		if rbErr := tx.Rollback(ctx); rbErr != nil && err == nil && rbErr != pgx.ErrTxClosed {
			err = fmt.Errorf("data: ROLLBACK: %w", rbErr)
		}
	}()

	// 事务级 RLS 租户上下文:is_local=true,绑本事务,结束即失效。
	if _, err = tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID); err != nil {
		return fmt.Errorf("data: 设租户上下文: %w", err)
	}
	// 审计归因(per-tx GUC,供审计触发器 audit_row() 在本事务内读;无主体则不设,触发器记 system)。
	if a, ok := actorFromContext(ctx); ok {
		if _, err = tx.Exec(ctx,
			"SELECT set_config('app.current_actor', $1, true), set_config('app.current_actor_role', $2, true)",
			a.Subject, a.Role); err != nil {
			return fmt.Errorf("data: 设审计归因上下文: %w", err)
		}
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("data: COMMIT: %w", err)
	}
	return nil
}

func (s *pgxStore) Close() {
	s.rw.Close()
	s.ro.Close()
	if s.platform != nil {
		s.platform.Close()
	}
	if s.platformRW != nil {
		s.platformRW.Close()
	}
}
