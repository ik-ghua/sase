// Package resource 是资源模块:ZTNA 应用与 App Connector 的注册(L1 3.3 Resource)。
// 对外只暴露 Service 接口;所有访问经 data.Store 的租户作用域事务(RLS)。
// 应用注册被策略编译器消费(校验策略 resource 引用存在性,编译器 L2 3.3①)。
package resource

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// App 是 ZTNA 应用注册(app_key 为策略 resource 字段引用的逻辑键)。
type App struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	AppKey   string `json:"app_key"`
	Name     string `json:"name"`
	Upstream string `json:"upstream"`
}

// Connector 是 App Connector 定义(服务哪个 app)。
type Connector struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	AppKey   string `json:"app_key"`
	Name     string `json:"name"`
}

// Service 是 resource 模块对外唯一接口。
type Service interface {
	CreateApp(ctx context.Context, tenantID string, a *App) error
	ListApps(ctx context.Context, tenantID string) ([]App, error)
	// AppKeys 返回租户已注册应用键集合(供策略编译器校验引用,编译器 L2 3.3①)。
	AppKeys(ctx context.Context, tenantID string) (map[string]bool, error)
	CreateConnector(ctx context.Context, tenantID string, c *Connector) error
	ListConnectors(ctx context.Context, tenantID string) ([]Connector, error)
}

type service struct {
	store data.Store
}

// NewService 构造 resource 服务。
func NewService(store data.Store) Service { return &service{store: store} }

func (s *service) CreateApp(ctx context.Context, tenantID string, a *App) error {
	if a.AppKey == "" || a.Name == "" {
		return errors.New("resource.CreateApp: app_key 与 name 必填")
	}
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		_, err := q.Exec(ctx,
			`INSERT INTO apps (id, tenant_id, app_key, name, upstream) VALUES ($1,$2,$3,$4,$5)`,
			a.ID, tenantID, a.AppKey, a.Name, a.Upstream)
		if err != nil {
			return fmt.Errorf("resource.CreateApp insert: %w", err)
		}
		return nil
	})
}

func (s *service) ListApps(ctx context.Context, tenantID string) ([]App, error) {
	var out []App
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(ctx, `SELECT id, tenant_id, app_key, name, upstream FROM apps ORDER BY app_key`)
		if err != nil {
			return fmt.Errorf("resource.ListApps query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a App
			if err := rows.Scan(&a.ID, &a.TenantID, &a.AppKey, &a.Name, &a.Upstream); err != nil {
				return fmt.Errorf("resource.ListApps scan: %w", err)
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []App{}
	}
	return out, nil
}

func (s *service) AppKeys(ctx context.Context, tenantID string) (map[string]bool, error) {
	keys := map[string]bool{}
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(ctx, `SELECT app_key FROM apps`)
		if err != nil {
			return fmt.Errorf("resource.AppKeys query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return fmt.Errorf("resource.AppKeys scan: %w", err)
			}
			keys[k] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *service) CreateConnector(ctx context.Context, tenantID string, c *Connector) error {
	if c.AppKey == "" || c.Name == "" {
		return errors.New("resource.CreateConnector: app_key 与 name 必填")
	}
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		_, err := q.Exec(ctx,
			`INSERT INTO connectors (id, tenant_id, app_key, name) VALUES ($1,$2,$3,$4)`,
			c.ID, tenantID, c.AppKey, c.Name)
		if err != nil {
			return fmt.Errorf("resource.CreateConnector insert: %w", err)
		}
		return nil
	})
}

func (s *service) ListConnectors(ctx context.Context, tenantID string) ([]Connector, error) {
	var out []Connector
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(ctx, `SELECT id, tenant_id, app_key, name FROM connectors ORDER BY name`)
		if err != nil {
			return fmt.Errorf("resource.ListConnectors query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var c Connector
			if err := rows.Scan(&c.ID, &c.TenantID, &c.AppKey, &c.Name); err != nil {
				return fmt.Errorf("resource.ListConnectors scan: %w", err)
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Connector{}
	}
	return out, nil
}
