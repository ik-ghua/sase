// Package site 是 SD-WAN 站点模块:站点注册(L1 3.3 Site / 3.8 租户路由域)。
// 对外只暴露 Service 接口;经 data 层 RLS。站点清单经 xDS SiteConfig 下发各 CPE(复用下发底座)。
package site

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// Site 是 SD-WAN 站点(逻辑键 + 子网)。
type Site struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	SiteKey  string `json:"site_key"`
	Name     string `json:"name"`
	CIDR     string `json:"cidr"`
}

// Service 是 site 模块对外唯一接口。
type Service interface {
	CreateSite(ctx context.Context, tenantID string, s *Site) error
	ListSites(ctx context.Context, tenantID string) ([]Site, error)
}

type service struct {
	store data.Store
}

// NewService 构造 site 服务。
func NewService(store data.Store) Service { return &service{store: store} }

func (s *service) CreateSite(ctx context.Context, tenantID string, st *Site) error {
	if st.SiteKey == "" || st.CIDR == "" {
		return errors.New("site.CreateSite: site_key 与 cidr 必填")
	}
	if _, _, err := net.ParseCIDR(st.CIDR); err != nil {
		return fmt.Errorf("site.CreateSite: cidr %q 非法: %w", st.CIDR, err)
	}
	if st.ID == "" {
		st.ID = uuid.NewString()
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO sites (id, tenant_id, site_key, name, cidr) VALUES ($1,$2,$3,$4,$5)`,
			st.ID, tenantID, st.SiteKey, st.Name, st.CIDR); err != nil {
			return fmt.Errorf("site.CreateSite insert: %w", err)
		}
		// 通知 xds-server 重读该租户站点清单下发各 CPE(复用下发底座)
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelSite, tenantID); err != nil {
			return fmt.Errorf("site.CreateSite notify: %w", err)
		}
		return nil
	})
}

func (s *service) ListSites(ctx context.Context, tenantID string) ([]Site, error) {
	var out []Site
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(ctx, `SELECT id, tenant_id, site_key, name, cidr FROM sites ORDER BY site_key`)
		if err != nil {
			return fmt.Errorf("site.ListSites query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var st Site
			if err := rows.Scan(&st.ID, &st.TenantID, &st.SiteKey, &st.Name, &st.CIDR); err != nil {
				return fmt.Errorf("site.ListSites scan: %w", err)
			}
			out = append(out, st)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Site{}
	}
	return out, nil
}
