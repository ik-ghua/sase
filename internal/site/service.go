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
	if _, ipnet, err := net.ParseCIDR(st.CIDR); err != nil {
		return fmt.Errorf("site.CreateSite: cidr %q 非法: %w", st.CIDR, err)
	} else if err := checkCanonicalCIDR(ipnet); err != nil {
		// 输入侧纵深(承接 Slice70):拒绝非规范族表示(如 v4-mapped-v6 ::ffff:10.0.0.0/104),
		// 防其穿到数据面 dptunnel LPM 引发族不一致/越界(fail-closed,不入库)。
		return fmt.Errorf("site.CreateSite: cidr %q %w", st.CIDR, err)
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

// ErrNonCanonicalCIDR 表示 CIDR 用了非规范的地址族表示(典型:v4-mapped-v6,如
// ::ffff:10.0.0.0/104)。要求 v4 地址用 v4 掩码、v6 地址用 v6 掩码,二者一一对应。
var ErrNonCanonicalCIDR = errors.New("非规范:v4 地址须用 v4 掩码,勿用 v4-mapped-v6 表示")

// checkCanonicalCIDR 校验 net.ParseCIDR 解析出的网络段是规范族表示:
// 当且仅当地址可表为 4 字节 v4(To4()!=nil)时,掩码也须是 4 字节;否则视为
// v4-mapped-v6(16 字节掩码下的 v4 地址)等非规范形态,拒绝。
//
// 依据:Go net.ParseCIDR 对 "10.0.0.0/24" 返回 4 字节 IP+4 字节掩码;对
// "::ffff:10.0.0.0/104" 返回 v4-mapped 16 字节 IP(To4()!=nil)+16 字节掩码。
// 后者一旦入库再下发至数据面 dptunnel LPM,会因族不一致导致前缀越界(Slice70 已修
// 数据结构层崩溃,本处在输入侧再筑一道纵深,fail-closed)。
func checkCanonicalCIDR(ipnet *net.IPNet) error {
	isV4 := ipnet.IP.To4() != nil
	maskV4 := len(ipnet.Mask) == net.IPv4len
	if isV4 != maskV4 {
		return ErrNonCanonicalCIDR
	}
	return nil
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
