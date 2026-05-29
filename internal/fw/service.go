package fw

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// Service 是 FWaaS 规则的编写/读取(租户作用域,经 data 层 RLS)。变更发 NOTIFY → xds-server 下发 PoP。
type Service interface {
	CreateRule(ctx context.Context, tenantID string, r *Rule) error
	ListRules(ctx context.Context, tenantID string) ([]Rule, error)
}

type service struct {
	store data.Store
}

// NewService 构造 FWaaS 规则服务。
func NewService(store data.Store) Service { return &service{store: store} }

func validProto(p string) bool {
	switch p {
	case "", ProtoAny, ProtoTCP, ProtoUDP, ProtoICMP:
		return true
	default:
		return false
	}
}

func (s *service) CreateRule(ctx context.Context, tenantID string, r *Rule) error {
	if r.Action != ActionAllow && r.Action != ActionDeny {
		return errors.New("fw.CreateRule: action 须为 allow|deny")
	}
	if !validProto(r.Protocol) {
		return errors.New("fw.CreateRule: protocol 须为 any|tcp|udp|icmp")
	}
	if r.Protocol == "" {
		r.Protocol = ProtoAny
	}
	// CIDR 非空则校验合法(fail-closed:非法配置不入库,免运行期误判)
	for _, c := range []string{r.SrcCIDR, r.DstCIDR} {
		if c != "" {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("fw.CreateRule: cidr %q 非法: %w", c, err)
			}
		}
	}
	// 端口范围:0,0=any;否则须 0<min<=max(防 [min,0] 这类静默吞没规则的配置)
	if r.DstPortMin != 0 || r.DstPortMax != 0 {
		if r.DstPortMin == 0 || r.DstPortMax == 0 || r.DstPortMin > r.DstPortMax {
			return errors.New("fw.CreateRule: 端口范围须 0<min<=max(或两者皆 0 表 any)")
		}
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO fw_rules (id, tenant_id, priority, action, protocol, src_cidr, dst_cidr, dst_port_min, dst_port_max)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			uuid.NewString(), tenantID, r.Priority, r.Action, r.Protocol, r.SrcCIDR, r.DstCIDR, int(r.DstPortMin), int(r.DstPortMax)); err != nil {
			return fmt.Errorf("fw.CreateRule insert: %w", err)
		}
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelFW, tenantID); err != nil {
			return fmt.Errorf("fw.CreateRule notify: %w", err)
		}
		return nil
	})
}

func (s *service) ListRules(ctx context.Context, tenantID string) ([]Rule, error) {
	var out []Rule
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(ctx,
			`SELECT priority, action, protocol, src_cidr, dst_cidr, dst_port_min, dst_port_max
			 FROM fw_rules ORDER BY priority, created_at`)
		if err != nil {
			return fmt.Errorf("fw.ListRules query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r Rule
			var lo, hi int
			if err := rows.Scan(&r.Priority, &r.Action, &r.Protocol, &r.SrcCIDR, &r.DstCIDR, &lo, &hi); err != nil {
				return fmt.Errorf("fw.ListRules scan: %w", err)
			}
			r.DstPortMin, r.DstPortMax = uint16(lo), uint16(hi)
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Rule{}
	}
	return out, nil
}
