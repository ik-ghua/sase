package fw

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// ErrNotFound 表示规则不存在(或在当前租户 RLS 上下文下不可见)。
var ErrNotFound = errors.New("fw: 规则不存在")

// Service 是 FWaaS 规则的编写/读取(租户作用域,经 data 层 RLS)。变更发 NOTIFY → xds-server 下发 PoP。
type Service interface {
	CreateRule(ctx context.Context, tenantID string, r *Rule) error
	ListRules(ctx context.Context, tenantID string) ([]Rule, error)
	UpdateRule(ctx context.Context, tenantID, id string, r *Rule) error // 全量替换;不存在 → ErrNotFound
	DeleteRule(ctx context.Context, tenantID, id string) error          // 不存在 → ErrNotFound
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

// normalizeAndValidate 校验并补默认(Create/Update 共用,保证改规则与建规则同等约束:fail-closed,
// 非法配置不入库免运行期误判)。
func normalizeAndValidate(r *Rule) error {
	if r.Action != ActionAllow && r.Action != ActionDeny {
		return errors.New("fw: action 须为 allow|deny")
	}
	if !validProto(r.Protocol) {
		return errors.New("fw: protocol 须为 any|tcp|udp|icmp")
	}
	if r.Protocol == "" {
		r.Protocol = ProtoAny
	}
	for _, c := range []string{r.SrcCIDR, r.DstCIDR} {
		if c != "" {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("fw: cidr %q 非法: %w", c, err)
			}
		}
	}
	// 端口范围:0,0=any;否则须 0<min<=max(防 [min,0] 这类静默吞没规则的配置)
	if r.DstPortMin != 0 || r.DstPortMax != 0 {
		if r.DstPortMin == 0 || r.DstPortMax == 0 || r.DstPortMin > r.DstPortMax {
			return errors.New("fw: 端口范围须 0<min<=max(或两者皆 0 表 any)")
		}
	}
	return nil
}

func (s *service) CreateRule(ctx context.Context, tenantID string, r *Rule) error {
	if err := normalizeAndValidate(r); err != nil {
		return err
	}
	r.ID = uuid.NewString()
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO fw_rules (id, tenant_id, priority, action, protocol, src_cidr, dst_cidr, dst_port_min, dst_port_max)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			r.ID, tenantID, r.Priority, r.Action, r.Protocol, r.SrcCIDR, r.DstCIDR, int(r.DstPortMin), int(r.DstPortMax)); err != nil {
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
			`SELECT id, priority, action, protocol, src_cidr, dst_cidr, dst_port_min, dst_port_max
			 FROM fw_rules ORDER BY priority, created_at`)
		if err != nil {
			return fmt.Errorf("fw.ListRules query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r Rule
			var lo, hi int
			if err := rows.Scan(&r.ID, &r.Priority, &r.Action, &r.Protocol, &r.SrcCIDR, &r.DstCIDR, &lo, &hi); err != nil {
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

// UpdateRule 全量替换 id 指向的规则(RLS 限本租户;跨租户/不存在 id → 0 行 → ErrNotFound)。
func (s *service) UpdateRule(ctx context.Context, tenantID, id string, r *Rule) error {
	if id == "" {
		return errors.New("fw.UpdateRule: id 必填")
	}
	if err := normalizeAndValidate(r); err != nil {
		return err
	}
	r.ID = id
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		tag, err := q.Exec(ctx,
			`UPDATE fw_rules SET priority=$2, action=$3, protocol=$4, src_cidr=$5, dst_cidr=$6, dst_port_min=$7, dst_port_max=$8
			 WHERE id=$1`,
			id, r.Priority, r.Action, r.Protocol, r.SrcCIDR, r.DstCIDR, int(r.DstPortMin), int(r.DstPortMax))
		if err != nil {
			return fmt.Errorf("fw.UpdateRule update: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelFW, tenantID); err != nil {
			return fmt.Errorf("fw.UpdateRule notify: %w", err)
		}
		return nil
	})
}

// DeleteRule 删除 id 指向的规则(RLS 限本租户;跨租户/不存在 id → 0 行 → ErrNotFound)。
func (s *service) DeleteRule(ctx context.Context, tenantID, id string) error {
	if id == "" {
		return errors.New("fw.DeleteRule: id 必填")
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		tag, err := q.Exec(ctx, `DELETE FROM fw_rules WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("fw.DeleteRule delete: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelFW, tenantID); err != nil {
			return fmt.Errorf("fw.DeleteRule notify: %w", err)
		}
		return nil
	})
}
