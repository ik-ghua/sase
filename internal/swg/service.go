package swg

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// Service 是 SWG 规则的编写/读取(租户作用域,经 data 层 RLS)。变更发 NOTIFY → xds-server 下发 PoP。
type Service interface {
	CreateRule(ctx context.Context, tenantID string, r *Rule) error
	ListRules(ctx context.Context, tenantID string) ([]Rule, error)
}

type service struct {
	store data.Store
}

// NewService 构造 SWG 规则服务。
func NewService(store data.Store) Service { return &service{store: store} }

func (s *service) CreateRule(ctx context.Context, tenantID string, r *Rule) error {
	if r.Kind != KindHost && r.Kind != KindPathPrefix {
		return errors.New("swg.CreateRule: kind 须为 host|path_prefix")
	}
	if r.Pattern == "" {
		return errors.New("swg.CreateRule: pattern 必填")
	}
	if r.Action == "" {
		r.Action = ActionBlock
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO swg_rules (id, tenant_id, kind, pattern, action) VALUES ($1,$2,$3,$4,$5)`,
			uuid.NewString(), tenantID, r.Kind, r.Pattern, r.Action); err != nil {
			return fmt.Errorf("swg.CreateRule insert: %w", err)
		}
		// 通知 xds-server 重读该租户 SWG 规则下发(安全栈 L2 复用下发底座)
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelSWG, tenantID); err != nil {
			return fmt.Errorf("swg.CreateRule notify: %w", err)
		}
		return nil
	})
}

func (s *service) ListRules(ctx context.Context, tenantID string) ([]Rule, error) {
	var out []Rule
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(ctx, `SELECT kind, pattern, action FROM swg_rules ORDER BY created_at`)
		if err != nil {
			return fmt.Errorf("swg.ListRules query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r Rule
			if err := rows.Scan(&r.Kind, &r.Pattern, &r.Action); err != nil {
				return fmt.Errorf("swg.ListRules scan: %w", err)
			}
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
