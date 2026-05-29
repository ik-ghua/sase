package swg

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// ErrNotFound 表示规则不存在(或在当前租户 RLS 上下文下不可见)。
var ErrNotFound = errors.New("swg: 规则不存在")

// Service 是 SWG 规则的编写/读取(租户作用域,经 data 层 RLS)。变更发 NOTIFY → xds-server 下发 PoP。
type Service interface {
	CreateRule(ctx context.Context, tenantID string, r *Rule) error
	ListRules(ctx context.Context, tenantID string) ([]Rule, error)
	UpdateRule(ctx context.Context, tenantID, id string, r *Rule) error // 全量替换;不存在 → ErrNotFound
	DeleteRule(ctx context.Context, tenantID, id string) error          // 不存在 → ErrNotFound
}

type service struct {
	store data.Store
}

// NewService 构造 SWG 规则服务。
func NewService(store data.Store) Service { return &service{store: store} }

// normalizeAndValidate 校验并补默认(Create/Update 共用,保证改规则与建规则同等约束)。
func normalizeAndValidate(r *Rule) error {
	if r.Kind != KindHost && r.Kind != KindPathPrefix {
		return errors.New("swg: kind 须为 host|path_prefix")
	}
	if r.Pattern == "" {
		return errors.New("swg: pattern 必填")
	}
	if r.Action == "" {
		r.Action = ActionBlock
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
			`INSERT INTO swg_rules (id, tenant_id, kind, pattern, action) VALUES ($1,$2,$3,$4,$5)`,
			r.ID, tenantID, r.Kind, r.Pattern, r.Action); err != nil {
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
		rows, err := q.Query(ctx, `SELECT id, kind, pattern, action FROM swg_rules ORDER BY created_at`)
		if err != nil {
			return fmt.Errorf("swg.ListRules query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r Rule
			if err := rows.Scan(&r.ID, &r.Kind, &r.Pattern, &r.Action); err != nil {
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

// UpdateRule 全量替换 id 指向的规则(RLS 限本租户;跨租户/不存在 id → 0 行 → ErrNotFound)。
func (s *service) UpdateRule(ctx context.Context, tenantID, id string, r *Rule) error {
	if id == "" {
		return errors.New("swg.UpdateRule: id 必填")
	}
	if err := normalizeAndValidate(r); err != nil {
		return err
	}
	r.ID = id
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		tag, err := q.Exec(ctx,
			`UPDATE swg_rules SET kind=$2, pattern=$3, action=$4 WHERE id=$1`,
			id, r.Kind, r.Pattern, r.Action)
		if err != nil {
			return fmt.Errorf("swg.UpdateRule update: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelSWG, tenantID); err != nil {
			return fmt.Errorf("swg.UpdateRule notify: %w", err)
		}
		return nil
	})
}

// DeleteRule 删除 id 指向的规则(RLS 限本租户;跨租户/不存在 id → 0 行 → ErrNotFound)。
func (s *service) DeleteRule(ctx context.Context, tenantID, id string) error {
	if id == "" {
		return errors.New("swg.DeleteRule: id 必填")
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		tag, err := q.Exec(ctx, `DELETE FROM swg_rules WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("swg.DeleteRule delete: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelSWG, tenantID); err != nil {
			return fmt.Errorf("swg.DeleteRule notify: %w", err)
		}
		return nil
	})
}
