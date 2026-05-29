package dlp

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// ErrNotFound 表示规则不存在(或在当前租户 RLS 上下文下不可见)。
var ErrNotFound = errors.New("dlp: 规则不存在")

// Service 是 DLP 规则的编写/读取(租户作用域,经 data 层 RLS)。变更发 NOTIFY → xds-server 下发 PoP。
type Service interface {
	CreateRule(ctx context.Context, tenantID string, r *Rule) error
	ListRules(ctx context.Context, tenantID string) ([]Rule, error)
	UpdateRule(ctx context.Context, tenantID, id string, r *Rule) error // 全量替换;不存在 → ErrNotFound
	DeleteRule(ctx context.Context, tenantID, id string) error          // 不存在 → ErrNotFound
}

type service struct {
	store data.Store
}

// NewService 构造 DLP 规则服务。
func NewService(store data.Store) Service { return &service{store: store} }

func validSeverity(s string) bool {
	return s == SeverityLow || s == SeverityMedium || s == SeverityHigh
}

// normalizeAndValidate 校验并补默认(Create/Update 共用);正则规则入库前校验可编译(fail-loud,免运行期静默不命中)。
func normalizeAndValidate(r *Rule) error {
	if r.Name == "" || r.Pattern == "" {
		return errors.New("dlp: name 与 pattern 必填")
	}
	if r.MatchType != MatchKeyword && r.MatchType != MatchRegex {
		return errors.New("dlp: match_type 须为 keyword|regex")
	}
	if r.Action != ActionBlock && r.Action != ActionAlert {
		return errors.New("dlp: action 须为 block|alert")
	}
	if r.Severity == "" {
		r.Severity = SeverityMedium
	}
	if !validSeverity(r.Severity) {
		return errors.New("dlp: severity 须为 low|medium|high")
	}
	if r.MatchType == MatchRegex {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("dlp: 正则非法: %w", err)
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
			`INSERT INTO dlp_rules (id, tenant_id, name, match_type, pattern, action, severity)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			r.ID, tenantID, r.Name, r.MatchType, r.Pattern, r.Action, r.Severity); err != nil {
			return fmt.Errorf("dlp.CreateRule insert: %w", err)
		}
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelDLP, tenantID); err != nil {
			return fmt.Errorf("dlp.CreateRule notify: %w", err)
		}
		return nil
	})
}

func (s *service) ListRules(ctx context.Context, tenantID string) ([]Rule, error) {
	var out []Rule
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, err := q.Query(ctx,
			`SELECT id, name, match_type, pattern, action, severity FROM dlp_rules ORDER BY created_at`)
		if err != nil {
			return fmt.Errorf("dlp.ListRules query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r Rule
			if err := rows.Scan(&r.ID, &r.Name, &r.MatchType, &r.Pattern, &r.Action, &r.Severity); err != nil {
				return fmt.Errorf("dlp.ListRules scan: %w", err)
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
		return errors.New("dlp.UpdateRule: id 必填")
	}
	if err := normalizeAndValidate(r); err != nil {
		return err
	}
	r.ID = id
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		tag, err := q.Exec(ctx,
			`UPDATE dlp_rules SET name=$2, match_type=$3, pattern=$4, action=$5, severity=$6 WHERE id=$1`,
			id, r.Name, r.MatchType, r.Pattern, r.Action, r.Severity)
		if err != nil {
			return fmt.Errorf("dlp.UpdateRule update: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelDLP, tenantID); err != nil {
			return fmt.Errorf("dlp.UpdateRule notify: %w", err)
		}
		return nil
	})
}

// DeleteRule 删除 id 指向的规则(RLS 限本租户;跨租户/不存在 id → 0 行 → ErrNotFound)。
func (s *service) DeleteRule(ctx context.Context, tenantID, id string) error {
	if id == "" {
		return errors.New("dlp.DeleteRule: id 必填")
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		tag, err := q.Exec(ctx, `DELETE FROM dlp_rules WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("dlp.DeleteRule delete: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelDLP, tenantID); err != nil {
			return fmt.Errorf("dlp.DeleteRule notify: %w", err)
		}
		return nil
	})
}
