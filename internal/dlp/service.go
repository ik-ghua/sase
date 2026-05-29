package dlp

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// Service 是 DLP 规则的编写/读取(租户作用域,经 data 层 RLS)。变更发 NOTIFY → xds-server 下发 PoP。
type Service interface {
	CreateRule(ctx context.Context, tenantID string, r *Rule) error
	ListRules(ctx context.Context, tenantID string) ([]Rule, error)
}

type service struct {
	store data.Store
}

// NewService 构造 DLP 规则服务。
func NewService(store data.Store) Service { return &service{store: store} }

func validSeverity(s string) bool {
	return s == SeverityLow || s == SeverityMedium || s == SeverityHigh
}

func (s *service) CreateRule(ctx context.Context, tenantID string, r *Rule) error {
	if r.Name == "" || r.Pattern == "" {
		return errors.New("dlp.CreateRule: name 与 pattern 必填")
	}
	if r.MatchType != MatchKeyword && r.MatchType != MatchRegex {
		return errors.New("dlp.CreateRule: match_type 须为 keyword|regex")
	}
	if r.Action != ActionBlock && r.Action != ActionAlert {
		return errors.New("dlp.CreateRule: action 须为 block|alert")
	}
	if r.Severity == "" {
		r.Severity = SeverityMedium
	}
	if !validSeverity(r.Severity) {
		return errors.New("dlp.CreateRule: severity 须为 low|medium|high")
	}
	// 正则规则:入库前校验可编译(fail-loud,免运行期静默不命中)
	if r.MatchType == MatchRegex {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("dlp.CreateRule: 正则非法: %w", err)
		}
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO dlp_rules (id, tenant_id, name, match_type, pattern, action, severity)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			uuid.NewString(), tenantID, r.Name, r.MatchType, r.Pattern, r.Action, r.Severity); err != nil {
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
			`SELECT name, match_type, pattern, action, severity FROM dlp_rules ORDER BY created_at`)
		if err != nil {
			return fmt.Errorf("dlp.ListRules query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r Rule
			if err := rows.Scan(&r.Name, &r.MatchType, &r.Pattern, &r.Action, &r.Severity); err != nil {
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
