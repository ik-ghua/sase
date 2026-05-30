package risk

// 风险评分**持久化快照层**(Slice:risk RLS 持久化)。
//
// 背景:Service 是内存评分(规则加权 + TTL 衰减,见 service.go);权威评分态在内存,无持久化 →
// 运维/重启后看不到最新风险态。本文件加**附加的、可选的**持久化:评分变更后 best-effort 把
// (tenant,subject) 最新快照 upsert 到 risk_scores(经 store.InTx 走 RLS),并提供只读查询 GetScore。
//
// 目标:① 不改内存评分逻辑(持久化纯旁路,失败仅记日志不阻断评分);② 严格 RLS(经 InTx/InTxRO 注入
// 租户上下文,跨租户隔离由 DB 强制);③ store 可选(nil 则退化为纯内存现状,向后兼容既有 NewService 调用方)。
//
// 局限(诚实):本表是快照(每主体一行,upsert 覆盖),**非事件流**——不保留历史评分序列(事件流待 ClickHouse,
// L2 后续);快照可能短暂落后内存(best-effort 异步语义下);TTL 衰减不主动回写(下次评分变更才刷新快照)。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ikuai8/sase/internal/data"
)

// ErrNoScore 表示该 (tenant,subject) 无持久化快照(未评分过,或快照层未启用时不会到此)。
var ErrNoScore = errors.New("risk: 该主体无持久化风险快照")

// Score 是一条持久化风险快照(对应 risk_scores 一行;只读查询端点返回此结构)。
// 与内存 Assessment 区别:Assessment.ComputedAt 是内存算出时刻、Score.UpdatedAt 是快照落库时刻;
// 复用 Level / Factor 类型(不另造平行类型)。
type Score struct {
	Subject   string    `json:"subject"`
	Score     int       `json:"score"`
	Level     Level     `json:"level"`
	Factors   []Factor  `json:"factors"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WithStore 注入可选持久化快照层。不破坏既有 NewService 调用方(默认 nil = 纯内存)。
func WithStore(store data.Store) Option {
	return func(s *Service) { s.store = store }
}

// persistSnapshot 在评分变更后 best-effort 把当前快照 upsert 到 risk_scores(经 InTx 走 RLS)。
// **失败仅记日志、不返回错误**:持久化是旁路,不能阻断内存评分/撤销链(评分权威在内存)。
// 仅在配置了 store 时调用(observe 内已判 s.store != nil)。
func (s *Service) persistSnapshot(tenantID, subject string, a Assessment) {
	var factorsJSON []byte
	if len(a.Factors) > 0 {
		b, err := json.Marshal(a.Factors)
		if err != nil {
			log.Printf("[risk] 快照 factors 序列化失败 tenant=%s subject=%s: %v", tenantID, subject, err)
			// 序列化失败不阻断:factors 置 NULL 仍落 score/level(可解释性降级,核心快照保留)
		} else {
			factorsJSON = b
		}
	}
	// 持久化独立于请求 ctx(评分突变回调常在 best-effort 异步路径;同 audit 写不被请求取消影响),
	// 但加短超时防 DB 卡死拖垮调用方。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		_, e := q.Exec(ctx,
			`INSERT INTO risk_scores (tenant_id, subject, score, level, factors, updated_at)
			 VALUES ($1,$2,$3,$4,$5, now())
			 ON CONFLICT (tenant_id, subject)
			 DO UPDATE SET score = EXCLUDED.score,
			               level = EXCLUDED.level,
			               factors = EXCLUDED.factors,
			               updated_at = now()`,
			tenantID, subject, a.Score, string(a.Level), factorsJSON)
		return e
	})
	if err != nil {
		log.Printf("[risk] 快照持久化失败(不阻断评分)tenant=%s subject=%s: %v", tenantID, subject, err)
	}
}

// GetScore 读某主体最新持久化快照(经 InTxRO 走 RLS;platform_admin 由调用方传 path-tid 进上下文)。
// 未启用快照层 → ErrNoStore(fail-loud:端点存在但持久化未配,调用方据此返 503/404);无行 → ErrNoScore。
func (s *Service) GetScore(ctx context.Context, tenantID, subject string) (*Score, error) {
	if s.store == nil {
		return nil, ErrNoStore
	}
	if tenantID == "" || subject == "" {
		return nil, errors.New("risk.GetScore: tenant_id 与 subject 必填")
	}
	var (
		score     int
		level     string
		factorsdb []byte
		updatedAt time.Time
	)
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`SELECT score, level, factors, updated_at FROM risk_scores WHERE subject = $1`,
			subject) // tenant_id 由 RLS 上下文约束,无需显式 WHERE(隔离权威在 RLS)
		if e := row.Scan(&score, &level, &factorsdb, &updatedAt); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNoScore
			}
			return fmt.Errorf("risk.GetScore scan: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := &Score{Subject: subject, Score: score, Level: Level(level), UpdatedAt: updatedAt}
	out.Factors = decodeFactors(factorsdb, tenantID, subject)
	return out, nil
}

// decodeFactors 把库中 factors jsonb 原始字节解码为 []Factor;**反序列化失败不致命**——返回 nil
// (核心快照 score/level 仍可用,可解释性降级为空),并记日志供排障。GetScore / ListScores 复用此单源。
// raw 为空(NULL 列)直接返回 nil(无 factors,非错误)。
func decodeFactors(raw []byte, tenantID, subject string) []Factor {
	if len(raw) == 0 {
		return nil
	}
	var factors []Factor
	if e := json.Unmarshal(raw, &factors); e != nil {
		log.Printf("[risk] 快照 factors 反序列化失败 tenant=%s subject=%s: %v", tenantID, subject, e)
		return nil
	}
	return factors
}

// ErrNoStore 表示快照层未配置(WithStore 未注入)——GetScore 无法读持久化态(fail-loud)。
var ErrNoStore = errors.New("risk: 持久化快照层未配置(WithStore 未注入)")

// ListScores 列某租户全部持久化风险快照(经 InTxRO 走 RLS;platform_admin 由调用方传 path-tid 进上下文)。
// 排序:**score 降序、subject 升序**(高风险优先、同分稳定字典序)。
// 未启用快照层 → ErrNoStore(fail-loud,同 GetScore);空租户 → 空切片(非 nil,便 JSON 序列化为 [])。
// 跨租户隔离权威在 RLS:WHERE 不带 tenant_id(由 InTxRO 注入的租户上下文约束),他租户行不可见。
func (s *Service) ListScores(ctx context.Context, tenantID string) ([]Score, error) {
	if s.store == nil {
		return nil, ErrNoStore
	}
	if tenantID == "" {
		return nil, errors.New("risk.ListScores: tenant_id 必填")
	}
	out := []Score{} // 非 nil:空租户序列化为 [] 而非 null
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, e := q.Query(ctx,
			`SELECT subject, score, level, factors, updated_at FROM risk_scores
			 ORDER BY score DESC, subject ASC`) // tenant_id 由 RLS 上下文约束(隔离权威在 RLS)
		if e != nil {
			return fmt.Errorf("risk.ListScores query: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				sc        Score
				level     string
				factorsdb []byte
			)
			if e := rows.Scan(&sc.Subject, &sc.Score, &level, &factorsdb, &sc.UpdatedAt); e != nil {
				return fmt.Errorf("risk.ListScores scan: %w", e)
			}
			sc.Level = Level(level)
			sc.Factors = decodeFactors(factorsdb, tenantID, sc.Subject)
			out = append(out, sc)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
