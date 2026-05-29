// Package policy 是策略模块:编写态(authoring)+ 编译(compiler 子包)+ 编译产物落库/激活。
// 对外只暴露 Service 接口(模块边界,总览 3.3 规则 1)。所有访问经 data.Store 的租户作用域事务。
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/policy/compiler"
)

// ErrNoActiveBundle 表示该租户尚无激活的编译产物。
var ErrNoActiveBundle = errors.New("policy: 无激活 PolicyBundle(请先 Compile)")

// Policy 是编写态策略(对外/落库模型,与 compiler.Policy 同形)。
type Policy struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Priority     int    `json:"priority"`
	SubjectKind  string `json:"subject_kind"`
	SubjectValue string `json:"subject_value"`
	Resource     string `json:"resource"`
	Action       string `json:"action"`
	Effect       string `json:"effect"`
}

// CompileResult 是一次编译的结果(幂等信息,策略编译器 L2 3.7)。
type CompileResult struct {
	Version     int64  `json:"version"`
	ContentHash string `json:"content_hash"`
	Changed     bool   `json:"changed"` // false=内容未变、未产新版、未下发(幂等)
}

// AppRegistry 提供已注册应用键集合,供编译期校验策略 resource 引用(由 resource 模块实现,经接口注入)。
type AppRegistry interface {
	AppKeys(ctx context.Context, tenantID string) (map[string]bool, error)
}

// Service 是 policy 模块对外唯一接口。
type Service interface {
	CreatePolicy(ctx context.Context, tenantID string, p *Policy) error
	// Compile 全量编译该租户激活策略 → PolicyBundle,落库并原子激活;内容未变则幂等跳过。
	Compile(ctx context.Context, tenantID string) (CompileResult, error)
	// ActiveBundle 读该租户当前激活的编译产物(供 xds-server 下发)。
	ActiveBundle(ctx context.Context, tenantID string) (*xdsv1.PolicyBundle, error)
}

type service struct {
	store data.Store
	apps  AppRegistry // 可选:非 nil 时编译校验 resource 引用存在性
}

// Option 配置 policy 服务。
type Option func(*service)

// WithAppRegistry 注入应用注册表(编译期校验策略引用的应用已注册,编译器 L2 3.3①)。
func WithAppRegistry(r AppRegistry) Option { return func(s *service) { s.apps = r } }

// NewService 构造 policy 服务。
func NewService(store data.Store, opts ...Option) Service {
	s := &service{store: store}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *service) CreatePolicy(ctx context.Context, tenantID string, p *Policy) error {
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	if p.Priority == 0 {
		p.Priority = 100
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		_, err := q.Exec(ctx,
			`INSERT INTO policies (id, tenant_id, name, priority, subject_kind, subject_value, resource, action, effect)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			p.ID, tenantID, p.Name, p.Priority, p.SubjectKind, p.SubjectValue, p.Resource, p.Action, p.Effect)
		if err != nil {
			return fmt.Errorf("policy.CreatePolicy insert: %w", err)
		}
		return nil
	})
}

func (s *service) Compile(ctx context.Context, tenantID string) (CompileResult, error) {
	// 解析快照:已注册应用键(编译器 L2 3.3 显式输入)。在编译事务前读取(单租户 InTxRO);
	// 与编译事务间的微小漂移可接受(配额有界、低频编译),严格版本化留后续(L2 3.3 风险)。
	var knownApps map[string]bool
	if s.apps != nil {
		var err error
		knownApps, err = s.apps.AppKeys(ctx, tenantID)
		if err != nil {
			return CompileResult{}, fmt.Errorf("policy.Compile 读应用注册: %w", err)
		}
	}

	var res CompileResult
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		// 按租户事务级咨询锁串行化同租户并发编译:否则两个并发 Compile 读到相同 MAX(version)、
		// 算出相同新版,其一撞 uq_bundle_tenant_version 唯一索引回滚(安全但偶发 500)。
		// 锁随事务结束自动释放;不同租户哈希不同、互不阻塞。
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID); err != nil {
			return fmt.Errorf("policy.Compile 取租户编译锁: %w", err)
		}
		// 取该租户全部策略(全量编译,3.8)。
		policies, err := loadPolicies(ctx, q)
		if err != nil {
			return err
		}
		// 纯函数编译(fail-closed:出错不产 bundle)。
		bundle, err := compiler.Compile(tenantID, toCompilerPolicies(policies), knownApps)
		if err != nil {
			return err // 编译错误原样上抛(含策略 id/字段定位)
		}

		// 取当前激活版的 content_hash 与全局 max version(用于幂等与版本分配,3.7)。
		var activeHash string
		var haveActive bool
		var maxVersion int64
		// 注:以下 SELECT 不手工拼 WHERE tenant_id —— 靠 RLS 把可见行裁到当前租户上下文,
		// 故 MAX(version) 即"本租户最大版本"(每租户从 1 单调)。app_rw 为 NOBYPASSRLS。
		row := q.QueryRow(ctx,
			`SELECT content_hash FROM policy_bundles WHERE status = 'active'`)
		switch scanErr := row.Scan(&activeHash); {
		case scanErr == nil:
			haveActive = true
		case errors.Is(scanErr, data.ErrNoRows):
			haveActive = false
		default:
			return fmt.Errorf("policy.Compile 读激活版: %w", scanErr)
		}
		if err := q.QueryRow(ctx,
			`SELECT COALESCE(MAX(version), 0) FROM policy_bundles`).Scan(&maxVersion); err != nil {
			return fmt.Errorf("policy.Compile 读 max version: %w", err)
		}

		// 幂等:内容未变 → 不产新版、不下发(3.7)。
		if haveActive && activeHash == bundle.ContentHash {
			res = CompileResult{Version: maxVersion, ContentHash: bundle.ContentHash, Changed: false}
			return nil
		}

		// 原子激活:降级旧激活版 → 插新激活版(部分唯一索引保证至多一个 active)。
		newVersion := maxVersion + 1
		bundle.Version = newVersion
		compiled, err := json.Marshal(bundle)
		if err != nil {
			return fmt.Errorf("policy.Compile marshal bundle: %w", err)
		}
		if _, err := q.Exec(ctx,
			`UPDATE policy_bundles SET status = 'rolled_back' WHERE status = 'active'`); err != nil {
			return fmt.Errorf("policy.Compile 降级旧版: %w", err)
		}
		if _, err := q.Exec(ctx,
			`INSERT INTO policy_bundles (id, tenant_id, version, content_hash, compiled, status)
			 VALUES ($1,$2,$3,$4,$5,'active')`,
			uuid.NewString(), tenantID, newVersion, bundle.ContentHash, compiled); err != nil {
			return fmt.Errorf("policy.Compile 插新版: %w", err)
		}
		// 通知 xds-server 重建该租户快照下发(事务提交后投递,xDS server L2 3.5)。
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelPolicyBundle, tenantID); err != nil {
			return fmt.Errorf("policy.Compile 发变更通知: %w", err)
		}
		res = CompileResult{Version: newVersion, ContentHash: bundle.ContentHash, Changed: true}
		return nil
	})
	if err != nil {
		return CompileResult{}, err
	}
	return res, nil
}

func (s *service) ActiveBundle(ctx context.Context, tenantID string) (*xdsv1.PolicyBundle, error) {
	var bundle xdsv1.PolicyBundle
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		var compiled []byte
		row := q.QueryRow(ctx, `SELECT compiled FROM policy_bundles WHERE status = 'active'`)
		if scanErr := row.Scan(&compiled); scanErr != nil {
			if errors.Is(scanErr, data.ErrNoRows) {
				return ErrNoActiveBundle
			}
			return fmt.Errorf("policy.ActiveBundle scan: %w", scanErr)
		}
		if err := json.Unmarshal(compiled, &bundle); err != nil {
			return fmt.Errorf("policy.ActiveBundle unmarshal: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &bundle, nil
}

func loadPolicies(ctx context.Context, q data.Queries) ([]Policy, error) {
	rows, err := q.Query(ctx,
		`SELECT id, name, priority, subject_kind, subject_value, resource, action, effect
		 FROM policies ORDER BY priority, id`)
	if err != nil {
		return nil, fmt.Errorf("policy 读策略集: %w", err)
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.Priority, &p.SubjectKind, &p.SubjectValue, &p.Resource, &p.Action, &p.Effect); err != nil {
			return nil, fmt.Errorf("policy scan: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func toCompilerPolicies(ps []Policy) []compiler.Policy {
	out := make([]compiler.Policy, len(ps))
	for i, p := range ps {
		out[i] = compiler.Policy{
			ID: p.ID, Name: p.Name, Priority: p.Priority,
			SubjectKind: p.SubjectKind, SubjectValue: p.SubjectValue,
			Resource: p.Resource, Action: p.Action, Effect: p.Effect,
		}
	}
	return out
}
