// Package platform 是控制面**平台级模块**(总览第 1 平台级模块,首次编码):为平台运维控制台
// (app-admin)提供**跨租户**只读聚合。它走 data 层 `InPlatformTx`(app_platform_ro、不注入
// app.current_tenant),只读策展平台视图(tenant_summary 等),**不碰租户业务基表**。
//
// 授权由 authz 平台 RBAC 在 API 层把关(platform_admin),非 RLS——平台路径按定义跨租户
// (平台控制台 L2 3.1;数据访问层 L2 3.6)。跨租户写/单租户明细仍走业务 InTx(目标租户 RLS 上下文 + 理由 + 审计)。
package platform

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ikuai8/sase/internal/data"
)

// TenantSummary 是平台视角的租户摘要(策展字段:运营必需元数据,不含用户/策略明细)。
// quota 字段 nil = 不限(unlimited);非 nil = 上限。
type TenantSummary struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Status           string     `json:"status"` // active / suspended / offboarding
	Plan             string     `json:"plan"`
	CreatedAt        time.Time  `json:"created_at"`
	DecommissionAt   *time.Time `json:"decommission_at,omitempty"`    // 注销宽限期末(offboarding 时);nil=未注销
	MaxUsers         *int       `json:"max_users,omitempty"`          // 用户数上限;nil=不限
	MaxPolicies      *int       `json:"max_policies,omitempty"`       // 策略数上限;nil=不限
	MaxBandwidthMbps *int       `json:"max_bandwidth_mbps,omitempty"` // 带宽上限 Mbps;nil=不限
}

// DEKDestroyer 是硬删 sweep 对密钥销毁能力的最小要求(secret.Service 经 cmd 适配满足)。
// 适配器应吞掉"无 DEK 行"(老租户)语义当成已销毁,prevent 阻塞老租户的 status 推进。
type DEKDestroyer interface {
	DestroyTenantKey(ctx context.Context, tenantID string) error
}

// TenantStatusSetter 是 sweep 对租户状态推进能力的最小要求(tenant.Service.Update 经 cmd 适配满足)。
type TenantStatusSetter interface {
	SetStatus(ctx context.Context, tenantID, status string) error
}

// SweepResult 是硬删扫描结果(JSON 序列化用)。
type SweepResult struct {
	Processed []string    `json:"processed"`         // 成功硬删的租户 id
	Skipped   []SweepSkip `json:"skipped,omitempty"` // 跳过(及原因)
}

// SweepSkip 是单租户的跳过原因。
type SweepSkip struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

// Service 是 platform 模块对外接口(跨租户只读聚合 + sweep 编排)。
type Service interface {
	// ListTenants 跨租户列出所有租户摘要(平台运维控制台)。经 InPlatformTx 读策展视图 tenant_summary。
	ListTenants(ctx context.Context) ([]TenantSummary, error)
	// ListDecommissionsDue 跨租户列出"宽限期已到、待硬删"的租户 ID(status='offboarding' 且 decommission_at<now)。
	ListDecommissionsDue(ctx context.Context) ([]string, error)
	// RunDecommissionSweep 编排硬删:ListDecommissionsDue → 每条 DEKDestroyer.DestroyTenantKey + TenantStatusSetter.SetStatus(decommissioned)。
	// 各租户独立、各自原子幂等、失败不阻塞其它(进 Skipped)。**未配置 destroyer/setStatus → 返错**(fail-loud,防误用)。
	// 同一函数供 HTTP 端点(手工触发)与 cmd 后台 cron(周期自动)调用——单一编排源,避免 drift。
	RunDecommissionSweep(ctx context.Context) (SweepResult, error)
}

type service struct {
	store     data.Store
	destroyer DEKDestroyer       // sweep 注入(可选;未设则 RunDecommissionSweep 报错)
	setStatus TenantStatusSetter // sweep 注入(可选;未设则 RunDecommissionSweep 报错)
}

// Option 配置 platform 服务。
type Option func(*service)

// WithDEKDestroyer 注入 DEK 销毁能力(cmd 用 secret.Service 适配器满足;sweep 用)。
func WithDEKDestroyer(d DEKDestroyer) Option { return func(s *service) { s.destroyer = d } }

// WithTenantStatusSetter 注入租户状态设置能力(cmd 用 tenant.Service 适配器满足;sweep 用)。
func WithTenantStatusSetter(st TenantStatusSetter) Option {
	return func(s *service) { s.setStatus = st }
}

// NewService 构造 platform 服务;opts 可注入 sweep 依赖(destroyer/setStatus,见上)。
func NewService(store data.Store, opts ...Option) Service {
	s := &service{store: store}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *service) ListTenants(ctx context.Context) ([]TenantSummary, error) {
	var out []TenantSummary
	err := s.store.InPlatformTx(ctx, func(q data.Queries) error {
		rows, qerr := q.Query(ctx,
			`SELECT id, name, status, plan, created_at, decommission_at,
			        max_users, max_policies, max_bandwidth_mbps
			 FROM tenant_summary ORDER BY created_at`)
		if qerr != nil {
			return fmt.Errorf("platform.ListTenants query: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			var t TenantSummary
			if err := rows.Scan(&t.ID, &t.Name, &t.Status, &t.Plan, &t.CreatedAt, &t.DecommissionAt,
				&t.MaxUsers, &t.MaxPolicies, &t.MaxBandwidthMbps); err != nil {
				return fmt.Errorf("platform.ListTenants scan: %w", err)
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []TenantSummary{}
	}
	return out, nil
}

// ListDecommissionsDue 经 InPlatformTx 跨租户查"待硬删"租户 ID(策展视图,绕 RLS via 视图 owner)。
// **条件**:status='offboarding' AND decommission_at<now;按 decommission_at 升序(先到期先处理)。
func (s *service) ListDecommissionsDue(ctx context.Context) ([]string, error) {
	var out []string
	err := s.store.InPlatformTx(ctx, func(q data.Queries) error {
		rows, qerr := q.Query(ctx,
			`SELECT id FROM tenant_summary
			 WHERE status = 'offboarding' AND decommission_at IS NOT NULL AND decommission_at < now()
			 ORDER BY decommission_at ASC`)
		if qerr != nil {
			return fmt.Errorf("platform.ListDecommissionsDue query: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("platform.ListDecommissionsDue scan: %w", err)
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// ErrSweepNotConfigured 表示 RunDecommissionSweep 被调用但缺 DEKDestroyer/TenantStatusSetter(配置错;fail-loud)。
var ErrSweepNotConfigured = errors.New("platform: 硬删 sweep 未配置(需 WithDEKDestroyer + WithTenantStatusSetter)")

// RunDecommissionSweep 编排硬删扫描。注入的 destroyer/setStatus 缺一即报错。
// 各租户独立失败不阻塞其它;失败租户进 Skipped。返回的 Processed/Skipped 都是非 nil 切片(JSON 友好)。
func (s *service) RunDecommissionSweep(ctx context.Context) (SweepResult, error) {
	out := SweepResult{Processed: []string{}}
	if s.destroyer == nil || s.setStatus == nil {
		return out, ErrSweepNotConfigured
	}
	due, err := s.ListDecommissionsDue(ctx)
	if err != nil {
		return out, err
	}
	for _, tid := range due {
		if err := s.destroyer.DestroyTenantKey(ctx, tid); err != nil {
			out.Skipped = append(out.Skipped, SweepSkip{TenantID: tid, Reason: "destroy DEK: " + err.Error()})
			continue
		}
		if err := s.setStatus.SetStatus(ctx, tid, "decommissioned"); err != nil {
			out.Skipped = append(out.Skipped, SweepSkip{TenantID: tid, Reason: "set status: " + err.Error()})
			continue
		}
		out.Processed = append(out.Processed, tid)
	}
	return out, nil
}
