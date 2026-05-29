// Package tenant 是租户模块:租户 CRUD + 生命周期 + 配额(L1 3.3 Tenant)。
// 对外只暴露 Service 接口(模块边界,控制面 L2 总览 3.3 规则 1:模块间只经接口调用)。
package tenant

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ikuai8/sase/internal/data"
)

// ErrNotFound 表示租户不存在(或在当前 RLS 上下文下不可见)。
var ErrNotFound = errors.New("tenant: 不存在")

// ErrNoPatchFields 表示 PATCH 未提供任何可更新字段。
var ErrNoPatchFields = errors.New("tenant: 无可更新字段")

// ErrInvalidPatch 表示 PATCH 字段值非法(status 非枚举 / name 空)——handler 据此返 400(sentinel,避免字符串匹配)。
var ErrInvalidPatch = errors.New("tenant: patch 字段非法")

// ErrNotDecommissioning 表示取消注销时租户不在 offboarding 宽限期(不存在或非 offboarding)。
var ErrNotDecommissioning = errors.New("tenant: 不在注销宽限期,无法取消")

// validStatuses 是合法的租户生命周期状态(改状态时校验枚举,防写入任意值)。
// 'decommissioned' = 终态(硬删完成,DEK 已销毁,数据等效不可恢复;tenant 行保留作历史)。
var validStatuses = map[string]bool{
	"active":         true,
	"suspended":      true,
	"offboarding":    true,
	"decommissioned": true,
}

// maxDecommissionGrace 是注销宽限期上限(防超大值致 timestamptz 溢出 / 误用永不硬删);365 天足够任何挽留/导出窗口。
const maxDecommissionGrace = 365 * 24 * time.Hour

// Tenant 是租户领域模型(L1 3.3 Tenant 的最小子集)。
// quota 字段:**nil = "不限"(unlimited)**;**非 nil = 上限**(含 0 = 完全限死);本模块只持久化,
// 业务在写入路径(admission)校验上限。TODO(LP-PC1):PATCH *int 不能表达"置回 nil",待 ClearXxx flag/sentinel 扩展。
type Tenant struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Status           string     `json:"status"`                       // active / suspended / offboarding
	Plan             string     `json:"plan"`                         // 加密档/订阅档(standard/gm/...);业务命名,本模块不枚举校验
	DecommissionAt   *time.Time `json:"decommission_at,omitempty"`    // 计划硬删时刻(注销宽限期末);nil=未注销
	MaxUsers         *int       `json:"max_users,omitempty"`          // 用户数上限;nil=不限
	MaxPolicies      *int       `json:"max_policies,omitempty"`       // 策略数上限;nil=不限
	MaxBandwidthMbps *int       `json:"max_bandwidth_mbps,omitempty"` // 带宽上限 Mbps;nil=不限
}

// tenantColumns 是 Get/Update/Decommission/Cancel RETURNING 的统一列序(单一来源,防漂移)。
const tenantColumns = "id, name, status, plan, decommission_at, max_users, max_policies, max_bandwidth_mbps"

// scanTenant 把 tenantColumns 顺序的一行扫进 t(单一扫描点,与 tenantColumns 同源)。
func scanTenant(row pgx.Row, t *Tenant) error {
	return row.Scan(&t.ID, &t.Name, &t.Status, &t.Plan, &t.DecommissionAt,
		&t.MaxUsers, &t.MaxPolicies, &t.MaxBandwidthMbps)
}

// Patch 是租户部分更新(PATCH)的可选字段:nil = 不改该字段(PATCH 语义)。
// 支持:name / status(生命周期)+ plan(加密档/订阅档)+ 3 项配额(MaxUsers/Policies/BandwidthMbps)。
// **配额 *int 语义**:nil=不改;**0=完全限死(业务硬封顶,有意支持,运维须显式)**;>0=上限;<0 拒(ErrInvalidPatch)。
// **TODO(LP-PC1):本刀 *int 不能表达"改回 null/不限"**——若需此能力,后续可加 `ClearMaxUsers *bool` 显式标记或 sentinel,统一在 LP-PC1 字段细化时引入。
type Patch struct {
	Name             *string `json:"name,omitempty"`
	Status           *string `json:"status,omitempty"`
	Plan             *string `json:"plan,omitempty"`
	MaxUsers         *int    `json:"max_users,omitempty"`
	MaxPolicies      *int    `json:"max_policies,omitempty"`
	MaxBandwidthMbps *int    `json:"max_bandwidth_mbps,omitempty"`
}

// Service 是 tenant 模块对外唯一接口。
type Service interface {
	Get(ctx context.Context, tenantID string) (*Tenant, error)
	Create(ctx context.Context, t *Tenant) error
	// Update 部分更新租户(平台运维:停用/恢复/改名,PC-API-2a)。仅改 patch 中非 nil 字段;
	// 走业务 InTx(目标租户 RLS 上下文,平台身份经 authz);RLS WITH CHECK 保证只动该租户行。
	Update(ctx context.Context, tenantID string, patch Patch) (*Tenant, error)
	// Decommission 标注租户进入注销宽限期(PC-API-2b,平台运维):status→offboarding、decommission_at=now+grace。
	// **软删**:数据/DEK 保留至宽限期末;硬删(销毁 DEK,不可逆)是后续刀(secret 模块 + 定时清扫)。grace<=0 报错。
	Decommission(ctx context.Context, tenantID string, grace time.Duration) (*Tenant, error)
	// CancelDecommission 在宽限期内取消注销:status→active、decommission_at=NULL(仅当前 offboarding 才可,否则 ErrNotDecommissioning)。
	CancelDecommission(ctx context.Context, tenantID string) (*Tenant, error)
}

// KeyCreator 是 tenant 模块对密钥生成的最小要求(由 secret 模块满足);避免 tenant→secret 硬耦合(总览 3.3 规则 1)。
// 在 Create 同事务内调用 → 建租户 + 建 DEK 原子(任一失败一起回滚)。
type KeyCreator interface {
	CreateInTx(ctx context.Context, q data.Queries, tenantID string) error
}

type service struct {
	store      data.Store // 依赖横切数据层(不绕过,总览 3.3 规则 3)
	keyCreator KeyCreator // 可选:Create 时同事务建 DEK(Slice34 secret 模块)
}

// Option 配置 tenant 服务。
type Option func(*service)

// WithKeyCreator 注入密钥生成器(secret 模块满足);设置后 Create 在同事务内建 DEK。
// 未设 → 建租户不建 DEK(向后兼容;dev/test 不要求 secret 接入)。
func WithKeyCreator(k KeyCreator) Option {
	return func(s *service) { s.keyCreator = k }
}

// NewService 构造 tenant 服务(依赖注入 data.Store)。
func NewService(store data.Store, opts ...Option) Service {
	s := &service{store: store}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Get 在租户自身 RLS 上下文下查租户行(只能见自身 id)。
func (s *service) Get(ctx context.Context, tenantID string) (*Tenant, error) {
	var t Tenant
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx, `SELECT `+tenantColumns+` FROM tenants WHERE id = $1`, tenantID)
		if scanErr := scanTenant(row, &t); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("tenant.Get scan: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Update 部分更新租户(PC-API-2a)。动态拼 SET 仅含 patch 非 nil 字段;status 校验枚举;
// 无字段 → ErrNoPatchFields;租户不存在(RETURNING 0 行)→ ErrNotFound。
func (s *service) Update(ctx context.Context, tenantID string, patch Patch) (*Tenant, error) {
	if tenantID == "" {
		return nil, errors.New("tenant.Update: tenant_id 必填")
	}
	var sets []string
	var args []any
	add := func(col string, val any) {
		args = append(args, val)
		sets = append(sets, col+"=$"+strconv.Itoa(len(args)))
	}
	if patch.Name != nil {
		if *patch.Name == "" {
			return nil, fmt.Errorf("%w: name 不可为空", ErrInvalidPatch)
		}
		add("name", *patch.Name)
	}
	if patch.Status != nil {
		if !validStatuses[*patch.Status] {
			return nil, fmt.Errorf("%w: status %q 须 active/suspended/offboarding", ErrInvalidPatch, *patch.Status)
		}
		add("status", *patch.Status)
	}
	if patch.Plan != nil {
		if *patch.Plan == "" {
			return nil, fmt.Errorf("%w: plan 不可为空(若需清空,业务命名应保留默认 standard)", ErrInvalidPatch)
		}
		add("plan", *patch.Plan)
	}
	// 配额(quota):非 nil 即设;**0 = 完全限死**(业务硬封顶,有意支持,运维须显式);<0 → ErrInvalidPatch;
	// DB CHECK 兜底(`>= 0`)防绕 service 直写。**TODO(LP-PC1):本刀 *int 不能"置回 null/不限",待 ClearXxx flag 或 sentinel 扩展。**
	setQuota := func(col string, v *int) error {
		if v == nil {
			return nil
		}
		if *v < 0 {
			return fmt.Errorf("%w: %s 须 >= 0(0=完全限死)", ErrInvalidPatch, col)
		}
		add(col, *v)
		return nil
	}
	if err := setQuota("max_users", patch.MaxUsers); err != nil {
		return nil, err
	}
	if err := setQuota("max_policies", patch.MaxPolicies); err != nil {
		return nil, err
	}
	if err := setQuota("max_bandwidth_mbps", patch.MaxBandwidthMbps); err != nil {
		return nil, err
	}
	if len(sets) == 0 {
		return nil, ErrNoPatchFields
	}
	args = append(args, tenantID) // WHERE id = $N
	query := "UPDATE tenants SET " + strings.Join(sets, ", ") +
		" WHERE id=$" + strconv.Itoa(len(args)) + " RETURNING " + tenantColumns

	var t Tenant
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx, query, args...)
		if scanErr := scanTenant(row, &t); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("tenant.Update: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Decommission 标注注销宽限期:status→offboarding、decommission_at=now+grace(软删,数据/DEK 保留至宽限期末)。
func (s *service) Decommission(ctx context.Context, tenantID string, grace time.Duration) (*Tenant, error) {
	if tenantID == "" {
		return nil, errors.New("tenant.Decommission: tenant_id 必填")
	}
	if grace <= 0 {
		return nil, fmt.Errorf("%w: 宽限期须 > 0", ErrInvalidPatch)
	}
	if grace > maxDecommissionGrace {
		return nil, fmt.Errorf("%w: 宽限期超上限(%s)", ErrInvalidPatch, maxDecommissionGrace)
	}
	var t Tenant
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`UPDATE tenants SET status='offboarding', decommission_at = now() + $2::interval
			 WHERE id=$1 RETURNING `+tenantColumns,
			tenantID, fmt.Sprintf("%d seconds", int64(grace.Seconds())))
		if scanErr := scanTenant(row, &t); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("tenant.Decommission: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// CancelDecommission 取消注销:仅当前 offboarding 才回 active + 清 decommission_at;否则 ErrNotDecommissioning。
func (s *service) CancelDecommission(ctx context.Context, tenantID string) (*Tenant, error) {
	if tenantID == "" {
		return nil, errors.New("tenant.CancelDecommission: tenant_id 必填")
	}
	var t Tenant
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`UPDATE tenants SET status='active', decommission_at=NULL
			 WHERE id=$1 AND status='offboarding' RETURNING `+tenantColumns,
			tenantID)
		if scanErr := scanTenant(row, &t); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return ErrNotDecommissioning // 不存在或非 offboarding(WHERE 不匹配)
			}
			return fmt.Errorf("tenant.CancelDecommission: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Create 创建租户行。RLS WITH CHECK 要求 id == app.current_tenant,故事务上下文设为新租户自身 id。
// 若注入了 KeyCreator(secret 模块),在同事务内建 DEK——**建租户与建 DEK 原子**(任一失败一起回滚)。
func (s *service) Create(ctx context.Context, t *Tenant) error {
	if t.ID == "" {
		return errors.New("tenant.Create: id 必填")
	}
	status := t.Status
	if status == "" {
		status = "active"
	}
	return s.store.InTx(ctx, t.ID, func(q data.Queries) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO tenants (id, name, status) VALUES ($1, $2, $3)`,
			t.ID, t.Name, status); err != nil {
			return fmt.Errorf("tenant.Create insert: %w", err)
		}
		if s.keyCreator != nil {
			if err := s.keyCreator.CreateInTx(ctx, q, t.ID); err != nil {
				return fmt.Errorf("tenant.Create: 建 DEK(secret): %w", err)
			}
		}
		return nil
	})
}
