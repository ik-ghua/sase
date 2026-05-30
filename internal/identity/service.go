// Package identity 是身份模块:租户内用户与外部 IdP 映射(L1 3.3 Identity 的最小子集)。
// 对外只暴露 Service 接口;所有访问经 data.Store 的租户作用域事务(RLS 强隔离)。
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/authz"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
)

// ErrNoSigner 表示未配置签发器,无法签发会话凭证。
var ErrNoSigner = errors.New("identity: 未配置凭证签发器(NewService 需 WithSigner)")

// ErrUserNotFound 表示按 id 查不到用户(供凭证刷新等交叉核对路径分流)。
var ErrUserNotFound = errors.New("identity: 用户不存在")

// MaxTTL 是会话凭证最大 TTL(短 TTL 设计前提,L1 3.8)。签发时上限钳制;吊销项 expire_at 以此为界,
// 保证"撤销项有效期 ≥ 凭证剩余有效期"(撤销发生于签发之后,故 now_revoke+MaxTTL ≥ 凭证 exp)——
// 否则长 TTL 凭证的吊销项会先于凭证过期被滤除,导致被撤销凭证重新可用(fail-open)。
const MaxTTL = time.Hour

// MaxAdminTTL 是管理面 admin 令牌最大 TTL(限令牌泄露窗口;管理会话可比 ZTNA 会话稍长)。
const MaxAdminTTL = 12 * time.Hour

// User 是租户作用域的用户(最小子集)。
type User struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	ExternalID string `json:"external_id"` // IdP 侧主键
	Email      string `json:"email"`
	Status     string `json:"status"` // active / disabled
}

// Service 是 identity 模块对外唯一接口。
type Service interface {
	Create(ctx context.Context, u *User) error
	ListByTenant(ctx context.Context, tenantID string) ([]User, error)
	// EnsureUserByExternalID 按 (tenant_id, idp_id, external_id) 在租户内找用户;无则创建并返回。
	// 找/建在同一 RLS 事务内;并发同时建相同 sub 的两次回调:users 表 UNIQUE NULLS NOT DISTINCT 约束兜底
	// (migrations/0020,Slice37b-1 多 IdP 支持)。
	// **idpID 必填**(OIDC 回调路径必经 IdPConfig);手建用户走 Create 路径,idp_id=NULL,UNIQUE 退化为 (tenant_id, external_id)。
	// 邮箱以最新**非空**值更新(防 IdP 未配 email scope 时空覆盖,Slice37a H2)。
	EnsureUserByExternalID(ctx context.Context, tenantID, idpID, externalID, email string) (User, error)
	// IssueCredential 签发短 TTL 会话凭证(L1 3.4 令牌交换 / 3.8 短 TTL);未配置签发器返回 ErrNoSigner。
	// 返回 token 与其 jti(供后续按 jti 撤销)。
	IssueCredential(ctx context.Context, tenantID, userID string, groups []string, posture string, ttl time.Duration) (token, jti string, err error)
	// RevokeCredential 按 jti 撤销凭证:写吊销表 + 发变更通知,经 xDS 独立流秒级下发 PoP(ZTNA 硬化 L2 3.4)。
	RevokeCredential(ctx context.Context, tenantID, jti, subject, reason string) error
	// GCExpiredRevocations 删除该租户已过期的吊销项(expire_at < now;过期=凭证已自然失效,吊销项无用)。
	// 租户作用域(RLS),返回删除条数。跨租户全量清扫属运维(app_rw NOBYPASSRLS 不能枚举租户,见实现注释)。
	GCExpiredRevocations(ctx context.Context, tenantID string) (int64, error)
	// IsRevoked 经 InTxRO(RLS)查某 jti 是否存在**未过期**的吊销项(供凭证刷新纵深门禁,Slice81 §3.6.1)。
	// 仅判未过期项:过期吊销项对应凭证本就失效,残留无害(同 GC 语义)。
	IsRevoked(ctx context.Context, tenantID, jti string) (bool, error)
	// IssueAdminToken 签发管理面 admin 令牌(带角色;tenantID 为 tenant_admin/auditor 作用域,platform_admin 可空)。
	IssueAdminToken(ctx context.Context, subject, role, tenantID string, ttl time.Duration) (string, error)
	// IssuerPublicKey 返回签发公钥(算法无关,下发 PoP 作 TrustBundle 离线验证);未配置返回 ok=false。
	IssuerPublicKey() (cred.PublicKey, bool)
	// GetUserStatus 经 InTxRO(RLS)按 id 取用户状态(active/disabled);不存在返 ErrUserNotFound。
	// 供会话凭证刷新的「用户仍 active」门禁(Slice81 §3.6.1 三闸之一,自愈式注销生效)。
	GetUserStatus(ctx context.Context, tenantID, userID string) (status string, err error)
}

// RevocationNotifier 在凭证撤销后被通知,用于向终端实时通道下推(端提速,best-effort;由 control.Hub 实现)。
type RevocationNotifier interface {
	NotifyRevoked(tenantID, jti string)
}

// RiskFunc 返回某 subject 当前风险(score 0-100, level)。由 risk 引擎适配注入(避免 identity 直接依赖 risk)。
type RiskFunc func(tenantID, subject string) (score int, level string)

type service struct {
	store    data.Store
	signer   *cred.Signer
	notifier RevocationNotifier
	risk     RiskFunc
}

// Option 配置 identity 服务。
type Option func(*service)

// WithSigner 注入会话凭证签发器(控制面持私钥)。
func WithSigner(s *cred.Signer) Option { return func(svc *service) { svc.signer = s } }

// WithRevocationNotifier 注入撤销通知器(撤销后经实时通道下推 revoke,端提速)。
func WithRevocationNotifier(n RevocationNotifier) Option {
	return func(svc *service) { svc.notifier = n }
}

// WithRiskSource 注入风险来源:签发凭证时取 subject 当前风险填入 risk claim(动态访问控制,risk L2 3.3)。
func WithRiskSource(f RiskFunc) Option { return func(svc *service) { svc.risk = f } }

// NewService 构造 identity 服务。
func NewService(store data.Store, opts ...Option) Service {
	svc := &service{store: store}
	for _, o := range opts {
		o(svc)
	}
	return svc
}

func (s *service) IssueCredential(_ context.Context, tenantID, userID string, groups []string, posture string, ttl time.Duration) (string, string, error) {
	if s.signer == nil {
		return "", "", ErrNoSigner
	}
	if tenantID == "" || userID == "" {
		return "", "", errors.New("identity.IssueCredential: tenant_id 与 user_id 必填")
	}
	if ttl > MaxTTL {
		ttl = MaxTTL // 仅上限钳制:保证吊销项(expire_at=now+MaxTTL)总能覆盖凭证有效期(ttl≤0 留给调用方/默认值处理)
	}
	jti := uuid.NewString()
	claims := cred.Claims{
		JTI:      jti,
		TenantID: tenantID,
		Subject:  userID,
		Groups:   groups,
		Posture:  posture,
	}
	if s.risk != nil { // 取当前风险填 claim(PoP PEP 据此作运行期条件;突变即时性由撤销补)
		claims.RiskScore, claims.RiskLevel = s.risk(tenantID, userID)
	}
	token, err := s.signer.Issue(claims, ttl, time.Now())
	if err != nil {
		return "", "", err
	}
	return token, jti, nil
}

// RevokeCredential 写吊销表并通知 xds-server(独立流秒级下发),并机会式顺手清本租户过期吊销项(同事务)。
// expire_at 设保守上界供 GC(凭证短 TTL)。
func (s *service) RevokeCredential(ctx context.Context, tenantID, jti, subject, reason string) error {
	if jti == "" {
		return errors.New("identity.RevokeCredential: jti 必填")
	}
	expireAt := time.Now().Add(MaxTTL) // 与签发上限同源,保证覆盖凭证剩余有效期
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO revocations (tenant_id, jti, subject, reason, expire_at)
			 VALUES ($1,$2,$3,$4,$5)
			 ON CONFLICT (tenant_id, jti) DO NOTHING`,
			tenantID, jti, subject, reason, expireAt); err != nil {
			return fmt.Errorf("identity.RevokeCredential insert: %w", err)
		}
		// PoP 路径(权威):NOTIFY → xDS 独立流下发吊销表(ZTNA 硬化 L2 3.4 层①)
		if _, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, data.NotifyChannelRevocation, tenantID); err != nil {
			return fmt.Errorf("identity.RevokeCredential notify: %w", err)
		}
		// 机会式 GC:顺手删本租户已过期吊销项(同事务、RLS 内),为活跃租户约束吊销表增长
		if _, err := q.Exec(ctx, `DELETE FROM revocations WHERE expire_at < now()`); err != nil {
			return fmt.Errorf("identity.RevokeCredential gc: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 端提速路径(非权威,best-effort):经实时通道向 Agent 下推 revoke(层②)。提交后触发。
	if s.notifier != nil {
		s.notifier.NotifyRevoked(tenantID, jti)
	}
	return nil
}

// GCExpiredRevocations 删本租户过期吊销项(RLS 内)。供显式/定时(按租户)清扫;跨租户全量清扫属运维:
// app_rw 是 NOBYPASSRLS 且 tenants 表亦 RLS,应用无法枚举所有租户做全表清扫,该工作交 DB 维护作业
// (owner/pg_cron:DELETE FROM revocations WHERE expire_at < now())。过期项即便残留也无害:xDS 只下发未过期项、凭证已失效。
func (s *service) GCExpiredRevocations(ctx context.Context, tenantID string) (int64, error) {
	var n int64
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		ct, err := q.Exec(ctx, `DELETE FROM revocations WHERE expire_at < now()`)
		if err != nil {
			return fmt.Errorf("identity.GCExpiredRevocations: %w", err)
		}
		n = ct.RowsAffected()
		return nil
	})
	return n, err
}

// IsRevoked 见接口注释。RLS 保证只查本租户吊销项;只计未过期(expire_at > now)的命中。
func (s *service) IsRevoked(ctx context.Context, tenantID, jti string) (bool, error) {
	if tenantID == "" || jti == "" {
		return false, errors.New("identity.IsRevoked: tenant_id 与 jti 必填")
	}
	var revoked bool
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM revocations WHERE jti = $1 AND expire_at > now())`, jti)
		return row.Scan(&revoked)
	})
	if err != nil {
		return false, fmt.Errorf("identity.IsRevoked: %w", err)
	}
	return revoked, nil
}

func (s *service) IssueAdminToken(_ context.Context, subject, role, tenantID string, ttl time.Duration) (string, error) {
	if s.signer == nil {
		return "", ErrNoSigner
	}
	if subject == "" {
		return "", errors.New("identity.IssueAdminToken: subject 必填")
	}
	if !authz.ValidAdminRole(role) {
		return "", fmt.Errorf("identity.IssueAdminToken: 非法角色 %q", role)
	}
	if !authz.ScopeValid(role, tenantID) {
		return "", errors.New("identity.IssueAdminToken: 角色与租户作用域不符(platform_admin 须不带租户,其余须带)")
	}
	if ttl <= 0 || ttl > MaxAdminTTL {
		ttl = MaxAdminTTL // 上限钳制,限泄露窗口
	}
	// 注:admin 令牌与 ZTNA 会话令牌共用签发器,靠 Role 区分;生产宜分 audience/签发密钥(待加厚)。
	return s.signer.Issue(cred.Claims{Subject: subject, Role: role, TenantID: tenantID}, ttl, time.Now())
}

func (s *service) IssuerPublicKey() (cred.PublicKey, bool) {
	if s.signer == nil {
		return cred.PublicKey{}, false
	}
	return s.signer.Public(), true
}

// Create 在用户所属租户的 RLS 上下文下插入用户行(WITH CHECK 保证 tenant_id 一致)。
func (s *service) Create(ctx context.Context, u *User) error {
	if u.ID == "" || u.TenantID == "" {
		return errors.New("identity.Create: id 与 tenant_id 必填")
	}
	status := u.Status
	if status == "" {
		status = "active"
	}
	return s.store.InTx(ctx, u.TenantID, func(q data.Queries) error {
		_, err := q.Exec(ctx,
			`INSERT INTO users (id, tenant_id, external_id, email, status) VALUES ($1, $2, $3, $4, $5)`,
			u.ID, u.TenantID, u.ExternalID, u.Email, status)
		if err != nil {
			return fmt.Errorf("identity.Create insert: %w", err)
		}
		return nil
	})
}

// EnsureUserByExternalID 按 (tenant_id, external_id) 找用户;无则原子建。
// 流程:INSERT ... ON CONFLICT (tenant_id, external_id) DO UPDATE
//
//	(并发兜底:DB UNIQUE 约束 users_tenant_ext_unique 是单点强一致);RLS 事务内。
//
// 字段刷新策略(防数据降级):
//   - email:仅在 IdP 返回非空时刷新(`COALESCE(NULLIF(EXCLUDED.email,”), users.email)`),
//     避免某些 IdP 未配 email scope → 空串覆盖管理员先前手设的联系数据;
//   - status:**不动**,保留管理员手动 disabled 的状态(调用方负责校 status=active 后再签发,Slice37a H1)。
//
// Slice37b-1:idpID 参数支持多 IdP(同租户配企微+钉钉+飞书,跨 IdP 同 external_id 各自合法);
// idpID="" 走 NULL 路径(管理员手建/ZTNA,external_id 在租户内仍唯一,经 NULLS NOT DISTINCT)。
func (s *service) EnsureUserByExternalID(ctx context.Context, tenantID, idpID, externalID, email string) (User, error) {
	if tenantID == "" || externalID == "" {
		return User{}, errors.New("identity.EnsureUserByExternalID: tenant_id 与 external_id 必填")
	}
	// 把 idpID 折成 sql.NullString(空→NULL,非空→FK→idp_configs.id)
	var idpArg any
	if idpID != "" {
		idpArg = idpID
	}
	var u User
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		// 新建路径需要新 uuid;ON CONFLICT 时 EXCLUDED.id 不被采用(冲突保留原 id)。
		newID := uuid.NewString()
		row := q.QueryRow(ctx,
			`INSERT INTO users (id, tenant_id, idp_id, external_id, email, status)
			 VALUES ($1, $2, $3, $4, $5, 'active')
			 ON CONFLICT (tenant_id, idp_id, external_id)
			 DO UPDATE SET email = COALESCE(NULLIF(EXCLUDED.email, ''), users.email)
			 RETURNING id, tenant_id, external_id, email, status`,
			newID, tenantID, idpArg, externalID, email)
		return row.Scan(&u.ID, &u.TenantID, &u.ExternalID, &u.Email, &u.Status)
	})
	if err != nil {
		return User{}, fmt.Errorf("identity.EnsureUserByExternalID: %w", err)
	}
	return u, nil
}

// ListByTenant 列出租户内用户。RLS 保证只返回该租户的行(无法越界)。
func (s *service) ListByTenant(ctx context.Context, tenantID string) ([]User, error) {
	var out []User
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, qerr := q.Query(ctx,
			`SELECT id, tenant_id, external_id, email, status FROM users ORDER BY created_at`)
		if qerr != nil {
			return fmt.Errorf("identity.ListByTenant query: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			var u User
			if scanErr := rows.Scan(&u.ID, &u.TenantID, &u.ExternalID, &u.Email, &u.Status); scanErr != nil {
				return fmt.Errorf("identity.ListByTenant scan: %w", scanErr)
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []User{}
	}
	return out, nil
}

// GetUserStatus 经 InTxRO(RLS)按 id 取用户状态。RLS 保证只能读到本租户的行;跨租户 id 不可见 → ErrUserNotFound。
func (s *service) GetUserStatus(ctx context.Context, tenantID, userID string) (string, error) {
	if tenantID == "" || userID == "" {
		return "", errors.New("identity.GetUserStatus: tenant_id 与 user_id 必填")
	}
	var status string
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx, `SELECT status FROM users WHERE id = $1`, userID)
		if scanErr := row.Scan(&status); scanErr != nil {
			if errors.Is(scanErr, data.ErrNoRows) {
				return ErrUserNotFound
			}
			return fmt.Errorf("identity.GetUserStatus scan: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return status, nil
}
