// Package enroll 是设备入网(ZTP)服务:Connector/CPE 凭激活码 + CSR 换取租户绑定证书
// (L1 3.5 自建 PKI/ZTP、3.11 入网契约 Register/ZTP{activation_code, csr}→cert)。
//
// 私钥由设备本地生成(devpki.GenerateCSR),永不离开设备;控制面只对 CSR 签发,把 tenant 编进
// 证书 Subject.Organization、identity(connector app / cpe site_key)进 CommonName。
//
// 多租户 bootstrap:兑换端点无租户上下文(设备只持激活码),故激活码形如 `<tenant_uuid>.<random>`,
// 兑换时从码前缀解析租户 → 设 RLS 上下文 → 用随机串作秘密校验行,既能定位租户又不绕过 RLS。
package enroll

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
)

// Kind 区分入网设备类型(对应 revtunnel 注册的两类设备 + ZTNA Agent)。
const (
	KindConnector = "connector" // ZTNA App Connector
	KindCPE       = "cpe"       // SD-WAN 客户边缘
	KindAgent     = "agent"     // 真 OS 级 ZTNA 端点 Agent(Slice80;经 /agent/enroll IdP 编排入网,非激活码)
)

func validKind(k string) bool { return k == KindConnector || k == KindCPE || k == KindAgent }

// Device 是设备入网记录的**非敏感**只读视图(供 ZTP 可见性端点列出)。
// 有意不含 activation_code(一次性激活码=秘密,泄漏即可被冒充兑换):入网记录里唯一的敏感字段。
// identity 是设备自报的身份(connector app / cpe site_key),非秘密;证书/私钥从不存于本表(私钥永不离开设备)。
type Device struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`     // connector | cpe
	Identity   string     `json:"identity"` // 签入证书 CommonName(connector app / cpe site_key)
	Status     string     `json:"status"`   // pending | redeemed | revoked
	RedeemedAt *time.Time `json:"redeemed_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Service 是 enroll 模块对外唯一接口。
type Service interface {
	// CreateEnrollment 由管理面(RBAC)为某设备预置一条入网记录,返回一次性激活码。
	CreateEnrollment(ctx context.Context, tenantID, kind, identity string) (code string, err error)
	// Redeem 由设备(凭激活码,无 mTLS)调用:校验激活码 + CSR,签发租户绑定证书,激活码作废。
	Redeem(ctx context.Context, code string, csrPEM []byte) (certPEM []byte, err error)
	// RedeemAgent 是真 OS 级 ZTNA Agent 的入网签发(Slice80,L2 §3.10.1):**不经激活码**——信任来自上层
	// /agent/enroll 编排已完成的 IdP id_token 验签 + PKCE + code 一次性(控制面 Exchange);本方法只负责
	// 「记设备入网账本 + 签租户绑定证书」。tenant 由编排上下文给(非设备自报),deviceID=证书 CN,userID=
	// 同编排内 EnsureUser 产的 SASE 用户(cert↔cred 双绑定,可空则置 NULL)。
	// 经 InTx(tenant RLS)upsert(ON CONFLICT (tenant_id, identity) DO UPDATE,kind='agent' + user_id)→
	// SignCSR(tenant 进 Org、deviceID 进 CN、role:device 进 OU)。
	RedeemAgent(ctx context.Context, tenantID, deviceID, userID string, csrPEM []byte) (certPEM []byte, err error)
	// Renew 由设备(凭当前有效 mTLS 证书,非激活码)续期:tenant/identity 取自调用方已验证的证书,
	// 校验入网记录仍有效(未撤销)后据新 CSR 签发延期证书(密钥轮换)。激活码不参与。
	Renew(ctx context.Context, tenantID, identity string, csrPEM []byte) (certPEM []byte, err error)
	// RevokeDevice 由管理面(RBAC)撤销设备入网:置 status='revoked',此后续期被拒(设备 ≤证书有效期内掉线)。
	RevokeDevice(ctx context.Context, tenantID, identity string) error
	// ListDevices 列出该租户已登记设备(ZTP 可见性)。经 InTxRO 走 RLS,只返回**非敏感**列(不含激活码)。
	ListDevices(ctx context.Context, tenantID string) ([]Device, error)
}

// AuditFunc 记录 ZTP 证书签发/续期事件(设备认证、非 admin principal,故不经 admin 审计中间件,单独记)。
// 解耦:用函数型钩子而非依赖 audit 包。result 为 HTTP 状态码语义(200=成功)。
type AuditFunc func(ctx context.Context, tenantID, actor, action string, result int)

type service struct {
	store data.Store
	ca    *devpki.CA
	audit AuditFunc
}

// Option 配置 enroll 服务。
type Option func(*service)

// WithAudit 注入审计钩子,在 Redeem/Renew 成功后记录证书签发/续期(best-effort,不阻断签发)。
func WithAudit(f AuditFunc) Option { return func(s *service) { s.audit = f } }

// NewService 构造 enroll 服务(ca 为签发设备证书的 CA;dev 用 devpki,生产应为 PoP CA + HSM)。
func NewService(store data.Store, ca *devpki.CA, opts ...Option) Service {
	s := &service{store: store, ca: ca}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *service) recordAudit(ctx context.Context, tenantID, actor, action string, result int) {
	if s.audit != nil {
		s.audit(ctx, tenantID, actor, action, result)
	}
}

func (s *service) CreateEnrollment(ctx context.Context, tenantID, kind, identity string) (string, error) {
	// agent 入网经 /agent/enroll 的 IdP 编排(非激活码),绝不在此签发激活码(Slice80 reviewer S2:
	// validKind 放行 KindAgent 是为 RedeemAgent,但激活码路径 CreateEnrollment 须显式拒 agent)。
	if kind == KindAgent {
		return "", fmt.Errorf("enroll: kind=%q 经 /agent/enroll IdP 入网,不签发激活码", KindAgent)
	}
	if !validKind(kind) {
		return "", fmt.Errorf("enroll: kind 须为 %q 或 %q,得到 %q", KindConnector, KindCPE, kind)
	}
	if identity == "" {
		return "", errors.New("enroll: identity 必填")
	}
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	// 激活码自带租户前缀,使兑换端点无需先验身份即可定位租户(随机串为秘密)
	code := tenantID + "." + hex.EncodeToString(secret)
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		_, err := q.Exec(ctx,
			`INSERT INTO device_enrollments (id, tenant_id, kind, identity, activation_code, status)
			 VALUES ($1,$2,$3,$4,$5,'pending')`,
			uuid.NewString(), tenantID, kind, identity, code)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("enroll.CreateEnrollment: %w", err)
	}
	return code, nil
}

func (s *service) Redeem(ctx context.Context, code string, csrPEM []byte) ([]byte, error) {
	if s.ca == nil {
		return nil, errors.New("enroll.Redeem: ZTP 签发未启用(缺 CA)")
	}
	tenantID, _, ok := strings.Cut(code, ".")
	if !ok || tenantID == "" {
		return nil, errors.New("enroll.Redeem: 激活码格式非法")
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, errors.New("enroll.Redeem: 激活码租户前缀非法")
	}
	// 预检 CSR(在标记兑换前),无效 CSR 不浪费一次性激活码
	if _, err := devpki.ValidateCSR(csrPEM); err != nil {
		return nil, fmt.Errorf("enroll.Redeem: %w", err)
	}

	var identity string
	// 设租户上下文后,RLS 允许读到本租户该激活码行;status='pending' 保证一次性(防重放)
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`SELECT identity FROM device_enrollments
			 WHERE activation_code = $1 AND status = 'pending'`, code)
		if err := row.Scan(&identity); err != nil {
			return fmt.Errorf("激活码无效或已兑换: %w", err)
		}
		// 先标记兑换(同事务内,失败回滚),再签发——避免签发后标记失败导致激活码可重放
		ct, err := q.Exec(ctx,
			`UPDATE device_enrollments SET status='redeemed', redeemed_at=now()
			 WHERE activation_code = $1 AND status = 'pending'`, code)
		if err != nil {
			return err
		}
		if ct.RowsAffected() != 1 {
			return errors.New("激活码并发兑换冲突")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("enroll.Redeem: %w", err)
	}

	certPEM, err := s.ca.SignCSR(csrPEM, tenantID, identity)
	if err != nil {
		return nil, fmt.Errorf("enroll.Redeem 签发: %w", err)
	}
	s.recordAudit(ctx, tenantID, identity, "ZTP_ENROLL_REDEEM", 200)
	return certPEM, nil
}

// RedeemAgent 见接口注释。与 Redeem(激活码)正交:本方法的信任前置由调用方(agentenroll 编排)在控制面
// 完成 IdP 令牌交换后调用,**故无激活码、无一次性 status 跃迁**——同一用户同一设备重入网(换设备/重装)走
// upsert 更新而非建新行(避免账本膨胀)。userID 可空(置 NULL);非空时记入 user_id 做 device↔user 关联。
func (s *service) RedeemAgent(ctx context.Context, tenantID, deviceID, userID string, csrPEM []byte) ([]byte, error) {
	if s.ca == nil {
		return nil, errors.New("enroll.RedeemAgent: ZTP 签发未启用(缺 CA)")
	}
	if tenantID == "" {
		return nil, errors.New("enroll.RedeemAgent: tenant 必填(应取自编排上下文)")
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, errors.New("enroll.RedeemAgent: tenant 非法 UUID")
	}
	if deviceID == "" {
		return nil, errors.New("enroll.RedeemAgent: device_id 必填(=证书 CN)")
	}
	// 预检 CSR(在写账本前),无效 CSR 不写库。
	if _, err := devpki.ValidateCSR(csrPEM); err != nil {
		return nil, fmt.Errorf("enroll.RedeemAgent: %w", err)
	}
	// userID 折成 sql 参数(空→NULL,非空→FK→users.id;同租户内 RLS 校验由 FK + 表 RLS 保证)。
	var userArg any
	if userID != "" {
		userArg = userID
	}
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		// upsert:同 (tenant_id, identity) 已存在(同设备重入网)→ 更新 kind/user_id;否则建新 'pending'→'redeemed'。
		// status 直接置 'redeemed'(Agent 入网即兑换;激活码态不适用本路径)。activation_code 唯一约束需非空,
		// 故填一个不可作为兑换码使用的占位(含 'agent:' 前缀,不匹配 Redeem 的 `<uuid>.<rand>` 格式且不会被 Redeem 查到)。
		_, err := q.Exec(ctx,
			`INSERT INTO device_enrollments (id, tenant_id, kind, identity, activation_code, status, redeemed_at, user_id)
			 VALUES ($1,$2,'agent',$3,$4,'redeemed',now(),$5)
			 ON CONFLICT (tenant_id, identity)
			 DO UPDATE SET kind='agent', status='redeemed', redeemed_at=now(), user_id=EXCLUDED.user_id`,
			uuid.NewString(), tenantID, deviceID, "agent:"+uuid.NewString(), userArg)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("enroll.RedeemAgent 记录: %w", err)
	}
	certPEM, err := s.ca.SignCSR(csrPEM, tenantID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("enroll.RedeemAgent 签发: %w", err)
	}
	s.recordAudit(ctx, tenantID, deviceID, "AGENT_ENROLL", 200)
	return certPEM, nil
}

func (s *service) Renew(ctx context.Context, tenantID, identity string, csrPEM []byte) ([]byte, error) {
	if s.ca == nil {
		return nil, errors.New("enroll.Renew: ZTP 签发未启用(缺 CA)")
	}
	if tenantID == "" || identity == "" {
		return nil, errors.New("enroll.Renew: tenant/identity 必填(应取自调用方证书)")
	}
	if _, err := devpki.ValidateCSR(csrPEM); err != nil {
		return nil, fmt.Errorf("enroll.Renew: %w", err)
	}
	// 续期闸:入网记录须仍 'redeemed'(已入网且未撤销)。admin 撤销 → 'revoked' → 此处查不到 → 拒续。
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		var n int
		row := q.QueryRow(ctx,
			`SELECT count(*) FROM device_enrollments
			 WHERE identity = $1 AND status = 'redeemed'`, identity)
		if err := row.Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return errors.New("设备未入网或已撤销")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("enroll.Renew: %w", err)
	}
	// tenant/identity 来自调用方已验证的 mTLS 证书,设备无法借此续成他租户/他身份
	certPEM, err := s.ca.SignCSR(csrPEM, tenantID, identity)
	if err != nil {
		return nil, fmt.Errorf("enroll.Renew 签发: %w", err)
	}
	s.recordAudit(ctx, tenantID, identity, "ZTP_RENEW", 200)
	return certPEM, nil
}

func (s *service) RevokeDevice(ctx context.Context, tenantID, identity string) error {
	if identity == "" {
		return errors.New("enroll.RevokeDevice: identity 必填")
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		ct, err := q.Exec(ctx,
			`UPDATE device_enrollments SET status='revoked'
			 WHERE identity = $1 AND status = 'redeemed'`, identity)
		if err != nil {
			return fmt.Errorf("enroll.RevokeDevice: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return errors.New("enroll.RevokeDevice: 无此已入网设备(或已撤销)")
		}
		return nil
	})
}

// ListDevices 列出该租户已登记设备(ZTP 可见性)。经 InTxRO(app_ro)走 RLS,只 SELECT **非敏感**列
// (id/kind/identity/status/redeemed_at/created_at)——**绝不**取 activation_code(一次性秘密)。
// 按 created_at 排序;空返非 nil 空切片(序列化为 [] 而非 null,对齐 identity.ListByTenant/policy.ListByTenant)。
func (s *service) ListDevices(ctx context.Context, tenantID string) ([]Device, error) {
	var out []Device
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, qerr := q.Query(ctx,
			`SELECT id, kind, identity, status, redeemed_at, created_at
			   FROM device_enrollments ORDER BY created_at`)
		if qerr != nil {
			return fmt.Errorf("enroll.ListDevices query: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			var d Device
			if scanErr := rows.Scan(&d.ID, &d.Kind, &d.Identity, &d.Status, &d.RedeemedAt, &d.CreatedAt); scanErr != nil {
				return fmt.Errorf("enroll.ListDevices scan: %w", scanErr)
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Device{}
	}
	return out, nil
}
