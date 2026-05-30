// Package agentenroll 编排真 OS 级 ZTNA Agent 的 per-user 首次入网(Slice80,L2 §3.10.1 锁定契约)。
//
// 角色定位(身份子 L2 形态,而非塞进激活码语义的 enroll):它**编排** oidc + identity + enroll 三个 Service,
// 把「IdP 用户认证 + 设备本地 CSR」一次性换成「租户绑定设备证书 + per-user 短 TTL 会话凭证」:
//
//	① 据 (tenant, idpID) 取 IdPConfig(RLS,active 闸)+ 解密 client_secret + 构造 adapter;
//	② adapter.Exchange(code, code_verifier, redirect_uri) → UserInfo(**控制面持 client_secret 完成令牌交换**,
//	   client_secret 永不下发设备;PKCE verifier 由 daemon 持有,id_token 验签由 adapter 保证);
//	③ identity.EnsureUserByExternalID(tenant, idpID, sub, email) → SASE 用户(status=active 闸,H1 对齐 OIDC callback);
//	④ enroll.RedeemAgent(tenant, deviceID, user.ID, csr) → 租户绑定设备证书(Org=tenant、CN=deviceID、role:device);
//	⑤ identity.IssueCredential(tenant, user.ID, groups, posture, ttl) → 会话凭证(Subject=user.ID、Groups=IdP 组)。
//
// **cert↔cred 双绑定(crux)**:同一 user.ID 同时用于 ④ RedeemAgent.user_id 与 ⑤ IssueCredential.Subject——
// 防设备账本与凭证主体不一致;PoP ztnaterm.VerifyCred 已交叉核对 claims.TenantID==证书 Org。
//
// **引导态信任**:Agent 首次入网无设备证书,/agent/enroll 是公开端点(authz 白名单 + CSRF skip + IP 限流);
// 授权信任来自 IdP id_token(JWKS 验签 + aud + iss + exp,在控制面 Exchange)+ PKCE + code 一次性;
// transport 由 daemon 侧以管理面 server-TLS(预置 CA pin)保障(devpki.ClientTLSServerOnly,同 ZTP 引导)。
package agentenroll

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/oidc"
)

// 错误 sentinel(handler 据此分流 HTTP 状态码;内部错由 handler 脱敏 500)。
var (
	// ErrIDPConfig 表示 IdP 配置不存在或被禁用(对应 4xx)。
	ErrIDPConfig = errors.New("agentenroll: IdP 配置不存在或已禁用")
	// ErrIDPAuth 表示 IdP 令牌交换失败 / 未返回 subject(对应 401)。
	ErrIDPAuth = errors.New("agentenroll: IdP 认证失败")
	// ErrUserDisabled 表示 SASE 用户存在但非 active(管理员手动停用,对应 403,H1 对齐 OIDC callback)。
	ErrUserDisabled = errors.New("agentenroll: 用户已停用")
	// ErrBadRequest 表示请求参数缺失/非法(对应 400)。
	ErrBadRequest = errors.New("agentenroll: 请求参数非法")
)

// IDPSvc 是依赖 idp.Service 的窄接口(取 IdPConfig + 解密 client_secret;复用 oidc.IDPSvc 同形态)。
type IDPSvc interface {
	Get(ctx context.Context, tenantID, id string) (*idp.Config, error)
	GetClientSecret(ctx context.Context, tenantID, id string) ([]byte, error)
}

// IdentitySvc 是依赖 identity.Service 的窄接口(EnsureUser;复用 oidc.IdentitySvc 同形态)。
type IdentitySvc interface {
	EnsureUserByExternalID(ctx context.Context, tenantID, idpID, externalID, email string) (identity.User, error)
}

// EnrollSvc 是依赖 enroll.Service 的窄接口(只用 Agent 入网签证)。
type EnrollSvc interface {
	RedeemAgent(ctx context.Context, tenantID, deviceID, userID string, csrPEM []byte) (certPEM []byte, err error)
}

// CredIssuer 是签会话凭证的窄接口(identity.Service.IssueCredential)。
type CredIssuer interface {
	IssueCredential(ctx context.Context, tenantID, userID string, groups []string, posture string, ttl time.Duration) (token, jti string, err error)
}

// AdapterFactory 给定 IdPConfig + 解密后的 client_secret 造一次性 oidc.Adapter(生产=oidc.DispatchFactory)。
type AdapterFactory func(ctx context.Context, cfg *idp.Config, clientSecret []byte) (oidc.Adapter, error)

// Service 编排 Agent 入网。窄依赖(便测试 mock,避免直接绑实现)。
type Service struct {
	idpSvc  IDPSvc
	ensurer IdentitySvc
	issuer  CredIssuer
	enroll  EnrollSvc
	factory AdapterFactory
	ttl     time.Duration
}

// Config 装配 Service。SessionTTL <= 0 时用默认 30min(短 TTL,L1 3.8;identity.MaxTTL=1h 上限钳制)。
type Config struct {
	IDPSvc     IDPSvc
	Ensurer    IdentitySvc
	Issuer     CredIssuer
	Enroll     EnrollSvc
	Factory    AdapterFactory
	SessionTTL time.Duration
}

// New 构造编排 Service。
func New(c Config) *Service {
	ttl := c.SessionTTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Service{
		idpSvc:  c.IDPSvc,
		ensurer: c.Ensurer,
		issuer:  c.Issuer,
		enroll:  c.Enroll,
		factory: c.Factory,
		ttl:     ttl,
	}
}

// Request 是 /agent/enroll 入参(daemon loopback 收到 IdP code 后提交)。
type Request struct {
	Code         string // IdP 回的授权码(一次性)
	CodeVerifier string // PKCE code_verifier(daemon 持有,控制面据此换 token)
	RedirectURI  string // 入网时使用的 redirect_uri(daemon loopback;须与 IdP authorize 一致,Exchange 校验)
	TenantID     string // 目标租户(daemon 配置;权威以编排为准)
	IDPID        string // IdPConfig ID
	DeviceID     string // 设备身份(=证书 CN;daemon 本地稳定随机 UUID,与私钥同源)
	CSRPem       []byte // 设备本地生成的 CSR(私钥不离设备)
	Posture      string // 入网时姿态摘要(可空;填入会话凭证 posture claim)
}

// Result 是入网成功返回(响应不含 client_secret/私钥;SessionToken 是会话凭证,明示)。
type Result struct {
	CertPEM      []byte
	SessionToken string
	SessionJTI   string
	ExpiresIn    int // 秒
	UserID       string
}

// Enroll 执行完整编排(见包注释五步)。错误用 sentinel 包装供 handler 分流;**绝不返回 client_secret/私钥/token 进 err**。
func (s *Service) Enroll(ctx context.Context, req Request) (*Result, error) {
	if req.Code == "" || req.CodeVerifier == "" || req.RedirectURI == "" {
		return nil, fmt.Errorf("%w: code/code_verifier/redirect_uri 必填", ErrBadRequest)
	}
	if req.TenantID == "" || req.IDPID == "" || req.DeviceID == "" {
		return nil, fmt.Errorf("%w: tenant_id/idp_id/device_id 必填", ErrBadRequest)
	}
	if len(req.CSRPem) == 0 {
		return nil, fmt.Errorf("%w: csr_pem 必填", ErrBadRequest)
	}

	// ① IdPConfig(RLS,active 闸)+ 解密 client_secret + adapter。
	cfg, err := s.idpSvc.Get(ctx, req.TenantID, req.IDPID)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return nil, fmt.Errorf("%w: %v", ErrIDPConfig, err)
		}
		return nil, fmt.Errorf("agentenroll get idp: %w", err)
	}
	if cfg.Status != "active" {
		return nil, fmt.Errorf("%w: status=%s", ErrIDPConfig, cfg.Status)
	}
	clientSecret, err := s.idpSvc.GetClientSecret(ctx, req.TenantID, req.IDPID)
	if err != nil {
		return nil, fmt.Errorf("agentenroll get client_secret: %w", err)
	}
	defer zeroize(clientSecret)
	adapter, err := s.factory(ctx, cfg, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("agentenroll adapter: %w", err)
	}

	// ② 控制面令牌交换(client_secret 永不下发设备;id_token 验签 + PKCE 由 adapter 保证)。
	userInfo, err := adapter.Exchange(ctx, req.Code, req.CodeVerifier, req.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIDPAuth, err)
	}
	if userInfo.Subject == "" {
		return nil, fmt.Errorf("%w: IdP 未返回 subject", ErrIDPAuth)
	}

	// ③ EnsureUser(status=active 闸,H1)。
	user, err := s.ensurer.EnsureUserByExternalID(ctx, req.TenantID, req.IDPID, userInfo.Subject, userInfo.Email)
	if err != nil {
		return nil, fmt.Errorf("agentenroll ensure_user: %w", err)
	}
	if user.Status != "active" {
		return nil, fmt.Errorf("%w: status=%s", ErrUserDisabled, user.Status)
	}

	// ④ 签设备证书(cert↔cred 双绑定:user.ID 入 user_id)。
	certPEM, err := s.enroll.RedeemAgent(ctx, req.TenantID, req.DeviceID, user.ID, req.CSRPem)
	if err != nil {
		return nil, fmt.Errorf("agentenroll redeem_agent: %w", err)
	}

	// ⑤ 签会话凭证(Subject=user.ID 同④ 的 user_id;Groups=IdP 组)。
	token, jti, err := s.issuer.IssueCredential(ctx, req.TenantID, user.ID, userInfo.Groups, req.Posture, s.ttl)
	if err != nil {
		return nil, fmt.Errorf("agentenroll issue_credential: %w", err)
	}

	return &Result{
		CertPEM:      certPEM,
		SessionToken: token,
		SessionJTI:   jti,
		ExpiresIn:    int(s.ttl.Seconds()),
		UserID:       user.ID,
	}, nil
}

// zeroize 擦零 client_secret 字节切片(用完即弃,同 oidc/secret 约定)。
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
