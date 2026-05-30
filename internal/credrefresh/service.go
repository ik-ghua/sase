// Package credrefresh 编排真 OS 级 ZTNA Agent 的会话凭证静默刷新(Slice81,L2 §3.6.1 锁定契约)。
//
// 角色定位(身份子 L2 形态,与 agentenroll 同构):它**编排** enroll(查设备↔用户关联)、identity(查用户状态 +
// 重签凭证)、cred.Verifier(验当前凭证签名)三件,把「设备 mTLS + 出示当前签名 cred」一次换成「带最新姿态的
// 新短 TTL 会话凭证」,**免重新 IdP 登录**:
//
//	① 验当前 cred 签名(cred.Verifier.Verify,控制面自己签的可信)→ 提取 subject + groups;(纵深)校 jti 未在吊销表;
//	② LookupAgentUser(tenant, deviceID=证书 CN)→ (user_id, deviceStatus);
//	③ 交叉核对 cred.Subject == user_id(设备与凭证同一用户,§3.6.1 防错配);
//	④ 三闸:deviceStatus='redeemed'(设备未撤销)+ user_id 非空 + GetUserStatus(user_id)='active'(用户未注销);
//	⑤ IssueCredential(tenant, user_id, groups-来自①验签 cred, posture-来自请求体, ttl) → 新 token/jti/expiresIn。
//
// **⚠️ 安全铁律:重签的 groups 必须来自步骤①已验签的当前 cred(控制面自己签的,可信),绝不取请求体里客户端
// 自报的任何字段**(否则恶意 Agent 谎报高权限组提权)。posture 可来自请求体(Agent 上报事实,本就不可信 →
// 姿态非唯一门禁,§3.8);risk 由 identity.WithRiskSource 在 IssueCredential 内自动填当前快照。
//
// **刷新门禁 vs EvictRevoked 互补(§3.6.1)**:本编排的「查 active+未撤销」= 周期性、自愈的注销/撤销生效
// (停用 user / 撤销设备 → 刷新失败 → 会话到 deadline ≤30min 自然死);RevokeCredential→EvictRevoked = 事件性、
// 秒级即时拆。纵深:步骤①校当前 jti 未在吊销表(防被 EvictRevoked 拆的会话靠刷新复活)。
package credrefresh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/identity"
)

// 错误 sentinel(handler 据此分流 HTTP 状态码;内部错由 handler 脱敏 500)。
var (
	// ErrCredInvalid 表示当前会话凭证验签失败/过期/格式非法(对应 401)。
	ErrCredInvalid = errors.New("credrefresh: 当前会话凭证无效")
	// ErrSubjectMismatch 表示 cred.Subject 与设备账本 user_id 不一致(设备与凭证非同一用户,对应 401)。
	ErrSubjectMismatch = errors.New("credrefresh: 凭证主体与设备关联用户不符")
	// ErrDeviceRevoked 表示设备入网记录已撤销或不存在/无关联用户(对应 403)。
	ErrDeviceRevoked = errors.New("credrefresh: 设备已撤销或未关联用户")
	// ErrUserDisabled 表示 SASE 用户存在但非 active(管理员手动停用,对应 403)。
	ErrUserDisabled = errors.New("credrefresh: 用户已停用")
	// ErrBadRequest 表示请求参数缺失/非法(对应 400)。
	ErrBadRequest = errors.New("credrefresh: 请求参数非法")
)

// EnrollLookup 是依赖 enroll.Service 的窄接口(只用 Agent 设备↔用户关联查询)。
type EnrollLookup interface {
	LookupAgentUser(ctx context.Context, tenantID, deviceID string) (userID, deviceStatus string, err error)
}

// UserStatusSvc 是依赖 identity.Service 的窄接口(查用户状态)。
type UserStatusSvc interface {
	GetUserStatus(ctx context.Context, tenantID, userID string) (status string, err error)
}

// CredIssuer 是签会话凭证的窄接口(identity.Service.IssueCredential;复用 agentenroll.CredIssuer 同形态)。
type CredIssuer interface {
	IssueCredential(ctx context.Context, tenantID, userID string, groups []string, posture string, ttl time.Duration) (token, jti string, err error)
}

// RevocationChecker 是「jti 是否在吊销表」的窄查询(纵深;可选,nil 时跳过该校验)。
// 返回 (revoked, err):err 非 nil 时本编排 fail-closed 拒刷新(查不到状态不放行)。
type RevocationChecker interface {
	IsRevoked(ctx context.Context, tenantID, jti string) (bool, error)
}

// agentDeviceRedeemed 是 Agent 设备入网记录的「有效/未撤销」状态(§3.6.1;device_enrollments.status)。
const agentDeviceRedeemed = "redeemed"

// userActive 是 SASE 用户的「未注销」状态(§3.6.1;users.status)。
const userActive = "active"

// Service 编排会话凭证刷新。窄依赖(便测试 mock,避免直接绑实现)。
type Service struct {
	verifier *cred.Verifier
	enroll   EnrollLookup
	users    UserStatusSvc
	issuer   CredIssuer
	revchk   RevocationChecker // 可空(纵深;nil=不查吊销表,仍靠短 TTL + 门禁兜底)
	ttl      time.Duration
}

// Config 装配 Service。SessionTTL <= 0 时用默认 30min(短 TTL,L1 3.8;与 agentenroll 一致;identity.MaxTTL=1h 上限钳制)。
type Config struct {
	Verifier   *cred.Verifier
	Enroll     EnrollLookup
	Users      UserStatusSvc
	Issuer     CredIssuer
	RevChk     RevocationChecker // 可空
	SessionTTL time.Duration
}

// New 构造刷新编排 Service。verifier/enroll/users/issuer 均必需(nil 会在 Refresh 内 fail-closed)。
func New(c Config) *Service {
	ttl := c.SessionTTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Service{
		verifier: c.Verifier,
		enroll:   c.Enroll,
		users:    c.Users,
		issuer:   c.Issuer,
		revchk:   c.RevChk,
		ttl:      ttl,
	}
}

// Request 是刷新入参(handler 据已验证的设备证书填 TenantID/DeviceID,据请求体填 CurrentCredToken/Posture)。
// **请求体不含 groups**:groups 唯一来源是已验签的 CurrentCredToken(防提权,见包注释铁律)。
type Request struct {
	TenantID         string // 取自设备证书 Org(权威,非客户端自报)
	DeviceID         string // 取自设备证书 CN(权威)
	CurrentCredToken string // 当前会话凭证(待验签;提取 subject + groups)
	Posture          string // 最新姿态摘要(来自请求体,可空;填入新凭证 posture claim)
}

// Result 是刷新成功返回(SessionToken 是新会话凭证,明示;不含任何敏感配置)。
type Result struct {
	SessionToken string
	SessionJTI   string
	ExpiresIn    int // 秒
}

// Refresh 执行完整编排(见包注释五步)。错误用 sentinel 包装供 handler 分流;**绝不返回 token 进 err**。
func (s *Service) Refresh(ctx context.Context, req Request) (*Result, error) {
	if s.verifier == nil || s.enroll == nil || s.users == nil || s.issuer == nil {
		return nil, errors.New("credrefresh: 服务未完整装配")
	}
	if req.TenantID == "" || req.DeviceID == "" {
		return nil, fmt.Errorf("%w: tenant/device_id 必填(应取自设备证书)", ErrBadRequest)
	}
	if req.CurrentCredToken == "" {
		return nil, fmt.Errorf("%w: current_cred_token 必填", ErrBadRequest)
	}

	// ① 验当前 cred 签名(控制面自己签的可信)→ 提取 subject + groups。验签失败/过期/格式非法 → 401。
	claims, err := s.verifier.Verify(req.CurrentCredToken, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredInvalid, err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: 凭证缺 subject", ErrCredInvalid)
	}
	// 交叉核对凭证租户与设备证书租户(纵深:防持他租户凭证经本租户设备刷新)。
	// 空 TenantID 也拒(reviewer S1):合法会话 cred 经 IssueCredential 恒带非空 TenantID,空=异常凭证。
	if claims.TenantID == "" || claims.TenantID != req.TenantID {
		return nil, fmt.Errorf("%w: 凭证租户与设备租户不符", ErrSubjectMismatch)
	}

	// (纵深)校当前 jti 未在吊销表:防被 EvictRevoked 秒级拆的会话靠刷新复活(§3.6.1)。
	if s.revchk != nil && claims.JTI != "" {
		revoked, rerr := s.revchk.IsRevoked(ctx, req.TenantID, claims.JTI)
		if rerr != nil {
			// fail-closed:查不到吊销状态不放行(同 adminActiveChecker 错→503 的 fail-closed 思路)。
			return nil, fmt.Errorf("credrefresh 查吊销表: %w", rerr)
		}
		if revoked {
			return nil, fmt.Errorf("%w: 当前凭证已撤销", ErrCredInvalid)
		}
	}

	// ② 查设备↔用户关联(经 InTxRO RLS;设备不存在/跨租户不可见 → ErrAgentDeviceNotFound)。
	userID, deviceStatus, err := s.enroll.LookupAgentUser(ctx, req.TenantID, req.DeviceID)
	if err != nil {
		// 设备记录不存在按「已撤销」语义对外(403,不区分以免泄露存在性);其它内部错原样返(handler 脱敏 500)。
		if errors.Is(err, enroll.ErrAgentDeviceNotFound) {
			return nil, fmt.Errorf("%w: 设备记录不存在", ErrDeviceRevoked)
		}
		return nil, fmt.Errorf("credrefresh lookup_device: %w", err)
	}

	// ③ 交叉核对 cred.Subject == device_enrollments.user_id(设备与凭证同一用户)。
	//    user_id 为空(未关联)先归到「设备已撤销/未关联」(③ 之前先判空,避免 ""=="" 误判一致)。
	if userID == "" {
		return nil, fmt.Errorf("%w: 设备未关联用户", ErrDeviceRevoked)
	}
	if claims.Subject != userID {
		return nil, fmt.Errorf("%w: cred.sub=%q device.user=%q", ErrSubjectMismatch, claims.Subject, userID)
	}

	// ④ 三闸之一:设备未撤销(status='redeemed')。
	if deviceStatus != agentDeviceRedeemed {
		return nil, fmt.Errorf("%w: device status=%s", ErrDeviceRevoked, deviceStatus)
	}

	// ④ 三闸之二:用户仍 active(未注销)。GetUserStatus 不存在 → 归「设备已撤销/用户失效」(403)。
	status, err := s.users.GetUserStatus(ctx, req.TenantID, userID)
	if err != nil {
		if errors.Is(err, identity.ErrUserNotFound) {
			return nil, fmt.Errorf("%w: 用户不存在", ErrUserDisabled)
		}
		return nil, fmt.Errorf("credrefresh user_status: %w", err)
	}
	if status != userActive {
		return nil, fmt.Errorf("%w: status=%s", ErrUserDisabled, status)
	}

	// ⑤ 重签会话凭证:groups **来自①验签 cred**(可信,防 body 提权);posture 来自请求体;risk 由 issuer 内 WithRiskSource 填。
	token, jti, err := s.issuer.IssueCredential(ctx, req.TenantID, userID, claims.Groups, req.Posture, s.ttl)
	if err != nil {
		return nil, fmt.Errorf("credrefresh issue_credential: %w", err)
	}
	return &Result{
		SessionToken: token,
		SessionJTI:   jti,
		ExpiresIn:    int(s.ttl.Seconds()),
	}, nil
}
