package credrefresh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/identity"
)

// ---- stubs(四态 device/user + 验签真 cred,纯逻辑无 PG)----

type stubEnroll struct {
	userID string
	status string
	err    error
}

func (s stubEnroll) LookupAgentUser(_ context.Context, _, _ string) (string, string, error) {
	if s.err != nil {
		return "", "", s.err
	}
	return s.userID, s.status, nil
}

type stubUsers struct {
	status string
	err    error
}

func (s stubUsers) GetUserStatus(_ context.Context, _, _ string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.status, nil
}

// recordingIssuer 记录 IssueCredential 入参(验 groups 来自验签 cred、posture 透传),回新 token/jti。
type recordingIssuer struct {
	gotTenant  string
	gotUserID  string
	gotGroups  []string
	gotPosture string
	signer     *cred.Signer
}

func (r *recordingIssuer) IssueCredential(_ context.Context, tenantID, userID string, groups []string, posture string, ttl time.Duration) (string, string, error) {
	r.gotTenant, r.gotUserID, r.gotGroups, r.gotPosture = tenantID, userID, groups, posture
	// 真签一枚新 cred,Subject=userID、Groups=传入(便测试断言新 cred 的组)。
	jti := "new-jti"
	tok, err := r.signer.Issue(cred.Claims{JTI: jti, TenantID: tenantID, Subject: userID, Groups: groups, Posture: posture}, ttl, time.Now())
	return tok, jti, err
}

type stubRevChk struct {
	revoked bool
	err     error
}

func (s stubRevChk) IsRevoked(_ context.Context, _, _ string) (bool, error) {
	return s.revoked, s.err
}

const testTenant = "11111111-1111-1111-1111-111111111111"
const testUser = "22222222-2222-2222-2222-222222222222"
const testDevice = "device-abc"

// mkSvc 造一个用真 Signer/Verifier 的 Service + 当前 cred(Subject=sub, Groups=groups)。
func mkSvc(t *testing.T, en EnrollLookup, us UserStatusSvc, rc RevocationChecker) (*Service, *cred.Signer, *cred.Verifier, *recordingIssuer) {
	t.Helper()
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	issuer := &recordingIssuer{signer: signer}
	svc := New(Config{Verifier: verifier, Enroll: en, Users: us, Issuer: issuer, RevChk: rc})
	return svc, signer, verifier, issuer
}

// issueCurrent 用 signer 签当前会话 cred(Subject/Groups/Tenant 可控)。
func issueCurrent(t *testing.T, signer *cred.Signer, sub string, groups []string) string {
	t.Helper()
	tok, err := signer.Issue(cred.Claims{JTI: "cur-jti", TenantID: testTenant, Subject: sub, Groups: groups}, 5*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("Issue current: %v", err)
	}
	return tok
}

// TestRefreshActiveSuccess:active 设备 + active 用户 + cred 有效 → 重签成功;新 cred Subject==user_id,
// 且 **groups 来自验签 cred(非 body)**,posture/ 透传。
func TestRefreshActiveSuccess(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "redeemed"}
	us := stubUsers{status: "active"}
	svc, signer, verifier, issuer := mkSvc(t, en, us, stubRevChk{})

	credGroups := []string{"eng", "sec"}
	cur := issueCurrent(t, signer, testUser, credGroups)

	res, err := svc.Refresh(context.Background(), Request{
		TenantID:         testTenant,
		DeviceID:         testDevice,
		CurrentCredToken: cur,
		Posture:          "compliant",
	})
	if err != nil {
		t.Fatalf("刷新应成功,得 %v", err)
	}
	if res.SessionToken == "" || res.SessionJTI != "new-jti" {
		t.Fatalf("应返回新会话凭证,得 %+v", res)
	}
	// 新 cred 主体==user_id。
	newClaims, verr := verifier.Verify(res.SessionToken, time.Now())
	if verr != nil {
		t.Fatalf("新 cred 应过验签: %v", verr)
	}
	if newClaims.Subject != testUser {
		t.Fatalf("新 cred Subject 应 %q,得 %q", testUser, newClaims.Subject)
	}
	// groups 来自验签 cred(非 body)。
	if len(issuer.gotGroups) != 2 || issuer.gotGroups[0] != "eng" || issuer.gotGroups[1] != "sec" {
		t.Fatalf("重签 groups 应来自验签 cred [eng sec],得 %v", issuer.gotGroups)
	}
	if issuer.gotPosture != "compliant" {
		t.Fatalf("posture 应透传 body,得 %q", issuer.gotPosture)
	}
	if issuer.gotUserID != testUser {
		t.Fatalf("重签 userID 应 %q,得 %q", testUser, issuer.gotUserID)
	}
}

// TestRefreshBodyGroupsIgnored:即便「请求体里没有 groups 字段」(本设计 body 无 groups),重签的 groups
// 也只来自验签 cred——构造一枚 cred 带高权限组,断言重签组==该 cred 组(证明无 body 提权旁路)。
func TestRefreshBodyGroupsIgnored(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "redeemed"}
	us := stubUsers{status: "active"}
	svc, signer, _, issuer := mkSvc(t, en, us, stubRevChk{})

	// 当前 cred 的组(可信来源)。
	credGroups := []string{"viewer"}
	cur := issueCurrent(t, signer, testUser, credGroups)

	if _, err := svc.Refresh(context.Background(), Request{
		TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur, Posture: "x",
	}); err != nil {
		t.Fatalf("刷新应成功: %v", err)
	}
	if len(issuer.gotGroups) != 1 || issuer.gotGroups[0] != "viewer" {
		t.Fatalf("重签 groups 必须==验签 cred 的组 [viewer],得 %v(疑似取了 body/其它来源)", issuer.gotGroups)
	}
}

// TestRefreshUserDisabled:用户 status=disabled → 403(ErrUserDisabled)。
func TestRefreshUserDisabled(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "redeemed"}
	us := stubUsers{status: "disabled"}
	svc, signer, _, _ := mkSvc(t, en, us, stubRevChk{})
	cur := issueCurrent(t, signer, testUser, nil)
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur})
	if !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("停用用户应 ErrUserDisabled,得 %v", err)
	}
}

// TestRefreshDeviceRevoked:设备 status=revoked → 403(ErrDeviceRevoked)。
func TestRefreshDeviceRevoked(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "revoked"}
	us := stubUsers{status: "active"}
	svc, signer, _, _ := mkSvc(t, en, us, stubRevChk{})
	cur := issueCurrent(t, signer, testUser, nil)
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur})
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("撤销设备应 ErrDeviceRevoked,得 %v", err)
	}
}

// TestRefreshNoUser:设备 user_id 为空(未关联)→ 403(ErrDeviceRevoked)。
func TestRefreshNoUser(t *testing.T) {
	en := stubEnroll{userID: "", status: "redeemed"}
	us := stubUsers{status: "active"}
	svc, signer, _, _ := mkSvc(t, en, us, stubRevChk{})
	cur := issueCurrent(t, signer, testUser, nil)
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur})
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("无关联用户应 ErrDeviceRevoked,得 %v", err)
	}
}

// TestRefreshDeviceNotFound:LookupAgentUser 返 ErrAgentDeviceNotFound → 403(ErrDeviceRevoked,不泄露存在性)。
func TestRefreshDeviceNotFound(t *testing.T) {
	en := stubEnroll{err: enroll.ErrAgentDeviceNotFound}
	us := stubUsers{status: "active"}
	svc, signer, _, _ := mkSvc(t, en, us, stubRevChk{})
	cur := issueCurrent(t, signer, testUser, nil)
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur})
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("设备记录不存在应 ErrDeviceRevoked,得 %v", err)
	}
}

// TestRefreshUserNotFound:GetUserStatus 返 ErrUserNotFound → 403(ErrUserDisabled)。
func TestRefreshUserNotFound(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "redeemed"}
	us := stubUsers{err: identity.ErrUserNotFound}
	svc, signer, _, _ := mkSvc(t, en, us, stubRevChk{})
	cur := issueCurrent(t, signer, testUser, nil)
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur})
	if !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("用户不存在应 ErrUserDisabled,得 %v", err)
	}
}

// TestRefreshSubjectMismatch:cred.Subject != device.user_id → 401(ErrSubjectMismatch,防错配/凭证盗用)。
func TestRefreshSubjectMismatch(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "redeemed"}
	us := stubUsers{status: "active"}
	svc, signer, _, _ := mkSvc(t, en, us, stubRevChk{})
	// 当前 cred 主体是另一用户(与设备关联 user 不符)。
	cur := issueCurrent(t, signer, "33333333-3333-3333-3333-333333333333", nil)
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur})
	if !errors.Is(err, ErrSubjectMismatch) {
		t.Fatalf("主体不符应 ErrSubjectMismatch,得 %v", err)
	}
}

// TestRefreshCredInvalid:cred 验签失败(他签发器签的)→ 401(ErrCredInvalid)。
func TestRefreshCredInvalid(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "redeemed"}
	us := stubUsers{status: "active"}
	svc, _, _, _ := mkSvc(t, en, us, stubRevChk{})

	// 用另一签发器签的 cred(本 svc 的 verifier 验不过)。
	other, _ := cred.GenerateSigner()
	bad, _ := other.Issue(cred.Claims{JTI: "x", TenantID: testTenant, Subject: testUser}, 5*time.Minute, time.Now())
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: bad})
	if !errors.Is(err, ErrCredInvalid) {
		t.Fatalf("外签 cred 应 ErrCredInvalid,得 %v", err)
	}
}

// TestRefreshRevokedJTI:当前 jti 在吊销表(被 EvictRevoked 拆)→ 401(防靠刷新复活,§3.6.1 纵深)。
func TestRefreshRevokedJTI(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "redeemed"}
	us := stubUsers{status: "active"}
	svc, signer, _, _ := mkSvc(t, en, us, stubRevChk{revoked: true})
	cur := issueCurrent(t, signer, testUser, nil)
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur})
	if !errors.Is(err, ErrCredInvalid) {
		t.Fatalf("已撤销 jti 应 ErrCredInvalid,得 %v", err)
	}
}

// TestRefreshRevChkErrFailsClosed:吊销表查询出错 → fail-closed 拒(非 sentinel,handler 脱敏 500)。
func TestRefreshRevChkErrFailsClosed(t *testing.T) {
	en := stubEnroll{userID: testUser, status: "redeemed"}
	us := stubUsers{status: "active"}
	svc, signer, _, _ := mkSvc(t, en, us, stubRevChk{err: errors.New("db down")})
	cur := issueCurrent(t, signer, testUser, nil)
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice, CurrentCredToken: cur})
	if err == nil {
		t.Fatal("吊销表查询出错应 fail-closed 拒刷新")
	}
	// 非业务 sentinel(handler 据此走 500 脱敏)。
	if errors.Is(err, ErrCredInvalid) || errors.Is(err, ErrDeviceRevoked) || errors.Is(err, ErrUserDisabled) || errors.Is(err, ErrSubjectMismatch) || errors.Is(err, ErrBadRequest) {
		t.Fatalf("吊销表错应为内部错(非 sentinel),得 %v", err)
	}
}

// TestRefreshBadRequest:缺 token → 400(ErrBadRequest)。
func TestRefreshBadRequest(t *testing.T) {
	svc, _, _, _ := mkSvc(t, stubEnroll{}, stubUsers{}, stubRevChk{})
	_, err := svc.Refresh(context.Background(), Request{TenantID: testTenant, DeviceID: testDevice})
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("缺 token 应 ErrBadRequest,得 %v", err)
	}
}
