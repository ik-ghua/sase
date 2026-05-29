package identity_test

// 验风险进会话凭证 claim:IssueCredential 经 WithRiskSource 取当前风险填 risk claim(动态访问控制 risk L2 3.3)。
// 不需 DB(IssueCredential 只用签发器,不触 store)。

import (
	"context"
	"testing"
	"time"

	"github.com/ikuai8/sase/api/xdsv1"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/identity"
)

func TestIssueCredentialFillsRiskClaim(t *testing.T) {
	signer, err := cred.GenerateSigner()
	if err != nil {
		t.Fatalf("签发器: %v", err)
	}
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		t.Fatalf("验证器: %v", err)
	}

	// 注入风险来源(模拟 risk 引擎):alice → score 72 / high
	svc := identity.NewService(data.NewStubStore(),
		identity.WithSigner(signer),
		identity.WithRiskSource(func(_, subject string) (int, string) {
			if subject == "alice" {
				return 72, xdsv1.RiskHigh
			}
			return 0, xdsv1.RiskLow
		}))

	tok, _, err := svc.IssueCredential(context.Background(), "t1", "alice", []string{"g1"}, "compliant", time.Minute)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}
	claims, err := verifier.Verify(tok, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.RiskScore != 72 || claims.RiskLevel != xdsv1.RiskHigh {
		t.Fatalf("risk claim 未正确填入:score=%d level=%q", claims.RiskScore, claims.RiskLevel)
	}

	// 无风险来源(未注入)→ claim 风险为空(向后兼容,PEP 视作最低)
	svc2 := identity.NewService(data.NewStubStore(), identity.WithSigner(signer))
	tok2, _, _ := svc2.IssueCredential(context.Background(), "t1", "bob", nil, "compliant", time.Minute)
	c2, _ := verifier.Verify(tok2, time.Now())
	if c2.RiskScore != 0 || c2.RiskLevel != "" {
		t.Fatalf("未注入风险来源 claim 应空,得 score=%d level=%q", c2.RiskScore, c2.RiskLevel)
	}
}
