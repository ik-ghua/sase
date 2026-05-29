package enroll_test

// ZTP 入网端到端:管理面预置入网 → 设备本地 CSR → 兑换租户绑定证书 → 一次性/防伪校验。
// 需 SASE_DB_RW_DSN(device_enrollments 走 RLS);未设则 SKIP。前置:已应用 migrations 0001-0007。

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/enroll"
)

func TestEnrollRedeemEndToEnd(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 ZTP 入网端到端测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	var auditCalls []string // 捕获 ZTP 审计钩子触发
	svc := enroll.NewService(store, ca, enroll.WithAudit(
		func(_ context.Context, tenantID, actor, action string, _ int) {
			auditCalls = append(auditCalls, action+":"+tenantID+":"+actor)
		}))
	tid := uuid.NewString()

	// 1) 管理面预置一条 connector 入网,得激活码(应带租户前缀)
	code, err := svc.CreateEnrollment(ctx, tid, enroll.KindConnector, "web")
	if err != nil {
		t.Fatalf("CreateEnrollment: %v", err)
	}
	if want := tid + "."; code[:len(want)] != want {
		t.Fatalf("激活码应以租户前缀打头,得 %q", code)
	}

	// 2) 设备本地生成密钥 + CSR,兑换证书
	csrPEM, _, err := devpki.GenerateCSR("web")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	certPEM, err := svc.Redeem(ctx, code, csrPEM)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	// 兑换成功须触发审计钩子(证书签发留痕)
	if len(auditCalls) != 1 || auditCalls[0] != "ZTP_ENROLL_REDEEM:"+tid+":web" {
		t.Fatalf("应记一条 ZTP_ENROLL_REDEEM 审计,得 %v", auditCalls)
	}

	// 3) 证书须把 tenant 编进 Organization、identity 编进 CommonName
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("解析签发证书: %v", err)
	}
	if got, ok := devpki.TenantFromCert(cert); !ok || got != tid {
		t.Fatalf("证书租户应为 %q,得 %q(ok=%v)", tid, got, ok)
	}
	if cert.Subject.CommonName != "web" {
		t.Fatalf("证书 CN 应为 web,得 %q", cert.Subject.CommonName)
	}

	// 4) 一次性:同激活码再兑换应失败(已 redeemed,防重放)
	csr2, _, _ := devpki.GenerateCSR("web")
	if _, err := svc.Redeem(ctx, code, csr2); err == nil {
		t.Fatal("激活码二次兑换应失败(一次性),却成功")
	}

	// 5) 伪造激活码(合法租户前缀 + 错误随机串)应失败
	if _, err := svc.Redeem(ctx, tid+".deadbeef", csr2); err == nil {
		t.Fatal("伪造激活码应兑换失败,却成功")
	}
}
