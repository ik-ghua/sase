package cred

import (
	"testing"
	"time"
)

// 对每种算法跑签发→验证往返 + 篡改/过期/换算法失败,证明 crypto-agility(同契约换算法)。
func TestSignerVerifierAgility(t *testing.T) {
	algs := map[string]func() (*Signer, error){
		AlgEd25519: GenerateSigner,
		AlgSM2:     GenerateSignerSM2,
	}
	for name, gen := range algs {
		t.Run(name, func(t *testing.T) {
			signer, err := gen()
			if err != nil {
				t.Fatalf("生成 %s 签发器: %v", name, err)
			}
			if signer.Public().Alg != name {
				t.Fatalf("公钥算法应为 %s,得 %s", name, signer.Public().Alg)
			}
			v, err := NewVerifier(signer.Public())
			if err != nil {
				t.Fatalf("构造验证器: %v", err)
			}
			now := time.Now()
			tok, err := signer.Issue(Claims{TenantID: "t1", Subject: "u1", Role: "tenant_admin"}, time.Hour, now)
			if err != nil {
				t.Fatalf("签发: %v", err)
			}
			// 正常验证
			c, err := v.Verify(tok, now)
			if err != nil {
				t.Fatalf("验证: %v", err)
			}
			if c.TenantID != "t1" || c.Subject != "u1" || c.Role != "tenant_admin" {
				t.Fatalf("声明回读错: %+v", c)
			}
			// 过期
			if _, err := v.Verify(tok, now.Add(2*time.Hour)); err != ErrExpired {
				t.Fatalf("过期应 ErrExpired,得 %v", err)
			}
			// 篡改 payload(改一个字符)
			if _, err := v.Verify("x"+tok[1:], now); err == nil {
				t.Fatal("篡改令牌应验证失败")
			}
		})
	}
}

// 换算法的验证器不能验另一算法签的令牌(隔离)。
func TestCrossAlgRejected(t *testing.T) {
	sm2Signer, _ := GenerateSignerSM2()
	edSigner, _ := GenerateSigner()
	edVerifier, _ := NewVerifier(edSigner.Public())

	tok, _ := sm2Signer.Issue(Claims{Subject: "u"}, time.Hour, time.Now())
	if _, err := edVerifier.Verify(tok, time.Now()); err == nil {
		t.Fatal("Ed25519 验证器不应通过 SM2 签的令牌")
	}
}

func TestUnknownAlg(t *testing.T) {
	if _, err := NewVerifier(PublicKey{Alg: "rsa", Bytes: []byte("x")}); err != ErrUnknownAlg {
		t.Fatalf("未知算法应 ErrUnknownAlg,得 %v", err)
	}
}
