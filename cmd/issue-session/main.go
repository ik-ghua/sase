// Command issue-session 是 **dev/demo 专用** 的会话凭证签发器:用与 api-server 同一签发种子
// (SASE_CRED_ED25519_SEED)签一枚带 subject/groups/posture/risk 的会话凭证 token,写文件 / 打印。
//
// 用途:Slice77 端到端 demo——真 OS Agent 需携 SESSION_TOKEN 与 PoP ZTNA 终结器握手,PoP 用 api-server
// 下发的同一公钥(TrustBundle)验签。本工具让 docker-compose 在不走完整 IdP 登录的前提下产出一枚可验的
// 会话凭证(对齐 seed.sql 直插 demo 数据的思路)。
//
// ⚠️ 仅 dev/demo:固定种子 + 命令行注入 claim。生产经 IdP 登录 → 令牌交换签发(L1 3.4),非本工具。
//
//	用法:SASE_CRED_ED25519_SEED=<base64url 32B> TENANT=<uuid> SUBJECT=alice GROUPS=eng,sales \
//	      [JTI=<jti>] [POSTURE=compliant] [RISK_LEVEL=low] [TTL=12h] [OUT=/certs/session.token] issue-session
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ikuai8/sase/internal/cred"
)

func main() {
	signer, err := newSigner()
	if err != nil {
		log.Fatalf("issue-session: %v", err)
	}
	tenant := envMust("TENANT")
	subject := envOr("SUBJECT", "demo-user")
	jti := envOr("JTI", fmt.Sprintf("sess-%d", time.Now().UnixNano()))
	ttl := parseTTL(envOr("TTL", "12h"))

	claims := cred.Claims{
		JTI:       jti,
		TenantID:  tenant,
		Subject:   subject,
		Groups:    splitCSV(os.Getenv("GROUPS")),
		Posture:   os.Getenv("POSTURE"),
		RiskLevel: os.Getenv("RISK_LEVEL"),
	}
	tok, err := signer.Issue(claims, ttl, time.Now())
	if err != nil {
		log.Fatalf("issue-session: 签发: %v", err)
	}

	if out := os.Getenv("OUT"); out != "" {
		// token 不含私钥,但仍是凭据 → 0600。
		if err := os.WriteFile(out, []byte(tok), 0o600); err != nil {
			log.Fatalf("issue-session: 写 %s: %v", out, err)
		}
		// 同写 jti(撤销匹配 / Agent SESSION_JTI 用),便于演示撤销。
		if jtiOut := os.Getenv("JTI_OUT"); jtiOut != "" {
			if err := os.WriteFile(jtiOut, []byte(jti), 0o600); err != nil {
				log.Fatalf("issue-session: 写 jti %s: %v", jtiOut, err)
			}
		}
		log.Printf("[issue-session] 已写会话凭证到 %s(tenant=%s sub=%s jti=%s groups=%v ttl=%s)",
			out, tenant, subject, jti, claims.Groups, ttl)
		return
	}
	fmt.Println(tok)
}

// newSigner 与 cmd/api-server 同口径(ed25519 + 固定种子);使 PoP 用 api-server 下发公钥可验本 token。
func newSigner() (*cred.Signer, error) {
	seedB64 := os.Getenv("SASE_CRED_ED25519_SEED")
	if seedB64 == "" {
		return nil, fmt.Errorf("须设 SASE_CRED_ED25519_SEED(与 api-server 同种子,否则 PoP 验签失败)")
	}
	seed, err := base64.RawURLEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("SASE_CRED_ED25519_SEED 非法(需 base64url 的 %d 字节)", ed25519.SeedSize)
	}
	return cred.NewSigner(ed25519.NewKeyFromSeed(seed)), nil
}

func parseTTL(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		log.Fatalf("issue-session: TTL %q 非法", s)
	}
	return d
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envMust(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("issue-session: 须设环境变量 %s", k)
	}
	return v
}
