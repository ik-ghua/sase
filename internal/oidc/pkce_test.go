package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// TestPKCE 校 code_verifier 长度/字符集 + code_challenge=SHA256(verifier).b64url(RFC 7636)。
func TestPKCE(t *testing.T) {
	v, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier: %v", err)
	}
	// b64url 无填充:无 +/= 字符
	if strings.ContainsAny(v, "+/=") {
		t.Fatalf("code_verifier 含非 b64url 字符: %q", v)
	}
	// 32B 输入 → 43 字符 b64url(无填充)
	if len(v) != 43 {
		t.Fatalf("code_verifier 长度 want 43,得 %d", len(v))
	}
	// challenge 应为 SHA256 + b64url-no-padding
	c := codeChallengeS256(v)
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if c != want {
		t.Fatalf("code_challenge: got %s want %s", c, want)
	}
}

// TestPKCEUnique 两次生成 verifier 不重复(熵充足)。
func TestPKCEUnique(t *testing.T) {
	a, _ := generateCodeVerifier()
	b, _ := generateCodeVerifier()
	if a == b {
		t.Fatal("两次生成的 code_verifier 相同(熵不足或 rand 错)")
	}
}
