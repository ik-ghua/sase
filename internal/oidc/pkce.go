package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// codeVerifierLen 是 PKCE code_verifier 字节长度(RFC 7636 §4.1:43-128 字符 base64url 编码,
// 即原始字节 32-96B;取 32 上限稳健且简单)。
const codeVerifierLen = 32

// generateCodeVerifier 生成 PKCE code_verifier(RFC 7636):随机字节 + base64url 无填充。
func generateCodeVerifier() (string, error) {
	b := make([]byte, codeVerifierLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: rand code_verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// codeChallengeS256 由 code_verifier 算 PKCE code_challenge(method=S256):
// SHA256(verifier) 再 base64url 无填充(RFC 7636 §4.2)。
func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
