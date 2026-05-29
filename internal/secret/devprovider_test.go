package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestDevProviderRoundtrip(t *testing.T) {
	p, err := NewDevProvider("__SECRET_UNSET_ENV__") // 临时 KEK 路径(env 未设)
	if err != nil {
		t.Fatalf("NewDevProvider: %v", err)
	}
	if p.KEKID() != "dev-mem" {
		t.Errorf("KEKID 应 dev-mem,得 %s", p.KEKID())
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("生成 DEK: %v", err)
	}
	wrapped, err := p.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// wrapped 含 nonce(12)+ct(>=tag 16)
	if len(wrapped) < 12+16 {
		t.Fatalf("wrapped 过短: %d", len(wrapped))
	}
	got, err := p.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap 还原 DEK 不符")
	}
}

func TestDevProviderTamperedRejects(t *testing.T) {
	p, _ := NewDevProvider("")
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	wrapped, _ := p.Wrap(dek)
	// 改一个字节(末尾,在 ciphertext+tag 内)→ AEAD 认证失败
	wrapped[len(wrapped)-1] ^= 0xFF
	if _, err := p.Unwrap(wrapped); err == nil {
		t.Fatal("篡改后 Unwrap 应失败")
	}
}

func TestDevProviderEnvBased(t *testing.T) {
	// 用固定 base64 32B key:确保 Wrap/Unwrap 跨 Provider 实例可用(测 env 路径)。
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	t.Setenv("SASE_TEST_KEK_FIXED", encoded)
	p1, err := NewDevProvider("SASE_TEST_KEK_FIXED")
	if err != nil {
		t.Fatalf("NewDevProvider env: %v", err)
	}
	dek := []byte("0123456789abcdef0123456789abcdef") // 32B
	wrapped, _ := p1.Wrap(dek)
	// 新建一个 Provider(同 env)→ 应能解开
	p2, err := NewDevProvider("SASE_TEST_KEK_FIXED")
	if err != nil {
		t.Fatalf("NewDevProvider env(2): %v", err)
	}
	got, err := p2.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap 跨实例: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("跨实例 Unwrap 还原不符")
	}
	// 临时 KEK 的实例不应能解 env KEK 包的 wrapped(KEK 不同)
	pTemp, _ := NewDevProvider("")
	if _, err := pTemp.Unwrap(wrapped); err == nil {
		t.Fatal("临时 KEK 实例不应能解 env KEK 包的 wrapped(否则 KEK 隔离破)")
	}
}

func TestDevProviderInvalidEnv(t *testing.T) {
	t.Setenv("SASE_TEST_KEK_BAD", "not-base64!!!")
	if _, err := NewDevProvider("SASE_TEST_KEK_BAD"); err == nil {
		t.Fatal("非法 base64 应报错")
	}
	t.Setenv("SASE_TEST_KEK_SHORT", base64.StdEncoding.EncodeToString([]byte("short")))
	if _, err := NewDevProvider("SASE_TEST_KEK_SHORT"); err == nil {
		t.Fatal("长度非 32B 应报错")
	}
}
