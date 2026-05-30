package secret

// DevProvider Wrap/Unwrap 边界单测(纯逻辑,不依赖 PG):
//   - Unwrap 对异常输入(空、过短 < nonce+tag、截断到 nonce 内)绝不 panic,返回 error;
//   - Wrap 空 DEK → error;
//   - 篡改 wrapped 任一字节(nonce 段 / 密文段 / tag 段)→ Unwrap AEAD 认证失败;
//   - Wrap→Unwrap 往返还原 DEK(覆盖不同长度 DEK:16B SM4 档大小 / 32B ChaCha20)。
// 现状(读 devprovider.go 确认):Unwrap 已有 `len(wrapped) < ns+Overhead` 长度护栏 →
// 异常输入走 error 不 panic;本组测试是回归防线(防未来改动引入越界 panic)。

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestUnwrapBoundaryInputsNoPanic 覆盖 Unwrap 对短/空/截断密文绝不 panic(数据面/控制面纪律)。
func TestUnwrapBoundaryInputsNoPanic(t *testing.T) {
	p, err := NewDevProvider("__SECRET_UNSET_ENV_BOUNDARY__")
	if err != nil {
		t.Fatalf("NewDevProvider: %v", err)
	}
	ns := p.aead.NonceSize()         // 12
	minLen := ns + p.aead.Overhead() // 12+16=28:合法 wrapped 的最小长度
	zeros := func(n int) []byte { return make([]byte, n) }

	cases := []struct {
		name    string
		wrapped []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one_byte", []byte{0x00}},
		{"len_just_under_nonce", zeros(ns - 1)},   // 11 < nonce,远不足
		{"len_eq_nonce", zeros(ns)},               // 12:有 nonce 无 tag
		{"len_nonce_plus_one", zeros(ns + 1)},     // 13:不足 nonce+tag
		{"len_just_under_min", zeros(minLen - 1)}, // 27:差一字节
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 任何 panic(含 index out of range)都会让本子测失败而非崩进程——
			// 但项目纪律要求代码本身不 panic,故这里直接断言返回 error。
			dek, err := p.Unwrap(c.wrapped)
			if err == nil {
				t.Fatalf("Unwrap(%d 字节) 应返 error,得 nil(dek=%d 字节)", len(c.wrapped), len(dek))
			}
			if dek != nil {
				t.Fatalf("Unwrap 失败时应返 nil dek,得 %d 字节", len(dek))
			}
		})
	}
}

// TestUnwrapMinLenBoundaryAuthFails 长度恰好达 minLen(28)但内容全零 → 长度护栏放行、AEAD 认证失败(非 panic)。
func TestUnwrapMinLenBoundaryAuthFails(t *testing.T) {
	p, _ := NewDevProvider("")
	minLen := p.aead.NonceSize() + p.aead.Overhead() // 28
	wrapped := make([]byte, minLen)                  // 全零:长度合法但非合法密文
	if _, err := p.Unwrap(wrapped); err == nil {
		t.Fatal("全零 minLen 字节 wrapped 应 AEAD 认证失败,得 nil")
	}
}

// TestWrapEmptyDEKRejected 空 DEK Wrap → error(不 panic,不产出可被误用的空包)。
func TestWrapEmptyDEKRejected(t *testing.T) {
	p, _ := NewDevProvider("")
	for _, in := range [][]byte{nil, {}} {
		if _, err := p.Wrap(in); err == nil {
			t.Fatalf("Wrap(空 DEK %v) 应返 error", in)
		}
	}
}

// TestWrapUnwrapRoundtripVariousLen 不同长度 DEK 往返还原(16B=SM4 档 / 32B=ChaCha20 档)。
func TestWrapUnwrapRoundtripVariousLen(t *testing.T) {
	p, _ := NewDevProvider("")
	for _, n := range []int{16, 24, 32, 64} {
		dek := make([]byte, n)
		if _, err := rand.Read(dek); err != nil {
			t.Fatalf("rand: %v", err)
		}
		wrapped, err := p.Wrap(dek)
		if err != nil {
			t.Fatalf("Wrap(%dB): %v", n, err)
		}
		got, err := p.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("Unwrap(%dB): %v", n, err)
		}
		if !bytes.Equal(got, dek) {
			t.Fatalf("往返还原不符(%dB)", n)
		}
	}
}

// TestUnwrapTamperEachSegment 翻转 wrapped 各段(nonce / 密文 / tag)任一字节 → Unwrap 认证失败。
func TestUnwrapTamperEachSegment(t *testing.T) {
	p, _ := NewDevProvider("")
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ns := p.aead.NonceSize() // 12
	tagLen := p.aead.Overhead()
	// 翻转位点:nonce 首字节、密文中段、tag 末字节(密文段 = [ns, len-tag),tag 段 = [len-tag, len))
	for _, idxFn := range []func(w []byte) int{
		func(_ []byte) int { return 0 },                         // nonce 段
		func(w []byte) int { return ns + (len(w)-ns-tagLen)/2 }, // 密文段中部
		func(w []byte) int { return len(w) - 1 },                // tag 段末字节
	} {
		wrapped, err := p.Wrap(dek)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		i := idxFn(wrapped)
		wrapped[i] ^= 0xFF
		if _, err := p.Unwrap(wrapped); err == nil {
			t.Fatalf("翻转 wrapped[%d] 后 Unwrap 应认证失败", i)
		}
	}
}
