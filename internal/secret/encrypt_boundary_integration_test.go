package secret_test

// Slice36 待后续③:secret.Service 的 Encrypt/Decrypt 边界单测(VM/本机真 PG,需 4 DSN;未设则 SKIP)。
// 密文格式:nonce(12B) || ct+tag(16B);基于 GetDEK + ChaCha20-Poly1305。
// 读 secret.go 确认:Decrypt 已有 `len(ciphertext) < NonceSize+16` 长度护栏 → 短/空密文走 error 不 panic;
// 本组测试是回归防线 + 覆盖往返/篡改/空明文/跨租户隔离/已销毁 DEK 等语义。
//
// 覆盖:
//   ① 正常往返(Encrypt→Decrypt 还原明文,含多长度明文)。
//   ② 密文过短(< 28B nonce+tag)/ 空密文 → Decrypt 返 error 不 panic(表驱动覆盖 0..27)。
//   ③ AEAD 篡改(翻转密文任一字节)→ Decrypt 认证失败。
//   ④ 空明文 Encrypt→Decrypt 往返 → 得空明文(非 error)。
//   ⑤ 跨租户隔离:A 的密文用 B 的 DEK 解 → 失败(DEK 按租户隔离,AEAD 认证失败)。
//   ⑥ DEK 已 destroyed → Encrypt/Decrypt 返 ErrDestroyed。
//   ⑦ 未创建 DEK 的租户 → Encrypt 返 ErrNotFound。

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/secret"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)
	tid := uuid.NewString()
	mkTenant(t, ctx, store, tid)
	if err := svc.CreateTenantKey(ctx, tid); err != nil {
		t.Fatalf("CreateTenantKey: %v", err)
	}

	for _, pt := range [][]byte{
		[]byte("hello-secret"),
		[]byte("a"),
		bytes.Repeat([]byte{0xAB}, 1024),
	} {
		ctext, err := svc.Encrypt(ctx, tid, pt)
		if err != nil {
			t.Fatalf("Encrypt(%dB): %v", len(pt), err)
		}
		// 密文 = nonce(12) + ct + tag(16) > 明文
		if len(ctext) < 12+16 {
			t.Fatalf("密文过短: %d", len(ctext))
		}
		got, err := svc.Decrypt(ctx, tid, ctext)
		if err != nil {
			t.Fatalf("Decrypt(%dB): %v", len(pt), err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("往返还原不符(明文 %dB)", len(pt))
		}
	}
}

// TestEncryptEmptyPlaintextRoundtrip 空明文 Encrypt→Decrypt 应得空明文(非 error)。
func TestEncryptEmptyPlaintextRoundtrip(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)
	tid := uuid.NewString()
	mkTenant(t, ctx, store, tid)
	if err := svc.CreateTenantKey(ctx, tid); err != nil {
		t.Fatalf("CreateTenantKey: %v", err)
	}

	for _, empty := range [][]byte{nil, {}} {
		ctext, err := svc.Encrypt(ctx, tid, empty)
		if err != nil {
			t.Fatalf("Encrypt(空明文 %v): %v", empty, err)
		}
		// 空明文密文 = nonce(12) + tag(16) = 28
		if len(ctext) != 12+16 {
			t.Fatalf("空明文密文应 28B,得 %d", len(ctext))
		}
		got, err := svc.Decrypt(ctx, tid, ctext)
		if err != nil {
			t.Fatalf("Decrypt(空明文密文): %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("空明文往返应得 0 长度,得 %d", len(got))
		}
	}
}

// TestDecryptShortCiphertextNoPanic 短/空密文(0..27B)→ Decrypt 返 error,绝不 panic。
func TestDecryptShortCiphertextNoPanic(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)
	tid := uuid.NewString()
	mkTenant(t, ctx, store, tid)
	if err := svc.CreateTenantKey(ctx, tid); err != nil {
		t.Fatalf("CreateTenantKey: %v", err)
	}

	// 合法密文最小 28B(nonce 12 + tag 16);逐个测 0..27 长度的"过短"密文。
	for n := 0; n < 28; n++ {
		ct := make([]byte, n) // 全零:既过短又非合法密文
		got, err := svc.Decrypt(ctx, tid, ct)
		if err == nil {
			t.Fatalf("Decrypt(%dB 短密文) 应返 error,得 nil(plain=%dB)", n, len(got))
		}
		if got != nil {
			t.Fatalf("Decrypt 失败时应返 nil,得 %dB", len(got))
		}
	}
	// nil 密文同样不 panic。
	if _, err := svc.Decrypt(ctx, tid, nil); err == nil {
		t.Fatal("Decrypt(nil) 应返 error")
	}
}

// TestDecryptTamperedRejects 翻转密文任一字节(nonce / 密文 / tag 段)→ Decrypt 认证失败。
func TestDecryptTamperedRejects(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)
	tid := uuid.NewString()
	mkTenant(t, ctx, store, tid)
	if err := svc.CreateTenantKey(ctx, tid); err != nil {
		t.Fatalf("CreateTenantKey: %v", err)
	}

	pt := []byte("tamper-me-please")
	const nonceLen, tagLen = 12, 16
	// nonce 首字节 / 密文中段 / tag 末字节
	for _, idxFn := range []func(c []byte) int{
		func(_ []byte) int { return 0 },
		func(c []byte) int { return nonceLen + (len(c)-nonceLen-tagLen)/2 },
		func(c []byte) int { return len(c) - 1 },
	} {
		ctext, err := svc.Encrypt(ctx, tid, pt)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		i := idxFn(ctext)
		ctext[i] ^= 0xFF
		if _, err := svc.Decrypt(ctx, tid, ctext); err == nil {
			t.Fatalf("翻转密文[%d] 后 Decrypt 应认证失败", i)
		}
	}
}

// TestDecryptCrossTenantFails A 的密文用 B 的 DEK 解 → 失败(DEK 按租户隔离,AEAD 认证失败)。
func TestDecryptCrossTenantFails(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)
	tidA, tidB := uuid.NewString(), uuid.NewString()
	mkTenant(t, ctx, store, tidA)
	mkTenant(t, ctx, store, tidB)
	if err := svc.CreateTenantKey(ctx, tidA); err != nil {
		t.Fatalf("Create A: %v", err)
	}
	if err := svc.CreateTenantKey(ctx, tidB); err != nil {
		t.Fatalf("Create B: %v", err)
	}

	ctext, err := svc.Encrypt(ctx, tidA, []byte("for-A-only"))
	if err != nil {
		t.Fatalf("Encrypt A: %v", err)
	}
	// 用 B 的 DEK 解 A 的密文 → AEAD 认证失败(两租户 DEK 各自独立随机生成,极大概率不同)。
	if _, err := svc.Decrypt(ctx, tidB, ctext); err == nil {
		t.Fatal("A 的密文用 B 的 DEK 解应失败(DEK 跨租户隔离)")
	}
	// 用 A 自己的 DEK 仍可解(对照,证密文本身有效)。
	if _, err := svc.Decrypt(ctx, tidA, ctext); err != nil {
		t.Fatalf("A 密文用 A DEK 解应成功,得 %v", err)
	}
}

// TestEncryptDecryptAfterDestroy DEK 销毁后 Encrypt/Decrypt 均返 ErrDestroyed(数据等效不可恢复)。
func TestEncryptDecryptAfterDestroy(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)
	tid := uuid.NewString()
	mkTenant(t, ctx, store, tid)
	if err := svc.CreateTenantKey(ctx, tid); err != nil {
		t.Fatalf("CreateTenantKey: %v", err)
	}
	// 先加密一段(销毁前密文落库的语义模拟)。
	ctext, err := svc.Encrypt(ctx, tid, []byte("doomed"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// 销毁 DEK。
	if err := svc.DestroyTenantKey(ctx, tid); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// Encrypt → ErrDestroyed。
	if _, err := svc.Encrypt(ctx, tid, []byte("x")); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("销毁后 Encrypt 应 ErrDestroyed,得 %v", err)
	}
	// Decrypt 既有密文 → ErrDestroyed(注意:Decrypt 的长度护栏在 GetDEK 之前,合法长度密文才走到 GetDEK)。
	if _, err := svc.Decrypt(ctx, tid, ctext); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("销毁后 Decrypt 应 ErrDestroyed,得 %v", err)
	}
}

// TestEncryptNoKeyReturnsNotFound 未建 DEK 的租户 Encrypt → ErrNotFound(经 GetDEK 透传)。
func TestEncryptNoKeyReturnsNotFound(t *testing.T) {
	store, ctx := newStore(t)
	svc := newSecretSvc(t, store)
	tid := uuid.NewString()
	mkTenant(t, ctx, store, tid) // 建租户但不建 DEK
	if _, err := svc.Encrypt(ctx, tid, []byte("x")); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("无 DEK 租户 Encrypt 应 ErrNotFound,得 %v", err)
	}
}
