package dptunnel

import (
	"bytes"
	"testing"
)

func newPair(t *testing.T, alg string, fecK int) (a, b *Session) {
	t.Helper()
	klen, err := KeyLen(alg)
	if err != nil {
		t.Fatalf("KeyLen: %v", err)
	}
	key := make([]byte, klen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	aeadA, err := NewAEAD(alg, key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}
	aeadB, _ := NewAEAD(alg, key)
	// A 发用 dir0、收用 dir1;B 镜像
	return NewSession(aeadA, fecK, 0, 1), NewSession(aeadB, fecK, 1, 0)
}

// 收发往返(两加密档),含变长包。
func TestRoundTrip(t *testing.T) {
	for _, alg := range []string{AlgChaCha20Poly1305, AlgSM4GCM} {
		t.Run(alg, func(t *testing.T) {
			a, b := newPair(t, alg, 1) // 无 FEC
			payloads := [][]byte{[]byte("hello"), []byte(""), bytes.Repeat([]byte{0xAB}, 1400)}
			for _, pt := range payloads {
				frames, err := a.Seal(pt)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				if len(frames) != 1 {
					t.Fatalf("无 FEC 应只 1 帧,得 %d", len(frames))
				}
				out, err := b.Open(frames[0])
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if len(out) != 1 || !bytes.Equal(out[0], pt) {
					t.Fatalf("往返不一致:得 %v", out)
				}
			}
		})
	}
}

// 重放/重复帧被拒。
func TestReplayReject(t *testing.T) {
	a, b := newPair(t, AlgChaCha20Poly1305, 1)
	frames, _ := a.Seal([]byte("once"))
	if out, _ := b.Open(frames[0]); len(out) != 1 {
		t.Fatal("首次应交付")
	}
	if out, _ := b.Open(frames[0]); len(out) != 0 {
		t.Fatal("重放应被拒、不交付")
	}
}

// 篡改密文 → 认证失败,不交付。
func TestTamperRejected(t *testing.T) {
	a, b := newPair(t, AlgChaCha20Poly1305, 1)
	frames, _ := a.Seal([]byte("secret"))
	bad := append([]byte(nil), frames[0]...)
	bad[len(bad)-1] ^= 0xFF // 翻转密文末字节
	if out, _ := b.Open(bad); len(out) != 0 {
		t.Fatal("篡改帧应认证失败、不交付")
	}
}

// 篡改帧头(BlockID)→ AEAD aad 认证失败,不交付(评审 B2/S2/S3)。
func TestHeaderTamperRejected(t *testing.T) {
	a, b := newPair(t, AlgChaCha20Poly1305, 1)
	frames, _ := a.Seal([]byte("payload"))
	bad := append([]byte(nil), frames[0]...)
	bad[2] ^= 0xFF // 翻转 BlockID 高字节(帧头,在 aad 内)
	if out, _ := b.Open(bad); len(out) != 0 {
		t.Fatal("篡改帧头应致 aad 认证失败、不交付")
	}
}

// 计数器达阈值 → Seal fail-closed(防 nonce 回绕复用,评审 B1)。
func TestRekeyRequired(t *testing.T) {
	a, _ := newPair(t, AlgChaCha20Poly1305, 1)
	a.sendCtr = rekeyAfter // 直达阈值
	if _, err := a.Seal([]byte("x")); err != ErrRekeyRequired {
		t.Fatalf("达阈值应返回 ErrRekeyRequired,得 %v", err)
	}
}

// sendDir==recvDir → NewSession panic(防同密钥 nonce 复用,评审 B1)。
func TestDirAssertPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("sendDir==recvDir 应 panic")
		}
	}()
	aead, _ := NewAEAD(AlgChaCha20Poly1305, make([]byte, 32))
	NewSession(aead, 1, 0, 0)
}

// FEC:块内丢 1 个 data,经 parity 恢复(变长包,验零填充 XOR)。
func TestFECRecoverOne(t *testing.T) {
	a, b := newPair(t, AlgChaCha20Poly1305, 4)
	payloads := [][]byte{[]byte("aaaa"), []byte("bbbbbbbb"), []byte("cc"), []byte("dddddd")}

	var wire [][]byte // 收集本块所有帧(4 data + 1 parity)
	for _, pt := range payloads {
		frames, _ := a.Seal(pt)
		wire = append(wire, frames...)
	}
	if len(wire) != 5 {
		t.Fatalf("K=4 应产 4 data + 1 parity = 5 帧,得 %d", len(wire))
	}

	// 丢掉第 2 个 data 帧(index 1),其余按序投递
	got := map[string]bool{}
	for i, fr := range wire {
		if i == 1 {
			continue // 模拟丢包
		}
		out, err := b.Open(fr)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		for _, pt := range out {
			got[string(pt)] = true
		}
	}
	for _, pt := range payloads {
		if !got[string(pt)] {
			t.Fatalf("FEC 应恢复全部 4 包,缺 %q;got=%v", pt, keys(got))
		}
	}
}

// FEC:丢 2 个(超出 m=1 能力)→ 不误恢复出垃圾,仅交付收到的。
func TestFECNoFalseRecover(t *testing.T) {
	a, b := newPair(t, AlgChaCha20Poly1305, 4)
	payloads := [][]byte{[]byte("p0"), []byte("p1"), []byte("p2"), []byte("p3")}
	var wire [][]byte
	for _, pt := range payloads {
		frames, _ := a.Seal(pt)
		wire = append(wire, frames...)
	}
	// 丢 index 1 和 2 两个 data
	got := map[string]bool{}
	for i, fr := range wire {
		if i == 1 || i == 2 {
			continue
		}
		out, _ := b.Open(fr)
		for _, pt := range out {
			got[string(pt)] = true
		}
	}
	if got["p1"] || got["p2"] {
		t.Fatal("丢 2 个超出 XOR 能力,不应恢复出 p1/p2")
	}
	if !got["p0"] || !got["p3"] {
		t.Fatal("收到的 p0/p3 应交付")
	}
	if len(got) != 2 {
		t.Fatalf("应只交付 2 个,得 %v", keys(got))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
