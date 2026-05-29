// PoC-G 国密加密栈性能基准(在 VM 真跑,不编造数)。
// 非对称(凭证签名/PKI):SM2 vs Ed25519。对称(隧道):SM4-GCM vs AES-128-GCM vs ChaCha20-Poly1305。
// 注:该 VM(Intel Xeon E5)**无 SM4 硬件加速(无 AVX-512+GFNI / 专用 SM4 指令)**,故 SM4 数为软件
// baseline,印证国密选型 v0.3 的 C-G1(PoP CPU 须带 SM4 加速)与 M-G1(SM4 约慢 ChaCha20 一个量级)。
// 跑法:go test -bench . -benchmem ./poc/pocG-gmcrypto/
package pocg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm4"
	"golang.org/x/crypto/chacha20poly1305"
)

var msg = []byte("sase session credential payload — tenant/subject/groups/exp claims blob")

// ---- 非对称:凭证签名(SM2 vs Ed25519)----

func BenchmarkSM2Sign(b *testing.B) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := priv.SignWithSM2(rand.Reader, nil, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSM2Verify(b *testing.B) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	sig, _ := priv.SignWithSM2(rand.Reader, nil, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !sm2.VerifyASN1WithSM2(&priv.PublicKey, nil, msg, sig) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkEd25519Sign(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(priv, msg)
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ed25519.Verify(pub, msg, sig) {
			b.Fatal("verify failed")
		}
	}
}

// ---- 对称:隧道吞吐(1500B/包,报 MB/s)----

var packet = make([]byte, 1500)

func benchAEAD(b *testing.B, aead cipher.AEAD) {
	nonce := make([]byte, aead.NonceSize())
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = aead.Seal(nil, nonce, packet, nil)
	}
}

func BenchmarkSM4GCM(b *testing.B) {
	block, _ := sm4.NewCipher(make([]byte, 16))
	aead, _ := cipher.NewGCM(block)
	benchAEAD(b, aead)
}

func BenchmarkAES128GCM(b *testing.B) {
	block, _ := aes.NewCipher(make([]byte, 16))
	aead, _ := cipher.NewGCM(block)
	benchAEAD(b, aead)
}

func BenchmarkChaCha20Poly1305(b *testing.B) {
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	benchAEAD(b, aead)
}
