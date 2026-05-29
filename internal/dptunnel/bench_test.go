package dptunnel

import (
	"bytes"
	"testing"
)

// BenchmarkSeal 测各加密档封装吞吐(1400B 典型 MTU 包)。
// ChaCha20-Poly1305 = 本阶段可信基准;SM4-GCM = gmsm 软件实现(慢,PoC-G M-G2),
// **带加速吞吐待国密 CPU(C-G1)**——此处软件数仅供功能对照,非国密生产吞吐。
func BenchmarkSeal(b *testing.B) {
	pkt := bytes.Repeat([]byte{0x5A}, 1400)
	for _, alg := range []string{AlgChaCha20Poly1305, AlgSM4GCM} {
		b.Run(alg, func(b *testing.B) {
			klen, _ := KeyLen(alg)
			key := make([]byte, klen)
			aead, err := NewAEAD(alg, key)
			if err != nil {
				b.Fatalf("NewAEAD: %v", err)
			}
			s := NewSession(aead, 1, 0, 1)
			b.SetBytes(int64(len(pkt)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Seal(pkt); err != nil {
					b.Fatalf("Seal: %v", err)
				}
			}
		})
	}
}
