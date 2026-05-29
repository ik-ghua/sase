// Package dptunnel 是 SD-WAN 数据面隧道的协议核心(L2 `sase-l2-data-plane-tunnel.md`):
// crypto-agile AEAD 封装 + 数据报帧 + 重放保护 + XOR-FEC + Session。
//
// 本包是「骨架」:实现可插拔加密(ChaCha20-Poly1305 / SM4-GCM,印证 crypto-agility)、密文数据报封装、
// 单调计数器重放保护、块状 XOR 前向纠错。**不含**:握手/密钥协商(Noise+ZTP,待密码学审查)——Session
// 接受外部已协商的会话密钥;TUN 设备与 PoP 每租户路由转发(需 CAP_NET_ADMIN/netns,后续集成刀)。
//
// 国密 SM4-GCM 功能正确可测,但软件实现慢 AES/ChaCha 数倍(PoC-G M-G2),**带加速吞吐待国密 CPU(C-G1)**。
package dptunnel

import (
	"crypto/cipher"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
	"golang.org/x/crypto/chacha20poly1305"
)

// 加密档名(与 cred 的 SASE_CRED_ALG 同范式;经 xDS SiteConfig 下发 tunnel_alg)。
const (
	AlgChaCha20Poly1305 = "chacha20poly1305" // 非国密,默认,现可基准
	AlgSM4GCM           = "sm4gcm"           // 国密,gmsm;带加速吞吐待国密 CPU
)

// AEAD 是隧道加密 provider 抽象:标准 AEAD + 档名。换算法不改帧/重放/FEC(crypto-agility)。
type AEAD interface {
	cipher.AEAD
	Name() string
}

type namedAEAD struct {
	cipher.AEAD
	name string
}

func (a namedAEAD) Name() string { return a.name }

// KeyLen 返回某档所需会话密钥字节数(供握手层校验协商出的密钥长度)。
func KeyLen(alg string) (int, error) {
	switch alg {
	case AlgChaCha20Poly1305:
		return chacha20poly1305.KeySize, nil // 32
	case AlgSM4GCM:
		return 16, nil // SM4 块密钥 128bit
	default:
		return 0, fmt.Errorf("dptunnel: 未知加密档 %q", alg)
	}
}

// NewAEAD 按档名 + 会话密钥构造 AEAD provider。只组合标准原语(不自研密码),见 L2 7.1。
func NewAEAD(alg string, key []byte) (AEAD, error) {
	want, err := KeyLen(alg)
	if err != nil {
		return nil, err
	}
	if len(key) != want {
		return nil, fmt.Errorf("dptunnel: 档 %q 需 %d 字节密钥,得 %d", alg, want, len(key))
	}
	switch alg {
	case AlgChaCha20Poly1305:
		a, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return namedAEAD{AEAD: a, name: alg}, nil
	case AlgSM4GCM:
		blk, err := sm4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		a, err := cipher.NewGCM(blk) // GCM 模式与块密码正交,SM4 复用标准 GCM
		if err != nil {
			return nil, err
		}
		return namedAEAD{AEAD: a, name: alg}, nil
	default:
		return nil, fmt.Errorf("dptunnel: 未知加密档 %q", alg)
	}
}
