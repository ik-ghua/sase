// Package cred 是会话凭证机制:签发(控制面)+ 离线验证(PoP)+ TTL(L1 3.4 / 3.8)。
//
// 加密算法**可插拔**(crypto-agility,R7 国密):同一 Claims schema 与令牌格式下,签名算法由 Signer/
// Verifier 内部 scheme 决定——默认 Ed25519(非国密档),可换 **国密 SM2**(gmsm)。部署期按算法选型,
// 契约(Claims、令牌格式 base64url(payload).base64url(sig)、TrustBundle 形态)不变。
// SM4(对称,隧道)与 SM3(杂凑)的性能与隧道收口见 poc/pocG-gmcrypto(SM4 吞吐需国密 CPU,C-G1)。
package cred

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
)

// 算法标识(随 TrustBundle 一并下发,使验证侧知道用哪套 scheme)。
const (
	AlgEd25519 = "ed25519"
	AlgSM2     = "sm2" // 国密
)

// Claims 是会话凭证声明(与算法无关)。
type Claims struct {
	JTI      string   `json:"jti"`
	TenantID string   `json:"tid"`
	Subject  string   `json:"sub"`
	Groups   []string `json:"grp"`
	Posture  string   `json:"pst"`
	Role     string   `json:"role"`
	// 风险(动态访问控制,信任/风险引擎 L2 3.3):签发时由控制面 risk 引擎填入,PoP PEP 作运行期条件求值。
	// 时效为签发时点,突变即时性由撤销补(risk L2 3.4)。空 RiskLevel = 未算/无信号,PEP 视作最低风险。
	RiskScore int    `json:"rsc,omitempty"`
	RiskLevel string `json:"rlv,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpireAt  int64  `json:"exp"`
}

// PublicKey 是算法无关的公钥(Alg + 原始字节),供 TrustBundle 下发与验证侧重建。
type PublicKey struct {
	Alg   string
	Bytes []byte
}

var (
	ErrMalformed    = errors.New("cred: 凭证格式非法")
	ErrBadSignature = errors.New("cred: 签名校验失败")
	ErrExpired      = errors.New("cred: 凭证已过期")
	ErrUnknownAlg   = errors.New("cred: 未知签名算法")
)

// ---- 内部 scheme 抽象(算法插拔点)----

type signScheme interface {
	sign(payload []byte) ([]byte, error)
	public() PublicKey
}

type verifyScheme interface {
	verify(payload, sig []byte) bool
}

// ---- Signer / Verifier ----

// Signer 持私钥签发凭证(控制面)。
type Signer struct{ s signScheme }

// GenerateSigner 生成 Ed25519 签发器(默认,非国密档)。
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cred: 生成 ed25519: %w", err)
	}
	return &Signer{s: ed25519Scheme{priv: priv}}, nil
}

// GenerateSignerSM2 生成国密 SM2 签发器(crypto-agility:同契约换算法)。
func GenerateSignerSM2() (*Signer, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cred: 生成 sm2: %w", err)
	}
	return &Signer{s: sm2Scheme{priv: priv}}, nil
}

// NewSigner 从已有 Ed25519 私钥构造(种子持久化场景)。
func NewSigner(priv ed25519.PrivateKey) *Signer { return &Signer{s: ed25519Scheme{priv: priv}} }

// Public 返回算法无关公钥(下发 PoP 作 TrustBundle)。
func (s *Signer) Public() PublicKey { return s.s.public() }

// Issue 签发凭证:填 iat/exp,按所选算法签名声明。
func (s *Signer) Issue(c Claims, ttl time.Duration, now time.Time) (string, error) {
	c.IssuedAt = now.Unix()
	c.ExpireAt = now.Add(ttl).Unix()
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("cred: 序列化声明: %w", err)
	}
	sig, err := s.s.sign(payload)
	if err != nil {
		return "", fmt.Errorf("cred: 签名: %w", err)
	}
	return b64(payload) + "." + b64(sig), nil
}

// Verifier 持公钥离线验证(PoP)。
type Verifier struct{ v verifyScheme }

// NewVerifier 据 PublicKey 的算法构造对应验证 scheme。
func NewVerifier(pk PublicKey) (*Verifier, error) {
	switch pk.Alg {
	case AlgEd25519:
		if len(pk.Bytes) != ed25519.PublicKeySize {
			return nil, ErrMalformed
		}
		return &Verifier{v: ed25519Scheme{pub: ed25519.PublicKey(pk.Bytes)}}, nil
	case AlgSM2:
		pub, err := sm2PubFromBytes(pk.Bytes)
		if err != nil {
			return nil, err
		}
		return &Verifier{v: sm2Scheme{pub: pub}}, nil
	default:
		return nil, ErrUnknownAlg
	}
}

// Verify 校验签名与有效期(fail-closed)。
func (v *Verifier) Verify(token string, now time.Time) (Claims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return Claims{}, ErrMalformed
	}
	payload, err := unb64(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	sig, err := unb64(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	if !v.v.verify(payload, sig) {
		return Claims{}, ErrBadSignature
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, ErrMalformed
	}
	if now.Unix() >= c.ExpireAt {
		return Claims{}, ErrExpired
	}
	return c, nil
}

// ---- Ed25519 scheme ----

type ed25519Scheme struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (e ed25519Scheme) sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(e.priv, payload), nil
}
func (e ed25519Scheme) public() PublicKey {
	return PublicKey{Alg: AlgEd25519, Bytes: e.priv.Public().(ed25519.PublicKey)}
}
func (e ed25519Scheme) verify(payload, sig []byte) bool { return ed25519.Verify(e.pub, payload, sig) }

// ---- SM2 国密 scheme ----

type sm2Scheme struct {
	priv *sm2.PrivateKey
	pub  *ecdsa.PublicKey
}

func (s sm2Scheme) sign(payload []byte) ([]byte, error) {
	return s.priv.SignWithSM2(rand.Reader, nil, payload) // nil uid → 默认用户标识;内部 SM3+ZA
}
func (s sm2Scheme) public() PublicKey {
	return PublicKey{Alg: AlgSM2, Bytes: sm2PubToBytes(&s.priv.PublicKey)}
}
func (s sm2Scheme) verify(payload, sig []byte) bool {
	return sm2.VerifyASN1WithSM2(s.pub, nil, payload, sig)
}

// SM2 公钥序列化:未压缩点 0x04 || X(32) || Y(32)(避免 deprecated elliptic.Marshal)。
func sm2PubToBytes(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 1+32+32)
	out[0] = 0x04
	pub.X.FillBytes(out[1:33])
	pub.Y.FillBytes(out[33:65])
	return out
}

func sm2PubFromBytes(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 65 || b[0] != 0x04 {
		return nil, ErrMalformed
	}
	return &ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     new(big.Int).SetBytes(b[1:33]),
		Y:     new(big.Int).SetBytes(b[33:65]),
	}, nil
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
