package secret

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

// DevProvider 是 **dev/测试用**的内存 KEK provider:KEK 取自 env(SASE_DEV_KEK,base64 32B)或临时生成(进程重启即变,
// 重启后老 wrapped_dek **不可解** → 数据失能)。**生产严禁使用**——生产须接 KMS/HSM(R7 选型衍生)。
// Wrap 用 ChaCha20-Poly1305:wrapped = nonce(12B) || ciphertext+tag(16B)。KEKID="dev-mem"(单 KEK,无轮换)。
type DevProvider struct {
	aead  cipher.AEAD
	kekID string
}

// NewDevProvider 构造 dev KEK provider。
//
//	envName 非空:从该 env 取 base64 32B(0 解码长度错→错)。
//	envName 空或 env 未设:生成临时随机 32B,**日志告警**(数据不跨进程,仅 dev)。
func NewDevProvider(envName string) (*DevProvider, error) {
	var key []byte
	if envName != "" {
		if v := os.Getenv(envName); v != "" {
			decoded, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("secret.NewDevProvider: 解码 %s: %w", envName, err)
			}
			if len(decoded) != chacha20poly1305.KeySize {
				return nil, fmt.Errorf("secret.NewDevProvider: %s 需 base64(%d 字节),得 %d", envName, chacha20poly1305.KeySize, len(decoded))
			}
			key = decoded
		}
	}
	if key == nil {
		key = make([]byte, chacha20poly1305.KeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("secret.NewDevProvider: 生成临时 KEK: %w", err)
		}
		log.Printf("[secret] ⚠️ 使用临时 KEK(env %q 未设),进程重启后 wrapped_dek 不可解——**仅 dev 可接受**", envName)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("secret.NewDevProvider: chacha20poly1305: %w", err)
	}
	return &DevProvider{aead: aead, kekID: "dev-mem"}, nil
}

// KEKID 返回 dev KEK 标识(单 KEK)。
func (p *DevProvider) KEKID() string { return p.kekID }

// Wrap:nonce(12B 随机)|| Seal(plaintextDEK)。aead.NonceSize()=12,Overhead=16(tag)。
func (p *DevProvider) Wrap(plaintextDEK []byte) ([]byte, error) {
	if len(plaintextDEK) == 0 {
		return nil, errors.New("secret.Wrap: 空 DEK")
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secret.Wrap: 生成 nonce: %w", err)
	}
	ct := p.aead.Seal(nil, nonce, plaintextDEK, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Unwrap:拆 nonce + ciphertext,Open;失败(KEK 不符/篡改/截断)→ 错误。
func (p *DevProvider) Unwrap(wrapped []byte) ([]byte, error) {
	ns := p.aead.NonceSize()
	if len(wrapped) < ns+p.aead.Overhead() {
		return nil, fmt.Errorf("secret.Unwrap: wrapped 过短(%d < %d)", len(wrapped), ns+p.aead.Overhead())
	}
	nonce, ct := wrapped[:ns], wrapped[ns:]
	dek, err := p.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("secret.Unwrap: %w", err)
	}
	return dek, nil
}
