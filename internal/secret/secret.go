// Package secret 是 KMS/信封加密模块(L1 3.5/3.16,Slice34):
// 每租户一把 **DEK**(数据加密密钥,32B,ChaCha20-Poly1305 起步,crypto-agile)由 **KEK**(密钥加密密钥,
// 仅在 Provider 内存/KMS/HSM,**不入库**)包裹后持久化于 `tenant_keys.wrapped_dek`。
// 安全性来自 **KEK 与 wrapped_dek 的分离**:即便 wrapped_dek 泄露(DB 备份等),无 KEK 不可解。
//
// **生命周期(L1 3.16):** 租户创建 → CreateTenantKey(生成 DEK+Wrap+落库);租户硬删(注销宽限期末,
// 待定时清扫刀)→ DestroyTenantKey(wrapped_dek→NULL + destroyed_at,**密钥销毁式删除,不可逆**)。
// 一旦 DEK 销毁,任何用本 DEK 加密的数据等效失能——这是 PIPL/L1 3.16 删除权的工程实现。
//
// **诚实状态(Slice34):** 本模块=基础设施,**当前无业务数据用 DEK 加密**(IdPConfig 等 secret-bearing
// 字段未建);本刀让 DEK 生命周期就绪,首个加密用户接入即可用。生产 KMS/HSM 接入待 R7 选型衍生。
package secret

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/dptunnel"
)

// 标准 DEK 算法:与 dptunnel/cred 同栈(crypto-agility 顶层一致;国密档时 SM4-GCM 替)。
const (
	AlgChaCha20Poly1305 = dptunnel.AlgChaCha20Poly1305 // 32B 密钥
)

// ErrAlreadyExists 表示 CreateTenantKey 重复创建(同租户已有密钥行)。
var ErrAlreadyExists = errors.New("secret: 该租户已有密钥(CreateTenantKey 不幂等覆盖,防意外重生 DEK 致旧加密数据解不开)")

// ErrNotFound 表示该租户无密钥行(未 CreateTenantKey 或被删,但本模块只销毁不删行,此处指未创建)。
var ErrNotFound = errors.New("secret: 该租户无密钥")

// ErrDestroyed 表示 DEK 已被销毁(wrapped_dek=NULL,destroyed_at 非空)——加密数据应被视为不可恢复。
var ErrDestroyed = errors.New("secret: DEK 已销毁(密钥销毁式删除,不可逆)")

// Provider 是 KEK provider 抽象:包/解 DEK,与 KMS/HSM 解耦。dev 用内存 master key;生产用 KMS/HSM(R7)。
// Name/ID 用作 wrapped_dek 的 kek_id,供未来 KEK 轮换时解包路由(同 wrapped 用对应 KEK 解)。
type Provider interface {
	// Wrap 用本 Provider 当前 KEK 包裹 plaintextDEK,返回 wrapped(可入库)。
	Wrap(plaintextDEK []byte) (wrapped []byte, err error)
	// Unwrap 反包,要求 wrapped 是本 Provider(或匹配 kekID)产出。
	Unwrap(wrapped []byte) (plaintextDEK []byte, err error)
	// KEKID 是 Provider 的 KEK 标识(dev="dev-mem";KMS="<kms-key-arn>")。落库供未来轮换路由。
	KEKID() string
}

// Service 是 secret 模块对外接口(管租户 DEK 生命周期)。
type Service interface {
	// CreateTenantKey 为租户生成 DEK + Wrap + 落库。已有 → ErrAlreadyExists(不覆盖,防意外重生)。
	// 用于"在租户 Create 同事务内"的场景:见 CreateInTx。
	CreateTenantKey(ctx context.Context, tenantID string) error
	// CreateInTx 在调用方提供的 Queries(同事务)内创建 DEK,使"建租户+建密钥"原子(tenant.Create 调用此)。
	CreateInTx(ctx context.Context, q data.Queries, tenantID string) error
	// GetDEK 取明文 DEK(只在内存,**勿持久化/记日志**)。已销毁 → ErrDestroyed;未创建 → ErrNotFound。
	GetDEK(ctx context.Context, tenantID string) ([]byte, error)
	// DestroyTenantKey 销毁 DEK:wrapped_dek→NULL + destroyed_at=now()。**不可逆**;幂等(已销毁仍返 nil)。
	DestroyTenantKey(ctx context.Context, tenantID string) error
	// IsDestroyed 查租户 DEK 是否已销毁(true=destroyed_at 非空)。
	IsDestroyed(ctx context.Context, tenantID string) (bool, error)
	// Encrypt 用租户 DEK 加密明文(Slice36 首个加密消费者:idp.client_secret)。
	// 输出:nonce(12B) || ciphertext+tag(16B);**销毁的 DEK 即不可加密**(ErrDestroyed)。
	// 调用方:把密文落库即可,无需自己管 DEK/nonce。
	Encrypt(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error)
	// Decrypt 反过来:用租户 DEK 解上述格式密文。DEK 已销毁 → ErrDestroyed(数据等效不可恢复)。
	// 篡改 → AEAD 认证失败错误。
	Decrypt(ctx context.Context, tenantID string, ciphertext []byte) ([]byte, error)
}

type service struct {
	store    data.Store
	provider Provider
	alg      string // DEK 算法(当前固定 ChaCha20-Poly1305,crypto-agility 留 alg 字段供未来扩)
}

// NewService 构造 secret 服务。alg 当前固定 ChaCha20-Poly1305(32B),未来 SM4 等由 Provider 与本层 alg 协同。
func NewService(store data.Store, provider Provider) Service {
	return &service{store: store, provider: provider, alg: AlgChaCha20Poly1305}
}

// dekLen 是 DEK 字节长度(随 alg)。
func (s *service) dekLen() (int, error) {
	return dptunnel.KeyLen(s.alg) // ChaCha20=32B / SM4-GCM=16B
}

// CreateInTx 在调用方事务内插 tenant_keys 行(生成 DEK + Wrap)。租户 Create 应在同 InTx 内调本方法。
// **重要:不开自有事务**——使外层 InTx 失败回滚时密钥行也回滚,保证原子。
func (s *service) CreateInTx(ctx context.Context, q data.Queries, tenantID string) error {
	if tenantID == "" {
		return errors.New("secret.CreateInTx: tenant_id 必填")
	}
	n, err := s.dekLen()
	if err != nil {
		return fmt.Errorf("secret.CreateInTx: %w", err)
	}
	dek := make([]byte, n)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("secret.CreateInTx: 生成 DEK: %w", err)
	}
	// **defer 紧跟分配**(reviewer Slice34 B5):所有后续返回路径(含 Wrap 失败)都尽力 zero,
	// 不仅 happy path。Go 不强保证零化(逃逸/复制),只是把"短窗口"做到所有路径一致。
	defer zeroize(dek)
	wrapped, err := s.provider.Wrap(dek)
	if err != nil {
		return fmt.Errorf("secret.CreateInTx: Wrap: %w", err)
	}

	_, err = q.Exec(ctx,
		`INSERT INTO tenant_keys (tenant_id, alg, kek_id, wrapped_dek) VALUES ($1,$2,$3,$4)
		 ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID, s.alg, s.provider.KEKID(), wrapped)
	if err != nil {
		return fmt.Errorf("secret.CreateInTx insert: %w", err)
	}
	// 注:ON CONFLICT DO NOTHING 把 CreateInTx 做成幂等;若调用方需感知"已存在",用 CreateTenantKey(下方)。
	return nil
}

// CreateTenantKey 独立事务版:已有则 ErrAlreadyExists(显式拒,防意外重生 DEK)。
func (s *service) CreateTenantKey(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("secret.CreateTenantKey: tenant_id 必填")
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		// 先看是否已存在(任意状态,destroyed 也算"存在")
		var exists bool
		if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_keys WHERE tenant_id=$1)`, tenantID).Scan(&exists); err != nil {
			return fmt.Errorf("secret.CreateTenantKey check: %w", err)
		}
		if exists {
			return ErrAlreadyExists
		}
		return s.CreateInTx(ctx, q, tenantID)
	})
}

// GetDEK 取明文 DEK。**调用方用完应清零(crypto/subtle 或手工 for i:=range; b[i]=0)、勿持久化、勿记日志、勿存进长寿命字段**——
// 这是裸 []byte 返回 API 的所有权约定(后续刀可改为 Use(func([]byte))-with-zeroize 闭包形态做成不变量,B6)。
// 销毁后或未创建 → 区分返 ErrDestroyed / ErrNotFound;DB CHECK 保 wrapped_dek 与 destroyed_at 二元状态一致(0016)。
func (s *service) GetDEK(ctx context.Context, tenantID string) ([]byte, error) {
	if tenantID == "" {
		return nil, errors.New("secret.GetDEK: tenant_id 必填")
	}
	var wrapped []byte
	var destroyed bool
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`SELECT wrapped_dek, destroyed_at IS NOT NULL FROM tenant_keys WHERE tenant_id=$1`,
			tenantID)
		if scanErr := row.Scan(&wrapped, &destroyed); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("secret.GetDEK scan: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if destroyed { // DB CHECK 不变量:destroyed=true ↔ wrapped_dek IS NULL,故 destroyed 单列足以判定
		return nil, ErrDestroyed
	}
	dek, err := s.provider.Unwrap(wrapped)
	if err != nil {
		return nil, fmt.Errorf("secret.GetDEK Unwrap: %w", err)
	}
	return dek, nil
}

// DestroyTenantKey 销毁 DEK:UPDATE wrapped_dek=NULL + destroyed_at=now() WHERE tenant_id=$1。
// 幂等:已销毁仍返 nil(再次调用不改 destroyed_at,SQL 用 COALESCE 保留最早销毁时刻)。
// 不存在 → ErrNotFound(未创建过)。
func (s *service) DestroyTenantKey(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("secret.DestroyTenantKey: tenant_id 必填")
	}
	return s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		ct, err := q.Exec(ctx,
			`UPDATE tenant_keys
			   SET wrapped_dek = NULL,
			       destroyed_at = COALESCE(destroyed_at, now())
			 WHERE tenant_id = $1`,
			tenantID)
		if err != nil {
			return fmt.Errorf("secret.DestroyTenantKey: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// IsDestroyed 查询销毁状态(destroyed_at 非空 = 已销毁)。
func (s *service) IsDestroyed(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		return false, errors.New("secret.IsDestroyed: tenant_id 必填")
	}
	var destroyed bool
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx, `SELECT destroyed_at IS NOT NULL FROM tenant_keys WHERE tenant_id=$1`, tenantID)
		if scanErr := row.Scan(&destroyed); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("secret.IsDestroyed scan: %w", scanErr)
		}
		return nil
	})
	return destroyed, err
}

// dekAEAD 用明文 DEK 构造 ChaCha20-Poly1305 AEAD(本刀固定 alg;crypto-agility 留 alg 字段供未来扩 SM4)。
func dekAEAD(dek []byte) (cipher.AEAD, error) {
	a, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, fmt.Errorf("secret: 构造 AEAD: %w", err)
	}
	return a, nil
}

// Encrypt 用租户 DEK 加密;输出 nonce(12B)||ct+tag(16B)。GetDEK 已 cover ErrDestroyed/ErrNotFound。
func (s *service) Encrypt(ctx context.Context, tenantID string, plaintext []byte) ([]byte, error) {
	dek, err := s.GetDEK(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer zeroize(dek)
	aead, err := dekAEAD(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secret.Encrypt: 生成 nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt 反 Encrypt。DEK 已销毁 → ErrDestroyed(数据等效不可恢复,印证 Slice35 sweep 真效果)。
func (s *service) Decrypt(ctx context.Context, tenantID string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < chacha20poly1305.NonceSize+16 {
		return nil, fmt.Errorf("secret.Decrypt: 密文过短(%d)", len(ciphertext))
	}
	dek, err := s.GetDEK(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer zeroize(dek)
	aead, err := dekAEAD(dek)
	if err != nil {
		return nil, err
	}
	nonce, ct := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("secret.Decrypt: AEAD: %w", err)
	}
	return plain, nil
}

// zeroize 把 b 字节清零(尽力而为;Go 无强保证不被编译器/GC 复制,生产宜用 mlock+特定库)。
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
