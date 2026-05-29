// Package idp 是 IdP 配置模块(L1 3.4:OIDC/SAML + 企微/钉钉/飞书三家国产 IdP)。
// 本模块**持久化 IdP 配置**,client_secret 经 secret 模块用租户 DEK 加密落库——是 **Slice34/35 secret 模块的首个真加密消费者**:
// 租户硬删 sweep 销毁 DEK 后,本表所有 encrypted_client_secret 等效不可恢复(L1 3.16 密钥销毁式删除工程效果)。
//
// **本刀范围:CRUD 持久化**。真实 OIDC/SAML adapter(跳转/回调/换 IdP 令牌)= 后续刀,届时使用 GetClientSecret 取解密 secret。
package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/secret"
)

// ErrNotFound 表示 IdP 配置不存在(在该租户 RLS 上下文下)。
var ErrNotFound = errors.New("idp: 配置不存在")

// ErrInvalidPatch 表示请求字段非法(name/endpoint/client_id/client_secret 空、kind 空)。
var ErrInvalidPatch = errors.New("idp: 请求字段非法")

// Config 是 IdP 配置的对外模型。**有意不含 ClientSecret 字段**(防意外序列化到 JSON 响应/日志);
// 取解密 client_secret 走 `GetClientSecret`(adapter 后续刀用)。
type Config struct {
	ID        string         `json:"id"`
	TenantID  string         `json:"tenant_id"`
	Name      string         `json:"name"`
	Kind      string         `json:"kind"` // oidc/wecom/dingtalk/feishu(Slice37b-1 起统一 validKinds)
	Endpoint  string         `json:"endpoint"`
	ClientID  string         `json:"client_id"`
	Status    string         `json:"status"` // active / disabled
	Extra     map[string]any `json:"extra,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// CreateRequest 是创建 IdP 配置的入参;ClientSecret **明文**,服务端加密入库后丢弃。
type CreateRequest struct {
	Name         string         `json:"name"`
	Kind         string         `json:"kind"`
	Endpoint     string         `json:"endpoint"`
	ClientID     string         `json:"client_id"`
	ClientSecret string         `json:"client_secret"`
	Extra        map[string]any `json:"extra,omitempty"`
}

// Patch 是部分更新(PATCH 语义:nil=不改;ClientSecret 非 nil → 重新加密落库)。
type Patch struct {
	Name         *string         `json:"name,omitempty"`
	Endpoint     *string         `json:"endpoint,omitempty"`
	ClientID     *string         `json:"client_id,omitempty"`
	ClientSecret *string         `json:"client_secret,omitempty"`
	Status       *string         `json:"status,omitempty"`
	Extra        *map[string]any `json:"extra,omitempty"`
}

// Service 是 idp 模块对外接口。
type Service interface {
	Create(ctx context.Context, tenantID string, req CreateRequest) (*Config, error)
	Get(ctx context.Context, tenantID, id string) (*Config, error)
	List(ctx context.Context, tenantID string) ([]Config, error)
	Update(ctx context.Context, tenantID, id string, patch Patch) (*Config, error)
	Delete(ctx context.Context, tenantID, id string) error
	// GetClientSecret 取解密 client_secret(adapter 用,**绝勿记日志/返 API**)。DEK 已销毁 → secret.ErrDestroyed。
	GetClientSecret(ctx context.Context, tenantID, id string) ([]byte, error)
}

type service struct {
	store      data.Store
	sec        secret.Service // 经它加密/解密 client_secret(secret.Encrypt/Decrypt)
	deleteHook DeleteHook     // 可选(Slice37c):Delete 成功后回调,供 oidc 包淘汰 adapter token cache
}

// DeleteHook 在 IdP 配置被删除后(事务提交)被调,供下游(如 oidc adapter token cache)联动清理。
// 参数复用 Config 字段供 hook 自由派发(按 kind=wecom/feishu 选择淘汰目标)。失败仅 log,不阻塞 Delete。
type DeleteHook func(tenantID, idpID, kind, clientID string)

// Option 配置 idp 服务。
type Option func(*service)

// WithDeleteHook 注入 Delete 后回调(Slice37c B4-B5 修复:Delete IdP 时联动淘汰 adapter token cache)。
func WithDeleteHook(h DeleteHook) Option { return func(s *service) { s.deleteHook = h } }

// NewService 构造 idp 服务。secret 必须注入(IdP 配置依赖 DEK 加密;无 DEK→拒)。
func NewService(store data.Store, sec secret.Service, opts ...Option) Service {
	s := &service{store: store, sec: sec}
	for _, o := range opts {
		o(s)
	}
	return s
}

// idpColumns 是 Config 列序的单一来源(与 scanConfig 同源)。
const idpColumns = "id, tenant_id, name, kind, endpoint, client_id, status, extra, created_at, updated_at"

// scanConfig 把 idpColumns 顺序的一行扫进 c(extra 为 jsonb → 经 []byte + json.Unmarshal)。
func scanConfig(row pgx.Row, c *Config) error {
	var extraRaw []byte
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Kind, &c.Endpoint, &c.ClientID, &c.Status, &extraRaw, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return err
	}
	if len(extraRaw) > 0 {
		if err := json.Unmarshal(extraRaw, &c.Extra); err != nil {
			return fmt.Errorf("idp.scanConfig: extra jsonb: %w", err)
		}
	}
	return nil
}

// validKinds 与 OpenAPI enum 同源(api/openapi/admin.yaml IdPConfig.kind / oidc.factory.Kind*)。
// Slice37b-1:oidc + wecom 已实现;dingtalk/feishu 允许配置但 oidc.DispatchFactory 会拒(留客户端"先配置后实现"的弹性)。
var validKinds = map[string]bool{"oidc": true, "wecom": true, "dingtalk": true, "feishu": true}

func validateCreate(r CreateRequest) error {
	if r.Name == "" || r.Kind == "" || r.Endpoint == "" || r.ClientID == "" || r.ClientSecret == "" {
		return fmt.Errorf("%w: name/kind/endpoint/client_id/client_secret 均必填", ErrInvalidPatch)
	}
	if !validKinds[r.Kind] {
		return fmt.Errorf("%w: kind 须为 oidc|wecom|dingtalk|feishu,得 %q", ErrInvalidPatch, r.Kind)
	}
	return nil
}

func (s *service) Create(ctx context.Context, tenantID string, req CreateRequest) (*Config, error) {
	if tenantID == "" {
		return nil, errors.New("idp.Create: tenant_id 必填")
	}
	if err := validateCreate(req); err != nil {
		return nil, err
	}
	// 加密 client_secret(secret.GetDEK 已校验 DEK 状态,销毁/不存在均拒)。
	ct, err := s.sec.Encrypt(ctx, tenantID, []byte(req.ClientSecret))
	if err != nil {
		return nil, fmt.Errorf("idp.Create: 加密 client_secret: %w", err)
	}
	id := uuid.NewString()
	extraJSON := []byte(`{}`)
	if req.Extra != nil {
		extraJSON, _ = json.Marshal(req.Extra)
	}
	var c Config
	err = s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx,
			`INSERT INTO idp_configs (id, tenant_id, name, kind, endpoint, client_id, encrypted_client_secret, status, extra)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8::jsonb)
			 RETURNING `+idpColumns,
			id, tenantID, req.Name, req.Kind, req.Endpoint, req.ClientID, ct, extraJSON)
		return scanConfig(row, &c)
	})
	if err != nil {
		return nil, fmt.Errorf("idp.Create: %w", err)
	}
	return &c, nil
}

func (s *service) Get(ctx context.Context, tenantID, id string) (*Config, error) {
	if tenantID == "" || id == "" {
		return nil, errors.New("idp.Get: tenant_id/id 必填")
	}
	var c Config
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx, `SELECT `+idpColumns+` FROM idp_configs WHERE id=$1`, id)
		if e := scanConfig(row, &c); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("idp.Get: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *service) List(ctx context.Context, tenantID string) ([]Config, error) {
	if tenantID == "" {
		return nil, errors.New("idp.List: tenant_id 必填")
	}
	var out []Config
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		rows, qerr := q.Query(ctx, `SELECT `+idpColumns+` FROM idp_configs ORDER BY created_at`)
		if qerr != nil {
			return fmt.Errorf("idp.List query: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			var c Config
			if e := scanConfig(rows, &c); e != nil {
				return fmt.Errorf("idp.List scan: %w", e)
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Config{}
	}
	return out, nil
}

func (s *service) Update(ctx context.Context, tenantID, id string, patch Patch) (*Config, error) {
	if tenantID == "" || id == "" {
		return nil, errors.New("idp.Update: tenant_id/id 必填")
	}
	// 字段校验:非 nil 即不允许空
	check := func(label string, v *string) error {
		if v != nil && *v == "" {
			return fmt.Errorf("%w: %s 不可为空", ErrInvalidPatch, label)
		}
		return nil
	}
	for _, e := range []error{check("name", patch.Name), check("endpoint", patch.Endpoint), check("client_id", patch.ClientID), check("client_secret", patch.ClientSecret), check("status", patch.Status)} {
		if e != nil {
			return nil, e
		}
	}
	// status 白名单(与 OpenAPI enum 同源)
	if patch.Status != nil && *patch.Status != "active" && *patch.Status != "disabled" {
		return nil, fmt.Errorf("%w: status 须为 active|disabled,得 %q", ErrInvalidPatch, *patch.Status)
	}
	// 若改 client_secret → 先加密(可能因 DEK 销毁失败)
	var newSecretCt []byte
	if patch.ClientSecret != nil {
		ct, err := s.sec.Encrypt(ctx, tenantID, []byte(*patch.ClientSecret))
		if err != nil {
			return nil, fmt.Errorf("idp.Update: 加密 client_secret: %w", err)
		}
		newSecretCt = ct
	}
	// 动态 SET
	var sets []string
	var args []any
	add := func(col string, val any) {
		args = append(args, val)
		sets = append(sets, fmt.Sprintf("%s=$%d", col, len(args)))
	}
	if patch.Name != nil {
		add("name", *patch.Name)
	}
	if patch.Endpoint != nil {
		add("endpoint", *patch.Endpoint)
	}
	if patch.ClientID != nil {
		add("client_id", *patch.ClientID)
	}
	if newSecretCt != nil {
		add("encrypted_client_secret", newSecretCt)
	}
	if patch.Status != nil {
		add("status", *patch.Status)
	}
	if patch.Extra != nil {
		extraJSON, _ := json.Marshal(*patch.Extra)
		args = append(args, extraJSON)
		sets = append(sets, fmt.Sprintf("extra=$%d::jsonb", len(args)))
	}
	if len(sets) == 0 {
		return nil, fmt.Errorf("%w: 无可更新字段", ErrInvalidPatch)
	}
	sets = append(sets, "updated_at=now()")
	args = append(args, id)
	query := `UPDATE idp_configs SET ` + join(sets) +
		fmt.Sprintf(" WHERE id=$%d RETURNING ", len(args)) + idpColumns

	var c Config
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx, query, args...)
		if e := scanConfig(row, &c); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("idp.Update: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *service) Delete(ctx context.Context, tenantID, id string) error {
	if tenantID == "" || id == "" {
		return errors.New("idp.Delete: tenant_id/id 必填")
	}
	// Slice37c:删除前先取 kind/client_id(供 deleteHook 联动淘汰 adapter cache);RETURNING 一并完成。
	var kind, clientID string
	err := s.store.InTx(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx, `DELETE FROM idp_configs WHERE id=$1 RETURNING kind, client_id`, id)
		if e := row.Scan(&kind, &clientID); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("idp.Delete: %w", e)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 事务已提交后再回调(失败 → 提交完审计 + cache 仍是脏的;hook 自身仅 best-effort,失败 log 不重试)
	if s.deleteHook != nil {
		s.deleteHook(tenantID, id, kind, clientID)
	}
	return nil
}

// GetClientSecret 取解密的 client_secret(adapter 后续刀用)。**绝勿记日志/返 API/落本地变量长期持有**。
// DEK 已销毁 → secret.ErrDestroyed(印证 sweep 真效果)。
func (s *service) GetClientSecret(ctx context.Context, tenantID, id string) ([]byte, error) {
	var ct []byte
	err := s.store.InTxRO(ctx, tenantID, func(q data.Queries) error {
		row := q.QueryRow(ctx, `SELECT encrypted_client_secret FROM idp_configs WHERE id=$1`, id)
		if e := row.Scan(&ct); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("idp.GetClientSecret: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.sec.Decrypt(ctx, tenantID, ct)
}

// join 是 strings.Join 的小替身(避免新增 strings import 影响 lint;实现等价)。
func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
