package httpapi_test

// 测试共享 helper:构造一个 secret.Service(临时 KEK,测试隔离)。Register 现需要 secret.Service,
// 不实际调用 sweep 端点的测试也能复用此 helper,避免每文件重复 boilerplate。

import (
	"context"
	"errors"
	"testing"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/platform"
	"github.com/ikuai8/sase/internal/secret"
	"github.com/ikuai8/sase/internal/tenant"
)

func testSecretSvc(t *testing.T, store data.Store) secret.Service {
	t.Helper()
	p, err := secret.NewDevProvider("") // 临时 KEK(测试隔离;真值无关——本进程内 Wrap/Unwrap 一致即可)
	if err != nil {
		t.Fatalf("testSecretSvc: NewDevProvider: %v", err)
	}
	return secret.NewService(store, p)
}

func testIDPSvc(t *testing.T, store data.Store, sec secret.Service) idp.Service {
	t.Helper()
	return idp.NewService(store, sec)
}

// testSweepDestroyer / testSweepStatusSetter:测试用 sweep 适配器(同 cmd/api-server 内的形态),
// 让 sweep_integration_test 能给 platformSvc 注入 sweep 依赖。
type testSweepDestroyer struct{ s secret.Service }

func (d testSweepDestroyer) DestroyTenantKey(ctx context.Context, tenantID string) error {
	if err := d.s.DestroyTenantKey(ctx, tenantID); err != nil && !errors.Is(err, secret.ErrNotFound) {
		return err
	}
	return nil
}

type testSweepStatusSetter struct{ s tenant.Service }

func (a testSweepStatusSetter) SetStatus(ctx context.Context, tenantID, status string) error {
	_, err := a.s.Update(ctx, tenantID, tenant.Patch{Status: &status})
	return err
}

// testPlatformSvc 构造带 sweep 依赖的 platform.Service,供 sweep_integration_test 用。
func testPlatformSvc(store data.Store, sec secret.Service, ten tenant.Service) platform.Service {
	return platform.NewService(store,
		platform.WithDEKDestroyer(testSweepDestroyer{sec}),
		platform.WithTenantStatusSetter(testSweepStatusSetter{ten}),
	)
}
