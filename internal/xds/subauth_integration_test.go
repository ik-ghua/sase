package xds

// Slice61 订阅授权放行 + 驱逐(真 PG)。承接 subauth_test.go 的拒绝路径纯测,这里验需要 DB 的两条:
// ① role:device 订**自身**租户放行 + 缓存填充(loadRevocations 经 InTxRO 读 DB);
// ② 关流 → 引用计数归零 → 驱逐缓存(降量,xDS server L2 §3.4)。
// 需 SASE_DB_RW_DSN + SASE_DB_RO_DSN;前置 migrations(revocations 表)。

import (
	"context"
	"testing"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xdspb "github.com/ikuai8/sase/api/proto/sase/xds/v1"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
)

func TestSubscriptionAllowAndEvict(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN/RO_DSN,跳过订阅授权放行/驱逐测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	srv := NewServer(ctx, store)
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	tidA := uuid.NewString()
	devCSR, _, _ := devpki.GenerateCSR("cpe-a")
	devPEM, err := ca.SignCSR(devCSR, tidA, "cpe-a")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	const sid = int64(101)
	if err := srv.onDeltaStreamOpen(certCtx(t, devPEM), sid, ""); err != nil {
		t.Fatalf("onDeltaStreamOpen: %v", err)
	}

	nameA := xdspb.ResourceName(tidA)

	// ① device-A 订自身租户 A → 放行 + 填充缓存(loadRevocations 即使空清单也 UpdateResource)
	if err := srv.onDeltaRequest(sid, subReq(revTypeURL, tidA)); err != nil {
		t.Fatalf("device-A 订自身租户不应拒,得 %v", err)
	}
	if _, exists := srv.revCache.GetResources()[nameA]; !exists {
		t.Fatalf("订自身租户后应填充 A 缓存")
	}
	if got := tenantRef(srv, tidA); got != 1 {
		t.Fatalf("tidA 活跃订阅引用应 1,得 %d", got)
	}

	// ② 关流 → 引用归零 → 驱逐 A 缓存 + 从对账集移除
	srv.onDeltaStreamClosed(sid, nil)
	if _, exists := srv.revCache.GetResources()[nameA]; exists {
		t.Fatalf("关流后应驱逐 A 缓存(无活跃订阅)")
	}
	if got := tenantRef(srv, tidA); got != 0 {
		t.Fatalf("关流后 tidA 引用应 0,得 %d", got)
	}
}

// 具名订阅后:同 typeURL 空请求 = ACK 放行;**未具名的另一 typeURL 空请求 = 拒**(评审 H1 cross-typeURL wildcard)。
func TestSubscriptionACKvsCrossTypeWildcard(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN/RO_DSN,跳过 ACK/cross-type wildcard 测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	srv := NewServer(ctx, store)
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	tidA := uuid.NewString()
	devCSR, _, _ := devpki.GenerateCSR("cpe-a")
	devPEM, err := ca.SignCSR(devCSR, tidA, "cpe-a")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	const sid = int64(303)
	if err := srv.onDeltaStreamOpen(certCtx(t, devPEM), sid, ""); err != nil {
		t.Fatalf("onDeltaStreamOpen: %v", err)
	}

	// 具名订阅自身租户的 revTypeURL → 放行(填充缓存 + 标记 revTypeURL 已具名)
	if err := srv.onDeltaRequest(sid, subReq(revTypeURL, tidA)); err != nil {
		t.Fatalf("device-A 具名订阅自身不应拒,得 %v", err)
	}
	// 同 typeURL 空请求 = ACK → 放行
	ack := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: revTypeURL}
	if err := srv.onDeltaRequest(sid, ack); err != nil {
		t.Fatalf("已具名 revTypeURL 后的空 ACK 应放行,得 %v", err)
	}
	// **未具名的另一 typeURL(policyTypeURL)空请求 = cross-type wildcard → 拒**
	crossWildcard := &discoveryv3.DeltaDiscoveryRequest{TypeUrl: policyTypeURL}
	if err := srv.onDeltaRequest(sid, crossWildcard); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("未具名 policyTypeURL 的空请求(cross-type wildcard)应 PermissionDenied,得 %v", err)
	}
}

// role:pop(无租户绑定)订任意租户放行(受信多租户基础设施)。
func TestSubscriptionPoPAllowsAnyTenant(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN/RO_DSN,跳过 PoP 订阅测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	srv := NewServer(ctx, store)
	ca, err := devpki.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	popCSR, _, _ := devpki.GenerateCSR("pop-1")
	popPEM, err := ca.SignPoP(popCSR, "pop-1")
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	const sid = int64(202)
	if err := srv.onDeltaStreamOpen(certCtx(t, popPEM), sid, ""); err != nil {
		t.Fatalf("onDeltaStreamOpen: %v", err)
	}

	tidX := uuid.NewString() // 与 PoP 证书无绑定关系的任意租户
	if err := srv.onDeltaRequest(sid, subReq(revTypeURL, tidX)); err != nil {
		t.Fatalf("role:pop 订任意租户不应拒,得 %v", err)
	}
	if _, exists := srv.revCache.GetResources()[xdspb.ResourceName(tidX)]; !exists {
		t.Fatalf("role:pop 订阅后应填充缓存")
	}
}
