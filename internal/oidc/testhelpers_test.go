package oidc

// 测试共享 helper(Slice37b-2:多 IdP 派发测试需要构造 idp.Config 桩)。

import (
	"testing"

	"github.com/ikuai8/sase/internal/idp"
)

// newIdpCfg 构造测试用 idp.Config(用于 DispatchFactory 派发测试)。
func newIdpCfg(t *testing.T, id, kind, endpoint, clientID string) *idp.Config {
	t.Helper()
	return &idp.Config{
		ID:       id,
		TenantID: "t-test",
		Name:     "test-" + kind,
		Kind:     kind,
		Endpoint: endpoint,
		ClientID: clientID,
		Status:   "active",
	}
}
