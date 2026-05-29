package xds

// subauth:Delta 订阅的多租户授权(控制面隔离不变量,xDS server L2 §3.8 + L1 3.12 限爆炸半径)。
//
// 缺口(本刀前):onDeltaRequest 对订阅不做任何租户校验——mTLS 只认"是合法节点",
// 但订阅哪个租户的策略/撤销/SWG/FW/DLP/站点拓扑无人把关。一个持租户绑定设备证书(ZTP role:device)
// 的客户边缘可订阅**任意他租户**资源,直接拿到其全部数据面配置(跨租户泄漏)。
//
// 修复:开流时(onDeltaStreamOpen,go-control-plane 保证每流一次且带 ctx)从已验证 mTLS 叶证书
// 提取 (role, certTenant) 按 streamID 登记;每次订阅请求复查 authorizeSubscription。

import (
	"context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/ikuai8/sase/internal/devpki"
)

// streamAuth 是一条 Delta 流的身份与订阅账本:开流时从证书提取 role/certTenant,
// 订阅授权通过的租户记入 tenants(关流时按此退订计数)。go-control-plane 串行处理单流请求,
// role/certTenant/hasCert 仅在开流时写一次、之后只读;tenants 集与 Server.tenantRefs 同在 refMu 下读写。
type streamAuth struct {
	role       string          // devpki.RolePoP / RoleDevice / ""(role-less 或无证书)
	certTenant string          // role:device 证书绑定的租户(Org);role:pop / role-less 为空
	hasCert    bool            // 是否取到已验证 mTLS 叶证书
	tenants    map[string]bool // 本流已授权订阅的租户集(退订计数用)
	namedTypes map[string]bool // 本流已**具名**订阅过的 type URL 集——防 wildcard 旁路:
	// wildcard 由 go-control-plane 按「(流,typeURL) 首请求 ResourceNamesSubscribe 为空」判定,
	// 故须按 typeURL(非按流)记具名态,否则一条流先具名订阅 A 类、再空订阅 B 类会让 B 类退化为 wildcard。
}

// authorizeSubscription 判定持某证书(role + certTenant)的流可否订阅 subTenant 的资源(纯函数,可测)。
// 信任模型(对齐 W9 证书租户绑定 + W11 角色门控,见 docs/sase-l2-cp-xds-server.md §3.8):
//   - role:pop —— 无租户绑定 = 多租户共享基础设施,受信代任意租户(pop-agent 服务其归属租户集)
//     → 放行任意 subTenant。(per-PoP 租户分配表当前未建模,故 PoP 暂不细分;见 topGaps 未来项。)
//   - role:device —— 绑定单租户 = 客户边缘(CPE 订 SiteConfig)→ 仅放行 certTenant==subTenant。
//     **核心跨租户泄漏修复:tenant-A 设备证书订 tenant-B 资源被拒(L1 3.12 限爆炸半径)。**
//   - role-less / 无证书 —— strict=true(SASE_XDS_REQUIRE_CERT_SCOPE=1,生产)→ 拒;
//     strict=false(dev,pop-agent 可退回共享 client.crt)→ 放行(向后兼容,同 W9 SASE_REQUIRE_CERT_TENANT 形态)。
//
// 注意:role:device 跨租户拒在**两种模式都生效**(不靠 strict),因它是确定无误的越权;
// strict 只决定 role-less/无证书的宽严(dev 兼容 vs 生产硬化)。
func authorizeSubscription(role string, hasCert bool, certTenant, subTenant string, strict bool) (bool, string) {
	switch role {
	case devpki.RolePoP:
		return true, "role:pop 受信多租户基础设施"
	case devpki.RoleDevice:
		if certTenant != "" && certTenant == subTenant {
			return true, "role:device 订阅自身租户"
		}
		return false, "role:device 证书租户与订阅租户不符(跨租户越权)"
	default: // role-less 或无证书
		if strict {
			return false, "无角色标记证书在严格模式被拒(SASE_XDS_REQUIRE_CERT_SCOPE)"
		}
		_ = hasCert // 宽松模式下不区分有无证书,统一放行(dev 兼容)
		return true, "宽松模式放行无角色标记证书(dev)"
	}
}

// peerCertIdentity 从 gRPC 对端已验证 mTLS 叶证书提取 (role, certTenant, hasCert)。
// 对齐 internal/telemetry/ingest.go 的 peerRole(W11);mTLS 由 devpki.LoadServerTLS 的
// RequireAndVerifyClientCert 保证叶证书已通过 CA 校验(握手不过则到不了这里)。
func peerCertIdentity(ctx context.Context) (role, certTenant string, hasCert bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", "", false
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return "", "", false
	}
	leaf := ti.State.PeerCertificates[0]
	role, _ = devpki.RoleFromCert(leaf)
	certTenant, _ = devpki.TenantFromCert(leaf)
	return role, certTenant, true
}
