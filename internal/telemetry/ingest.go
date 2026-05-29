package telemetry

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	telemetrypb "github.com/ikuai8/sase/api/proto/sase/telemetry/v1"
	"github.com/ikuai8/sase/internal/devpki"
)

// Ingest 是控制面遥测接收端(实现 telemetrypb.TelemetryServer):收 PoP 上报的事件批,派发给各 Sink。
//
// ⚠️ **信任模型(须知,P0 多租户隔离相关)**:本端点信任**PoP 角色**节点上报**任意租户**事件——PoP 是多租户
// 共享基础设施(同时服务多租户),故事件里的 tenant/subject/jti 的权威来自"调用方是受信 PoP",**不能像
// W9/CPE 那样把 tenant 绑到调用方证书**(PoP 非单租户)。当前 mTLS 仅证明"持本 CA 证书",**不区分 PoP 角色
// 与设备角色**——dev 共享证书下,Connector/CPE 也持同证书,理论上可冒充上报伪造事件污染他租户风险/触发撤销。
// **W11 门控已实现**:`NewIngest(requirePoPRole=true)`(api-server `SASE_TELEMETRY_REQUIRE_POP_ROLE=1`)开启后,
// 从对端 mTLS 证书取角色(`devpki.RoleFromCert`),非 PoP 角色拒(fail-closed,与 revtunnel W9 同形态)。
// **生产必开**;开启前提是 **PoP 持 role:pop 证书**(`devpki.SignPoP`/PoP 入网签发)——dev 共享证书无角色故默认关。
type Ingest struct {
	telemetrypb.UnimplementedTelemetryServer
	sinks          []Sink
	requirePoPRole bool // W11:开启则只接受 PoP 角色证书的调用方(fail-closed)。生产必开;dev 默认关。
}

// NewIngest 构造 Ingest。requirePoPRole 开启 W11 角色门控(只收 PoP 角色,见信任模型);sinks 为事件消费者。
func NewIngest(requirePoPRole bool, sinks ...Sink) *Ingest {
	return &Ingest{requirePoPRole: requirePoPRole, sinks: sinks}
}

// authorizeReport 是纯函数门控判定(便于单测):require 开启时,调用方角色须为 PoP,否则拒。
func authorizeReport(require bool, role string, hasRole bool) error {
	if !require {
		return nil
	}
	if !hasRole || role != devpki.RolePoP {
		return status.Error(codes.PermissionDenied, "telemetry: 仅 PoP 角色证书可上报事件(W11)")
	}
	return nil
}

// peerRole 从 gRPC 对端已验证 mTLS 证书取角色。
func peerRole(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return "", false
	}
	return devpki.RoleFromCert(ti.State.PeerCertificates[0])
}

// Report 收事件批,转 Event 并派发给各 Sink。best-effort:坏事件跳过,不让一条坏事件失败整批。
// W11 角色门控:requirePoPRole 开启时,非 PoP 角色调用方直接拒(防设备/边缘冒充上报伪造事件污染他租户风险)。
func (in *Ingest) Report(ctx context.Context, req *telemetrypb.ReportRequest) (*telemetrypb.ReportResponse, error) {
	role, hasRole := peerRole(ctx)
	if err := authorizeReport(in.requirePoPRole, role, hasRole); err != nil {
		return nil, err
	}
	var n int32
	for _, pe := range req.GetEvents() {
		e := Event{
			TenantID: pe.GetTenantId(),
			Subject:  pe.GetSubject(),
			JTI:      pe.GetJti(),
			Kind:     pe.GetKind(),
			Attrs:    pe.GetAttrs(),
			Ts:       unixNano(pe.GetTsUnixNano()),
		}
		for _, s := range in.sinks {
			s.Handle(e)
		}
		n++
	}
	return &telemetrypb.ReportResponse{Accepted: n}, nil
}
