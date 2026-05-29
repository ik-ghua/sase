// Package control 是控制面的终端实时控制通道(Agent↔控制面持久双向流)。
//
// ZTNA 硬化 L2 3.4 层②"端提速":控制面经长连向 Agent 下推撤销/重认证/重采姿态指令,使端侧秒级反应;
// 同时承接 Agent 的姿态上报,驱动持续自适应(姿态异常 → 触发撤销)。
// 权威仍在 PoP(吊销表 + 短 TTL,层①③);本通道 best-effort:连接断/消息丢不影响安全,PoP 兜底。
package control

import (
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	controlpb "github.com/ikuai8/sase/api/proto/sase/control/v1"
	"github.com/ikuai8/sase/internal/cred"
)

// Hub 维护各租户已连接 Agent,下推指令并接收姿态上报。
type Hub struct {
	controlpb.UnimplementedAgentControlServer
	verifier *cred.Verifier

	mu        sync.Mutex
	conns     map[string]map[*agentConn]bool // tenantID → 连接集
	onPosture func(tenantID, subject, jti, posture string)
}

type agentConn struct {
	tenantID, subject, jti string
	send                   chan *controlpb.ControlCommand // 缓冲;满则丢(best-effort)
}

// NewHub 构造 Hub。verifier 用于校验 Agent hello 携带的会话凭证(确定身份)。
func NewHub(verifier *cred.Verifier) *Hub {
	return &Hub{verifier: verifier, conns: map[string]map[*agentConn]bool{}}
}

// SetPostureHandler 设姿态上报回调(持续自适应:如姿态非合规 → 撤销)。后置注入以解 hub↔identity 构造环。
func (h *Hub) SetPostureHandler(fn func(tenantID, subject, jti, posture string)) {
	h.mu.Lock()
	h.onPosture = fn
	h.mu.Unlock()
}

// Channel 是 gRPC 双向流:首条 hello 验凭证注册身份,之后下推指令 / 收姿态上报。
func (h *Hub) Channel(stream grpc.BidiStreamingServer[controlpb.AgentEvent, controlpb.ControlCommand]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetKind() != "hello" {
		return status.Errorf(codes.InvalidArgument, "首条必须是 hello")
	}
	claims, err := h.verifier.Verify(first.GetToken(), time.Now())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "hello 凭证无效: %v", err)
	}
	ac := &agentConn{
		tenantID: claims.TenantID, subject: claims.Subject, jti: claims.JTI,
		send: make(chan *controlpb.ControlCommand, 8),
	}
	h.register(ac)
	defer h.unregister(ac)
	log.Printf("[control] Agent 接入 tenant=%s sub=%s jti=%s", ac.tenantID, ac.subject, ac.jti)

	ctx := stream.Context()
	// 写循环:下推指令(单独 goroutine,与下方 Recv 并发——gRPC 允许各一个 Send/Recv)
	go func() {
		for {
			select {
			case cmd := <-ac.send:
				if err := stream.Send(cmd); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// 读循环:姿态上报 / ACK
	for {
		ev, err := stream.Recv()
		if err != nil {
			return nil // Agent 断开
		}
		if ev.GetKind() == "posture" {
			h.mu.Lock()
			fn := h.onPosture
			h.mu.Unlock()
			if fn != nil {
				// 异步:handler 可能含撤销写库,不阻塞本 Agent 的 Recv 处理(姿态低频,goroutine 开销可忽略)
				go fn(ac.tenantID, ac.subject, ac.jti, ev.GetPosture())
			}
		}
	}
}

// NotifyRevoked 实现 identity.RevocationNotifier:撤销发生时下推 revoke(端提速,best-effort)。
func (h *Hub) NotifyRevoked(tenantID, jti string) {
	h.broadcast(tenantID, &controlpb.ControlCommand{Kind: "revoke", Jti: jti, Reason: "revoked"})
}

// PushRecheckPosture 下推重采姿态指令(持续自适应:主动触发端侧重新上报)。
func (h *Hub) PushRecheckPosture(tenantID string) {
	h.broadcast(tenantID, &controlpb.ControlCommand{Kind: "recheck_posture"})
}

// ConnCount 返回某租户当前连接数(测试/可观测用)。
func (h *Hub) ConnCount(tenantID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns[tenantID])
}

func (h *Hub) broadcast(tenantID string, cmd *controlpb.ControlCommand) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ac := range h.conns[tenantID] {
		select {
		case ac.send <- cmd:
		default: // 缓冲满 → 丢弃(best-effort;PoP 吊销表+短 TTL 兜底)
		}
	}
}

func (h *Hub) register(ac *agentConn) {
	h.mu.Lock()
	if h.conns[ac.tenantID] == nil {
		h.conns[ac.tenantID] = map[*agentConn]bool{}
	}
	h.conns[ac.tenantID][ac] = true
	h.mu.Unlock()
}

func (h *Hub) unregister(ac *agentConn) {
	h.mu.Lock()
	if set := h.conns[ac.tenantID]; set != nil {
		delete(set, ac)
		if len(set) == 0 {
			delete(h.conns, ac.tenantID)
		}
	}
	h.mu.Unlock()
}
