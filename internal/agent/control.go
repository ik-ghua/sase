package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	controlpb "github.com/ikuai8/sase/api/proto/sase/control/v1"
)

// Session 是 Agent 的会话状态:维护与控制面的实时通道,并据下推指令更新本地凭证有效性。
// 端提速(ZTNA 硬化 L2 3.4 层②):收到 revoke 即本地弃用凭证,不必等下次 PoP 请求被拒。
// 注:这是 best-effort 加速;即便本通道失效,PoP 仍按吊销表 + 短 TTL 兜底(权威)。
type Session struct {
	mu      sync.RWMutex
	jti     string
	posture string
	revoked bool
}

// NewSession 构造会话(jti=本凭证标识,posture=当前上报姿态)。
func NewSession(jti, posture string) *Session {
	return &Session{jti: jti, posture: posture}
}

// Revoked 返回本地是否已感知凭证被撤销(收到匹配 revoke 指令)。
func (s *Session) Revoked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revoked
}

// SetPosture 更新本地姿态(下次上报/重采时用)。
func (s *Session) SetPosture(p string) {
	s.mu.Lock()
	s.posture = p
	s.mu.Unlock()
}

func (s *Session) getPosture() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.posture
}

// RunControlChannel 连接控制面实时通道:发 hello(token)+ 初始姿态,处理下推指令,直到 ctx 取消/流断。
// tlsConf 为 mTLS 客户端配置(设备级 transport 认证;hello 内凭证为 app 层身份)。
func (s *Session) RunControlChannel(ctx context.Context, addr string, tlsConf *tls.Config, token string) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	if err != nil {
		return fmt.Errorf("agent: 建控制通道连接: %w", err)
	}
	defer conn.Close()

	stream, err := controlpb.NewAgentControlClient(conn).Channel(ctx)
	if err != nil {
		return fmt.Errorf("agent: 开控制流: %w", err)
	}
	if err := stream.Send(&controlpb.AgentEvent{Kind: "hello", Token: token}); err != nil {
		return fmt.Errorf("agent: 发 hello: %w", err)
	}
	if err := stream.Send(&controlpb.AgentEvent{Kind: "posture", Posture: s.getPosture()}); err != nil {
		return fmt.Errorf("agent: 发初始姿态: %w", err)
	}

	for {
		cmd, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("agent: 收控制指令: %w", err)
		}
		switch cmd.GetKind() {
		case "revoke":
			if cmd.GetJti() == s.jti {
				s.mu.Lock()
				s.revoked = true
				s.mu.Unlock()
				log.Printf("[agent] 收到 revoke,本地弃用凭证 jti=%s reason=%s", s.jti, cmd.GetReason())
			}
		case "recheck_posture":
			if err := stream.Send(&controlpb.AgentEvent{Kind: "posture", Posture: s.getPosture()}); err != nil {
				return fmt.Errorf("agent: 上报姿态: %w", err)
			}
		case "reauth":
			log.Printf("[agent] 收到 reauth(slice:记录;生产应重新走 enroll/令牌交换)")
		}
	}
}
