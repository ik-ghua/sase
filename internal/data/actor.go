package data

import "context"

// Actor 是审计归因主体(谁在操作)的**中性载体**:data 层不依赖 authz/业务模块,
// 由上层(authz 中间件 → audit.ActorMiddleware)注入 ctx,runTx 读出后设 per-tx GUC
// (app.current_actor[_role]),供审计触发器 audit_row() 在业务事务内归因(审计事务化 L2 4.2,方案 ③)。
// 无注入(内部任务/非 HTTP 路径)→ GUC 不设 → 触发器记 actor 空、role='system'。
type Actor struct {
	Subject string
	Role    string
}

type actorCtxKey struct{}

// WithActor 把审计主体放入 ctx(上层中间件调用)。空 Subject 视为无主体(不污染)。
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorCtxKey{}, a)
}

// actorFromContext 取审计主体(runTx 内部用)。
func actorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorCtxKey{}).(Actor)
	return a, ok && a.Subject != ""
}
