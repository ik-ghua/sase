package platformaudit_test

// Slice39 平台审计端到端(真实 PG):验证
//   ① Record(source=api)写得进、读得出;
//   ② DB 触发器 platform_audit_row 挂在 pop_nodes 上 → INSERT pop_nodes 后自动落 source=data 一行;
//   ③ **双层一致**:同一次 PoP 注册经 PopRegistry.Create + handler 显式 Record,得到 source=data + source=api 两条;
//   ④ actor GUC 归因(经 data.WithActor)正确入 actor_subject/actor_role;
//   ⑤ List 按 ts DESC + limit 截断。
// 需 SASE_DB_RW_DSN + SASE_DB_PLATFORM_DSN + SASE_DB_PLATFORM_RW_DSN;前置 migrations 0001-0021。

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/platform"
	"github.com/ikuai8/sase/internal/platformaudit"
)

func TestPlatformAuditRecord(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 SASE_DB_RW_DSN + PLATFORM_DSN + PLATFORM_RW_DSN,跳过")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	svc := platformaudit.NewService(store)

	// ① 显式 Record(source=api)
	subject := "test-ops-" + uuid.NewString()[:8]
	if err := svc.Record(ctx, platformaudit.Entry{
		ActorSubject: subject,
		ActorRole:    "platform_admin",
		Action:       "TEST_ACTION",
		Result:       http.StatusOK,
		Detail:       "smoke=ok",
	}); err != nil {
		t.Fatalf("Record api: %v", err)
	}

	// 读出
	all, err := svc.List(ctx, 200)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var sawAPI bool
	for _, e := range all {
		if e.ActorSubject == subject && e.Action == "TEST_ACTION" {
			sawAPI = true
			if e.Source != platformaudit.SourceAPI || e.Result != http.StatusOK || e.Detail != "smoke=ok" || e.ActorRole != "platform_admin" {
				t.Errorf("api 审计字段错: %+v", e)
			}
		}
	}
	if !sawAPI {
		t.Fatal("应能读到刚写的 source=api 审计行")
	}
}

// TestPlatformAuditTrigger:DB 触发器挂在 pop_nodes 上,INSERT pop_nodes 自动落 source=data;
// 且 actor GUC 经 data.WithActor → InPlatformTxRW 注入 → 触发器读出。
func TestPlatformAuditTrigger(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设 SASE_DB_RW_DSN + PLATFORM_DSN + PLATFORM_RW_DSN,跳过")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	reg := platform.NewPopRegistry(store)
	svc := platformaudit.NewService(store)

	actor := "trig-actor-" + uuid.NewString()[:8]
	popName := "trig-pop-" + uuid.NewString()[:8]
	// 经 data.WithActor 注入 actor → InPlatformTxRW 设 GUC → 触发器读
	ctxA := data.WithActor(ctx, data.Actor{Subject: actor, Role: "platform_admin"})
	p, err := reg.Create(ctxA, platform.CreatePopRequest{Name: popName, Region: "cn-test", Endpoint: "x:443"})
	if err != nil {
		t.Fatalf("Create pop: %v", err)
	}

	// 应能查到 source=data 审计行,actor=trig-actor-...,action=INSERT pop_nodes,detail 含本行 id
	all, err := svc.List(ctx, 500)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var sawData bool
	for _, e := range all {
		if e.Source == platformaudit.SourceData && e.Action == "INSERT pop_nodes" && strings.Contains(e.Detail, "id="+p.ID) {
			sawData = true
			if e.ActorSubject != actor {
				t.Errorf("actor_subject 应来自 GUC=%s,得 %s", actor, e.ActorSubject)
			}
			if e.Result != 0 {
				t.Errorf("data 源 result 应为 0 哨兵,得 %d", e.Result)
			}
			if e.ActorRole != "platform_admin" {
				t.Errorf("actor_role 应来自 GUC,得 %s", e.ActorRole)
			}
		}
	}
	if !sawData {
		t.Fatalf("应有 source=data 触发器审计行 pop=%s,得 %d 条 audit", p.ID, len(all))
	}
}

// TestPlatformAuditSystemActor:无 actor GUC(ctx 不带)→ 触发器记 'system' 兜底。
func TestPlatformAuditSystemActor(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok || cfg.PlatformConnString == "" || cfg.PlatformRWConnString == "" {
		t.Skip("未设")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()
	reg := platform.NewPopRegistry(store)
	svc := platformaudit.NewService(store)

	popName := "sys-pop-" + uuid.NewString()[:8]
	// 不带 actor 上下文
	p, err := reg.Create(ctx, platform.CreatePopRequest{Name: popName, Region: "cn-test", Endpoint: "x:443"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// 找本行的触发器审计(detail 含 id=p.ID),actor 应为 'system'
	all, _ := svc.List(ctx, 200)
	for _, e := range all {
		if e.Source == platformaudit.SourceData && strings.Contains(e.Detail, "id="+p.ID) {
			if e.ActorSubject != "system" || e.ActorRole != "system" {
				t.Errorf("无 actor 上下文应记 system/system,得 %s/%s", e.ActorSubject, e.ActorRole)
			}
			return
		}
	}
	t.Fatalf("应有触发器审计行 id=%s,得 %d 条 audit", p.ID, len(all))
}
