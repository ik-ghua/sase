package audit_test

// Slice29 审计事务化(方案 A,DB 触发器)集成测试:验证
//   ① 原子性:业务回滚 → 审计回滚(无"变更成功无审计"窗口);业务提交 → 审计随之提交。
//   ② source 两层分工:触发器写 source='data'(数据变更级、result=0、action='TG_OP 表名')。
//   ③ actor 归因:经 data.WithActor 设的 per-tx GUC 进审计行;无主体 → role='system'。
//   ④ CI catalog 门禁:凡含 tenant_id 的业务表(除显式排除)均挂 audit_tr 触发器,防新增表漏挂。
// 需 SASE_DB_RW_DSN/_RO_DSN;未设则 SKIP。前置:migrations 0001-0012。-run TestAuditTrigger。

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/data"
)

// insertUser 在给定 ctx(可带 actor)+ 租户事务内插一行 users;retErr!=nil 则事务回滚。
func insertUser(ctx context.Context, store data.Store, tid, uid string, retErr error) error {
	return store.InTx(ctx, tid, func(q data.Queries) error {
		if _, err := q.Exec(ctx,
			`INSERT INTO users (id, tenant_id, external_id, email, status) VALUES ($1,$2,$3,$4,'active')`,
			uid, tid, "ext-"+uid, uid+"@t.example"); err != nil {
			return err
		}
		return retErr
	})
}

func dataAuditRows(t *testing.T, store data.Store, tid string) []audit.Entry {
	t.Helper()
	svc := audit.NewService(store)
	es, err := svc.ListByTenant(context.Background(), tid, 1000)
	if err != nil {
		t.Fatalf("读审计: %v", err)
	}
	var out []audit.Entry
	for _, e := range es {
		if e.Source == audit.SourceData {
			out = append(out, e)
		}
	}
	return out
}

func TestAuditTriggerAtomicityAndAttribution(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过审计触发器测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	// ① 原子性 —— 回滚:插 user 后返回错误,事务回滚 → 不应有任何审计行。
	tidRB := uuid.NewString()
	if err := insertUser(ctx, store, tidRB, uuid.NewString(), errors.New("force rollback")); err == nil {
		t.Fatal("期望回滚错误")
	}
	if rows := dataAuditRows(t, store, tidRB); len(rows) != 0 {
		t.Fatalf("回滚事务不应留审计(原子性),得 %d 条: %+v", len(rows), rows)
	}

	// ② 原子性 —— 提交 + actor 归因:带 actor 提交 → 恰一条 data 审计,字段正确。
	tid := uuid.NewString()
	uid := uuid.NewString()
	actorCtx := data.WithActor(ctx, data.Actor{Subject: "alice", Role: "tenant_admin"})
	if err := insertUser(actorCtx, store, tid, uid, nil); err != nil {
		t.Fatalf("提交插入: %v", err)
	}
	rows := dataAuditRows(t, store, tid)
	if len(rows) != 1 {
		t.Fatalf("提交应恰留 1 条 data 审计,得 %d: %+v", len(rows), rows)
	}
	e := rows[0]
	if e.Source != audit.SourceData || e.Action != "INSERT users" || e.Result != 0 {
		t.Errorf("data 审计字段错(source/action/result): %+v", e)
	}
	if e.ActorSubject != "alice" || e.ActorRole != "tenant_admin" {
		t.Errorf("actor 归因错,期望 alice/tenant_admin,得 %s/%s", e.ActorSubject, e.ActorRole)
	}
	if e.Detail != "id="+uid {
		t.Errorf("detail 应为行标识 id=%s,得 %q", uid, e.Detail)
	}

	// ③ 无 actor(非 HTTP 路径)→ role='system'。
	tidSys := uuid.NewString()
	if err := insertUser(ctx, store, tidSys, uuid.NewString(), nil); err != nil {
		t.Fatalf("无 actor 插入: %v", err)
	}
	sysRows := dataAuditRows(t, store, tidSys)
	if len(sysRows) != 1 || sysRows[0].ActorRole != "system" || sysRows[0].ActorSubject != "" {
		t.Fatalf("无主体应记 system/空,得 %+v", sysRows)
	}

	// ④ 跨租户隔离:租户 tid 的审计读不到 tidSys 的行(RLS;沿用项目"0 泄漏"风格)。
	for _, e := range dataAuditRows(t, store, tid) {
		if e.TenantID != tid {
			t.Fatalf("审计跨租户泄漏:在 %s 见到 %s 的行", tid, e.TenantID)
		}
	}
}

// TestAuditTriggerCatalogGate 是 CI 门禁(类比 RLS catalog 断言):凡含 tenant_id 列的业务表,
// 除显式排除清单外,必须挂 audit_tr 触发器——新增业务表漏挂即测试失败(防审计完整性漂移,L2 §5.3)。
func TestAuditTriggerCatalogGate(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过审计触发器 catalog 门禁")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	// 含 tenant_id 列但缺 audit_tr 触发器、且不在排除清单中的业务表 → 违规。
	// 排除:revocations(GC 风暴)、policy_bundles(编译高频)、audit_log(自触发)。
	const q = `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
		                   AND a.attnum > 0 AND NOT a.attisdropped
		WHERE c.relkind = 'r'
		  AND c.relname NOT IN ('revocations', 'policy_bundles', 'audit_log')
		  AND NOT EXISTS (
		    SELECT 1 FROM pg_trigger tg
		    WHERE tg.tgrelid = c.oid AND tg.tgname = 'audit_tr' AND NOT tg.tgisinternal
		  )
		ORDER BY c.relname`

	var missing []string
	// catalog 查询不依赖租户,借任意租户上下文跑只读事务。
	err = store.InTxRO(ctx, uuid.NewString(), func(qq data.Queries) error {
		rows, e := qq.Query(ctx, q)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if e := rows.Scan(&name); e != nil {
				return e
			}
			missing = append(missing, name)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("catalog 查询: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("以下业务表含 tenant_id 但未挂 audit_tr 触发器(漏挂或须加入排除清单): %v", missing)
	}

	// 另:tenants 表(租户 id 是 id 列、无 tenant_id)须单独确认挂了触发器。
	var hasTenants bool
	err = store.InTxRO(ctx, uuid.NewString(), func(qq data.Queries) error {
		return qq.QueryRow(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid
			  WHERE c.relname = 'tenants' AND tg.tgname = 'audit_tr' AND NOT tg.tgisinternal)`).Scan(&hasTenants)
	})
	if err != nil {
		t.Fatalf("tenants 触发器查询: %v", err)
	}
	if !hasTenants {
		t.Fatal("tenants 表未挂 audit_tr 触发器")
	}
}
