package data_test

// Slice32(c) RLS catalog 门禁(数据访问层 L2 §3.7/§3.9 设计的「0 泄漏回归防线」,此前未编码)。
// 数据驱动地查 pg_catalog,断言隔离不变量——**自动 catch 未来漏配**(新增 tenant_id 表忘开 RLS、
// 误给角色 BYPASSRLS、平台视图 owner 配错):
//   G1 含 tenant_id 的基表必 ENABLE+FORCE RLS + 有策略(除显式白名单);tenants(id 键)单独断言。
//   G2 应用角色(app_rw/app_ro/app_platform_ro)均无 BYPASSRLS、非 superuser。
//   G3 平台跨租户视图 tenant_summary 存在、是视图、owner 绕 RLS(superuser/BYPASSRLS),且在平台白名单。
// 注:数据访问层 L2 的 **G4 是「隔离行为用例」(越权读/写/上下文缺失/连接复用/平台路径),非 catalog 断言**——
// 已由 rls_integration_test.go(前四类)+ platform_integration_test.go 的 TestBusinessPathStillIsolated(平台路径)覆盖,
// 故本文件只实现 catalog 类 G1/G2/G3;G4 在行为测试。
// 注:仅查普通基表(relkind='r');若未来引入承载 tenant_id 的分区表('p')/外部表('f'),G1 须扩 relkind。
// 需 SASE_DB_RO_DSN(或 RW);未设则 SKIP。前置:migrations 0001-0013。-run TestRLSCatalogGate。

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// tenantIDExemptions:含 tenant_id 列却**豁免 RLS** 的基表白名单(须写理由)。当前无——
// 凡含 tenant_id 的表都该 RLS。新增豁免须在此显式登记 + 理由,否则 G1 失败(防"加了 tenant_id 又不配 RLS"的灰色绕过)。
var tenantIDExemptions = []string{}

// platformCrossTenantViews:已知的平台跨租户策展视图白名单(显式"除非显式"口子,平台控制台 L2 §3.1)。
var platformCrossTenantViews = []string{"tenant_summary"}

func gateStore(t *testing.T) (data.Store, context.Context) {
	t.Helper()
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW/RO_DSN,跳过 RLS catalog 门禁")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	t.Cleanup(store.Close)
	return store, ctx
}

// catalogQuery 用只读事务跑一个 catalog 查询(不依赖租户;借任意租户上下文)。
func catalogQuery(t *testing.T, ctx context.Context, store data.Store, run func(q data.Queries) error) {
	t.Helper()
	if err := store.InTxRO(ctx, uuid.NewString(), run); err != nil {
		t.Fatalf("catalog 查询: %v", err)
	}
}

func TestRLSCatalogGateG1TenantTablesHaveRLS(t *testing.T) {
	store, ctx := gateStore(t)

	// G1:含 tenant_id 列的基表,缺 ENABLE+FORCE+策略 且不在豁免白名单 → 违规。
	const q = `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
		                   AND a.attnum > 0 AND NOT a.attisdropped
		WHERE c.relkind = 'r'
		  AND NOT (
		    c.relrowsecurity AND c.relforcerowsecurity
		    AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
		  )
		  AND c.relname <> ALL($1::text[])
		ORDER BY c.relname`
	var bad []string
	catalogQuery(t, ctx, store, func(q2 data.Queries) error {
		rows, e := q2.Query(ctx, q, tenantIDExemptions)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if e := rows.Scan(&name); e != nil {
				return e
			}
			bad = append(bad, name)
		}
		return rows.Err()
	})
	if len(bad) != 0 {
		t.Fatalf("含 tenant_id 的基表缺 RLS(ENABLE+FORCE+策略),且不在豁免白名单: %v", bad)
	}

	// 非空性(防"门禁因匹配 0 张表而空过"=假安全):应检到一批 tenant_id 基表(现 ~12 张)。
	var n int
	catalogQuery(t, ctx, store, func(q2 data.Queries) error {
		return q2.QueryRow(ctx, `
			SELECT count(*) FROM pg_class c
			JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname='public'
			JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped
			WHERE c.relkind='r'`).Scan(&n)
	})
	if n < 8 {
		t.Fatalf("含 tenant_id 的基表只检到 %d 张(<8),门禁疑似空过/连错库", n)
	}

	// tenants 表租户键是 id 列(非 tenant_id),G1 不覆盖 → 单独断言它有 ENABLE+FORCE+策略。
	var ok bool
	catalogQuery(t, ctx, store, func(q2 data.Queries) error {
		return q2.QueryRow(ctx, `
			SELECT c.relrowsecurity AND c.relforcerowsecurity
			       AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
			WHERE c.relname = 'tenants' AND c.relkind = 'r'`).Scan(&ok)
	})
	if !ok {
		t.Fatal("tenants 表(id 键)须 ENABLE+FORCE RLS + 有策略")
	}
}

func TestRLSCatalogGateG2AppRolesNoBypass(t *testing.T) {
	store, ctx := gateStore(t)

	// G2:应用角色均不得有 BYPASSRLS、不得是 superuser(隔离不靠角色绕 RLS)。
	// 角色清单与 internal/data/config.go 暴露的 DSN 一一对应:租户路径(app_rw/ro)+ 平台只读
	// (app_platform_ro,Slice32)+ 平台写池(app_platform_rw,Slice38a,Slice38c/d 高敏感写复用)。
	const q = `
		SELECT rolname FROM pg_roles
		WHERE rolname IN ('app_rw', 'app_ro', 'app_platform_ro', 'app_platform_rw')
		  AND (rolbypassrls OR rolsuper)
		ORDER BY rolname`
	var bad []string
	catalogQuery(t, ctx, store, func(q2 data.Queries) error {
		rows, e := q2.Query(ctx, q)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if e := rows.Scan(&name); e != nil {
				return e
			}
			bad = append(bad, name)
		}
		return rows.Err()
	})
	if len(bad) != 0 {
		t.Fatalf("应用角色不应有 BYPASSRLS/superuser(违 G2,隔离不靠角色绕 RLS): %v", bad)
	}
}

func TestRLSCatalogGateG3PlatformViews(t *testing.T) {
	store, ctx := gateStore(t)

	// G3:每个已知平台跨租户视图须存在、是视图、且 owner 绕 RLS(superuser/BYPASSRLS)——
	// 否则跨租户读会静默少行(平台控制台 L2 §3.1;与 migration 0013 owner 自检呼应)。
	for _, view := range platformCrossTenantViews {
		var isViewOwnerBypass bool
		var exists bool
		catalogQuery(t, ctx, store, func(q2 data.Queries) error {
			return q2.QueryRow(ctx, `
				SELECT
				  EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
				          WHERE c.relname=$1 AND c.relkind='v' AND n.nspname='public'),
				  COALESCE((SELECT bool_and(r.rolbypassrls OR r.rolsuper)
				            FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
				            WHERE c.relname=$1 AND c.relkind='v'
				              AND c.relnamespace='public'::regnamespace), false)`,
				view).Scan(&exists, &isViewOwnerBypass)
		})
		if !exists {
			t.Fatalf("平台跨租户视图 %s 不存在(或非视图)", view)
		}
		if !isViewOwnerBypass {
			t.Fatalf("平台视图 %s 的 owner 须绕 RLS(superuser/BYPASSRLS),否则跨租户读静默少行", view)
		}
	}
}
