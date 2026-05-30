package site

// site.Service 端到端(真 PG;需 SASE_DB_RW_DSN/RO_DSN;未设则 SKIP)。
// 前置:migrations 0006(sites 表 RLS)。
//
// 覆盖:
//   A. ListSites:列出 + 按 site_key 升序 + **RLS 跨租户隔离实证**(tA 列不到 tB)+ 空租户返非 nil 空切片。
//   B. CreateSite 校验:
//      - 拒绝 v4-mapped-v6 CIDR(::ffff:10.0.0.0/104)→ ErrNonCanonicalCIDR(承接 Slice70 输入侧纵深);
//      - 正常 v4(10.0.1.0/24)/v6(2001:db8::/48)仍接受并入库;
//      - 缺字段 / net.ParseCIDR 解析失败仍拒。
//   非法 CIDR 一律 fail-closed,不入库(经 ListSites 反证)。

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/google/uuid"

	"github.com/ikuai8/sase/internal/data"
)

// TestCheckCanonicalCIDR 纯逻辑:规范族表示的边界(不依赖 DB)。
func TestCheckCanonicalCIDR(t *testing.T) {
	cases := []struct {
		cidr   string
		reject bool // true=应被 checkCanonicalCIDR 判为非规范
	}{
		{"10.0.1.0/24", false},        // 规范 v4:4 字节 IP + 4 字节掩码
		{"192.168.0.0/16", false},     // 规范 v4
		{"2001:db8::/48", false},      // 规范 v6:To4()==nil + 16 字节掩码
		{"fd00::/8", false},           // 规范 v6
		{"::ffff:10.0.0.0/104", true}, // v4-mapped-v6:To4()!=nil 但 16 字节掩码 → 非规范
		{"::ffff:192.168.1.0/120", true},
		{"::1/128", false},          // 纯 v6 loopback:To4()==nil + 16 字节掩码 → 规范
		{"0.0.0.0/0", false},        // v4 默认路由:4 字节 IP + 4 字节掩码 → 规范
		{"::/0", false},             // v6 默认路由:To4()==nil + 16 字节掩码 → 规范
		{"::ffff:0.0.0.0/96", true}, // v4-mapped 默认段:To4()!=nil 但 16 字节掩码 → 非规范
	}
	for _, c := range cases {
		_, ipnet, err := net.ParseCIDR(c.cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q) 预期可解析,得 err=%v", c.cidr, err)
		}
		gotErr := checkCanonicalCIDR(ipnet)
		if c.reject && gotErr == nil {
			t.Errorf("%q 应判为非规范被拒,却放行", c.cidr)
		}
		if !c.reject && gotErr != nil {
			t.Errorf("%q 应放行,却被拒:%v", c.cidr, gotErr)
		}
		if c.reject && !errors.Is(gotErr, ErrNonCanonicalCIDR) {
			t.Errorf("%q 拒绝错误应为 ErrNonCanonicalCIDR,得 %v", c.cidr, gotErr)
		}
	}
}

func TestServiceIntegration(t *testing.T) {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		t.Skip("未设 SASE_DB_RW_DSN,跳过 site 服务端到端测试")
	}
	ctx := context.Background()
	store, err := data.NewPgxStore(ctx, cfg)
	if err != nil {
		t.Fatalf("接 DB: %v", err)
	}
	defer store.Close()

	svc := NewService(store)
	tA := uuid.NewString()
	tB := uuid.NewString()
	tEmpty := uuid.NewString()

	// --- B. CreateSite 校验 ---

	// 拒 v4-mapped:不入库(后续 ListSites 反证 tA 仅含合法站点)。
	mapped := &Site{SiteKey: "mapped", Name: "v4mapped", CIDR: "::ffff:10.0.0.0/104"}
	if err := svc.CreateSite(ctx, tA, mapped); err == nil {
		t.Fatal("CreateSite 应拒绝 v4-mapped-v6 CIDR,却成功")
	} else if !errors.Is(err, ErrNonCanonicalCIDR) {
		t.Fatalf("v4-mapped 拒绝错误应包裹 ErrNonCanonicalCIDR,得 %v", err)
	}

	// 缺字段拒。
	if err := svc.CreateSite(ctx, tA, &Site{Name: "no-key", CIDR: "10.0.0.0/24"}); err == nil {
		t.Fatal("CreateSite 缺 site_key 应拒")
	}
	if err := svc.CreateSite(ctx, tA, &Site{SiteKey: "no-cidr", Name: "x"}); err == nil {
		t.Fatal("CreateSite 缺 cidr 应拒")
	}
	// net.ParseCIDR 解析失败拒。
	if err := svc.CreateSite(ctx, tA, &Site{SiteKey: "bad", Name: "x", CIDR: "10.0.0.0/99"}); err == nil {
		t.Fatal("CreateSite 非法 CIDR 应拒")
	}

	// 正常 v4 / v6 接受并入库。两个 v4 site_key 故意逆序插入以验排序。
	if err := svc.CreateSite(ctx, tA, &Site{SiteKey: "site-z", Name: "zz", CIDR: "10.0.2.0/24"}); err != nil {
		t.Fatalf("CreateSite 合法 v4(site-z)应成功:%v", err)
	}
	if err := svc.CreateSite(ctx, tA, &Site{SiteKey: "site-a", Name: "aa", CIDR: "10.0.1.0/24"}); err != nil {
		t.Fatalf("CreateSite 合法 v4(site-a)应成功:%v", err)
	}
	if err := svc.CreateSite(ctx, tA, &Site{SiteKey: "site-v6", Name: "v6", CIDR: "2001:db8::/48"}); err != nil {
		t.Fatalf("CreateSite 合法 v6 应成功:%v", err)
	}
	// tB 一个站点(验跨租户隔离),且 site_key 与 tA 之一相同以确认靠 tenant 隔离非 key。
	if err := svc.CreateSite(ctx, tB, &Site{SiteKey: "site-a", Name: "b-only", CIDR: "172.16.0.0/16"}); err != nil {
		t.Fatalf("CreateSite tB 应成功:%v", err)
	}

	// --- A. ListSites ---

	// tA:3 个(v4-mapped 已被拒未入库)+ 按 site_key 升序(site-a < site-v6 < site-z)+ RLS 隔离。
	listA, err := svc.ListSites(ctx, tA)
	if err != nil {
		t.Fatalf("ListSites(tA): %v", err)
	}
	if len(listA) != 3 {
		t.Fatalf("tA 应 3 个站点(mapped 被拒不入库),得 %d:%+v", len(listA), listA)
	}
	wantOrder := []string{"site-a", "site-v6", "site-z"}
	for i, w := range wantOrder {
		if listA[i].SiteKey != w {
			t.Fatalf("tA 站点应按 site_key 升序 %v,得 [%d]=%q(全:%+v)", wantOrder, i, listA[i].SiteKey, listA)
		}
	}
	for _, s := range listA {
		if s.TenantID != tA {
			t.Fatalf("RLS 泄漏:tA 列表含非 tA 租户行 %+v", s)
		}
		if s.Name == "b-only" || s.CIDR == "172.16.0.0/16" {
			t.Fatalf("RLS 泄漏:tA 列表混入 tB 的站点 %+v", s)
		}
		if s.SiteKey == "mapped" {
			t.Fatalf("v4-mapped 站点不应入库,却在 tA 列表 %+v", s)
		}
	}

	// tB:仅 1 个,且 RLS 隔离实证(列不到 tA 的 site-a 同名行)。
	listB, err := svc.ListSites(ctx, tB)
	if err != nil {
		t.Fatalf("ListSites(tB): %v", err)
	}
	if len(listB) != 1 || listB[0].SiteKey != "site-a" || listB[0].Name != "b-only" {
		t.Fatalf("tB 应仅含自身的 site-a(b-only),得 %+v", listB)
	}

	// 空租户:非 nil 空切片(可直接 JSON 序列化为 [])。
	listEmpty, err := svc.ListSites(ctx, tEmpty)
	if err != nil {
		t.Fatalf("ListSites(tEmpty): %v", err)
	}
	if listEmpty == nil {
		t.Fatal("空租户 ListSites 应返回非 nil 空切片(避免序列化为 null)")
	}
	if len(listEmpty) != 0 {
		t.Fatalf("空租户应 0 个站点,得 %d:%+v", len(listEmpty), listEmpty)
	}
}
