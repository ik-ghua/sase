package ztnaterm

// Slice78 appResolver @connector 标志单测:spec 尾缀 @connector → connector=true(走零暴露);
// 缺省 → connector=false(PoP-TUN SNAT,向后兼容 Slice77)。

import (
	"net"
	"testing"
)

func TestAppResolverConnectorFlag(t *testing.T) {
	ar := NewAppResolver()
	// @connector → 零暴露出站。
	if err := ar.AddSpec(tenant + "=10.123.0.50/32=internal-app@connector"); err != nil {
		t.Fatalf("AddSpec @connector: %v", err)
	}
	// 缺省 → PoP-TUN SNAT(向后兼容)。
	if err := ar.AddSpec(tenant + "=10.123.0.60/32=snat-app"); err != nil {
		t.Fatalf("AddSpec 缺省: %v", err)
	}

	app, connector, ok := ar.ResolveRule(tenant, net.ParseIP("10.123.0.50"), 9000)
	if !ok || app != "internal-app" || !connector {
		t.Fatalf("@connector 规则应 connector=true,得 app=%q connector=%v ok=%v", app, connector, ok)
	}
	app, connector, ok = ar.ResolveRule(tenant, net.ParseIP("10.123.0.60"), 9000)
	if !ok || app != "snat-app" || connector {
		t.Fatalf("缺省规则应 connector=false,得 app=%q connector=%v ok=%v", app, connector, ok)
	}

	// 旧 Resolve 二值签名仍兼容(向后兼容包路径 decide)。
	if a, ok := ar.Resolve(tenant, net.ParseIP("10.123.0.50"), 9000); !ok || a != "internal-app" {
		t.Fatalf("Resolve 二值签名应仍可用,得 %q ok=%v", a, ok)
	}
}

func TestAppResolverConnectorWithPort(t *testing.T) {
	ar := NewAppResolver()
	if err := ar.AddSpec(tenant + "=10.123.0.50/32:443=secure-app@connector"); err != nil {
		t.Fatalf("AddSpec port+@connector: %v", err)
	}
	app, connector, ok := ar.ResolveRule(tenant, net.ParseIP("10.123.0.50"), 443)
	if !ok || app != "secure-app" || !connector {
		t.Fatalf("port+@connector 应命中 connector=true,得 app=%q connector=%v ok=%v", app, connector, ok)
	}
	// 端口不符不命中。
	if _, _, ok := ar.ResolveRule(tenant, net.ParseIP("10.123.0.50"), 80); ok {
		t.Fatal("端口 80 不应命中 443 规则")
	}
}
