package httpapi_test

// Slice33 OpenAPI 一致性门禁(L1 3.11「spec 单一来源、不漂移」的 CI 落点;前端 L2 3.3)。
// 手写 spec(api/openapi/admin.yaml)是权威契约;本测试**双向对账** spec 路径 ↔ httpapi.AdminRoutePatterns:
//   - spec 有但实现没有 → 撒谎 spec(前端按它生成会调到不存在的端点);
//   - 实现有但 spec 没有 → 覆盖缺口(前端无类型可用)。
// 二者任一不符即 FAIL,逼"改端点必同步改 spec"。无需 DB/server(纯数据比较),任意 go test 环境可跑。

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ikuai8/sase/internal/admin/httpapi"
)

// httpMethods:OpenAPI path 对象里属于"操作"的键(其余如 parameters 不是方法)。
var httpMethods = map[string]string{
	"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
}

// specRoutePatterns 解析 admin.yaml,提取 "METHOD path" 集合(与 AdminRoutePatterns 同格式)。
func specRoutePatterns(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "..", "api", "openapi", "admin.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 OpenAPI spec %s: %v", path, err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("解析 OpenAPI YAML: %v", err)
	}
	out := map[string]bool{}
	for p, ops := range doc.Paths {
		for key := range ops {
			if m, ok := httpMethods[key]; ok {
				out[m+" "+p] = true
			}
		}
	}
	return out
}

func TestOpenAPIConformance(t *testing.T) {
	spec := specRoutePatterns(t)
	impl := map[string]bool{}
	for _, p := range httpapi.AdminRoutePatterns {
		impl[p] = true
	}

	// 非空性:防"spec 解析失败/路径键变更"导致空集空过(假一致)。
	if len(spec) < 20 {
		t.Fatalf("spec 仅解析出 %d 条路由(<20),疑似解析失败/spec 结构变更", len(spec))
	}
	if len(httpapi.AdminRoutePatterns) < 20 {
		t.Fatalf("AdminRoutePatterns 仅 %d 条(<20),疑似清单异常", len(httpapi.AdminRoutePatterns))
	}

	var specOnly, implOnly []string
	for r := range spec {
		if !impl[r] {
			specOnly = append(specOnly, r)
		}
	}
	for r := range impl {
		if !spec[r] {
			implOnly = append(implOnly, r)
		}
	}
	sort.Strings(specOnly)
	sort.Strings(implOnly)

	if len(specOnly) != 0 {
		t.Errorf("spec 有但实现(AdminRoutePatterns)没有(撒谎 spec,前端会调到不存在的端点): %v", specOnly)
	}
	if len(implOnly) != 0 {
		t.Errorf("实现有但 spec 没收录(覆盖缺口,前端无类型):请补 api/openapi/admin.yaml: %v", implOnly)
	}
}
