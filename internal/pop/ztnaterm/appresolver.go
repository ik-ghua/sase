package ztnaterm

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AppResolver 把内层包目的(dst IP:port)在**本租户**内解析为内部资源标识(appKey,即 PEP 的 resource)。
// 第一刀:env/静态注入的前缀表(tenant, dstCIDR, dstPort) → appKey;dstPort==0 表示任意端口。
// 生产化经 xDS 下发(类比 SubscribeSites,后续刀;不改 resource.App schema)。
//
// 跨租户隔离:解析**严格按 tenant 分域**——只在该租户登记的规则集内查,他租户规则不可见(Slice77 §3.3/§5)。
type AppResolver struct {
	// byTenant[tenant] = 该租户的有序规则列表(查找时取第一条 CIDR+端口命中的)。
	byTenant map[string][]appRule
}

type appRule struct {
	cidr      *net.IPNet
	dstPort   uint16 // 0 = 任意端口
	appKey    string
	connector bool // true=走零暴露 connector 反向出站(Slice78);false=PoP-TUN SNAT(Slice77,缺省)
}

// NewAppResolver 构造空解析器。
func NewAppResolver() *AppResolver {
	return &AppResolver{byTenant: map[string][]appRule{}}
}

// Add 登记一条解析规则(connector=false,即 PoP-TUN SNAT 出站;向后兼容 Slice77 调用)。
func (ar *AppResolver) Add(tenant, cidrStr string, dstPort uint16, appKey string) error {
	return ar.AddRule(tenant, cidrStr, dstPort, appKey, false)
}

// AddRule 登记一条解析规则:本租户内 dst ∈ cidr 且(dstPort==0 或 命中)→ appKey。
// connector=true → 该 resource 走零暴露 connector 反向出站(Slice78);false → PoP-TUN SNAT(Slice77)。
// cidrStr 非法 → 返回 error(fail-loud,装配期发现配置错,不静默吞)。
func (ar *AppResolver) AddRule(tenant, cidrStr string, dstPort uint16, appKey string, connector bool) error {
	if tenant == "" || appKey == "" {
		return fmt.Errorf("ztnaterm: appResolver 规则缺 tenant/appKey")
	}
	_, n, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("ztnaterm: appResolver CIDR %q 非法: %w", cidrStr, err)
	}
	ar.byTenant[tenant] = append(ar.byTenant[tenant], appRule{cidr: n, dstPort: dstPort, appKey: appKey, connector: connector})
	return nil
}

// Resolve 在 tenant 域内把 (dst, dstPort) 解析为 appKey。无任一匹配 → ("", false)。
// 仅查 tenant 自己的规则集(跨租户隔离);v4/v6 由 net.IPNet.Contains 自然处理同族比较。
//
// 注:本方法保留 (appKey, ok) 二值签名,供包路径(decide)向后兼容;透明代理用 ResolveRule 取 connector 标志。
func (ar *AppResolver) Resolve(tenant string, dst net.IP, dstPort uint16) (string, bool) {
	r, ok := ar.resolveRule(tenant, dst, dstPort)
	if !ok {
		return "", false
	}
	return r.appKey, true
}

// ResolveRule 在 tenant 域内解析目的,返回 appKey + 是否走 connector(Slice78 零暴露)。无匹配 → ("",false,false)。
func (ar *AppResolver) ResolveRule(tenant string, dst net.IP, dstPort uint16) (appKey string, connector, ok bool) {
	r, found := ar.resolveRule(tenant, dst, dstPort)
	if !found {
		return "", false, false
	}
	return r.appKey, r.connector, true
}

// resolveRule 取本租户域内第一条 CIDR+端口命中的规则。
func (ar *AppResolver) resolveRule(tenant string, dst net.IP, dstPort uint16) (appRule, bool) {
	for _, r := range ar.byTenant[tenant] {
		if !r.cidr.Contains(dst) {
			continue
		}
		if r.dstPort != 0 && r.dstPort != dstPort {
			continue
		}
		return r, true
	}
	return appRule{}, false
}

// AddSpec 解析并登记一条 spec 字符串(env 注入便捷形式):
//
//	"<tenant>=<cidr>[:port]=<appKey>[@connector]"   端口可省(=任意端口);@connector 可省(=PoP-TUN SNAT)
//
// 例:
//
//	11111111-...=10.99.0.0/24=internal-app            PoP-TUN SNAT 出站(Slice77,缺省,向后兼容)
//	11111111-...=10.123.0.50/32=internal-app@connector 走零暴露 connector 反向出站(Slice78)
//	t1=10.99.0.5/32:80=web                            端口约束
func (ar *AppResolver) AddSpec(spec string) error {
	parts := strings.Split(spec, "=")
	if len(parts) != 3 {
		return fmt.Errorf("ztnaterm: appResolver spec %q 非法,应为 tenant=cidr[:port]=appKey[@connector]", spec)
	}
	tenant := strings.TrimSpace(parts[0])
	dest := strings.TrimSpace(parts[1])
	appField := strings.TrimSpace(parts[2])

	// 尾缀 @connector(Slice78):走零暴露 connector 反向出站;缺省 PoP-TUN SNAT(向后兼容)。
	connector := false
	appKey := appField
	if strings.HasSuffix(appField, "@connector") {
		connector = true
		appKey = strings.TrimSpace(strings.TrimSuffix(appField, "@connector"))
	}

	cidrStr := dest
	var port uint16
	// 仅当 ":port" 形式且不是 IPv6 字面量(含多个冒号)时解析端口。CIDR 网络段不含冒号(IPv4)。
	if i := strings.LastIndex(dest, ":"); i >= 0 && !strings.Contains(dest[:i], ":") {
		cidrStr = dest[:i]
		p, err := parsePort(dest[i+1:])
		if err != nil {
			return fmt.Errorf("ztnaterm: appResolver spec %q 端口非法: %w", spec, err)
		}
		port = p
	}
	return ar.AddRule(tenant, cidrStr, port, appKey, connector)
}

func parsePort(s string) (uint16, error) {
	// strconv.Atoi 严格解析(整串必为数字)——装配期 fail-loud,避免 fmt.Sscanf 吞尾(如 "80x"→80)。
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("端口 %q 非法: %w", s, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("端口 %d 越界", p)
	}
	return uint16(p), nil
}
