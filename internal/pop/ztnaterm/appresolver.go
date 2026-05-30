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
	cidr    *net.IPNet
	dstPort uint16 // 0 = 任意端口
	appKey  string
}

// NewAppResolver 构造空解析器。
func NewAppResolver() *AppResolver {
	return &AppResolver{byTenant: map[string][]appRule{}}
}

// Add 登记一条解析规则:本租户内 dst ∈ cidr 且(dstPort==0 或 命中)→ appKey。
// cidrStr 非法 → 返回 error(fail-loud,装配期发现配置错,不静默吞)。
func (ar *AppResolver) Add(tenant, cidrStr string, dstPort uint16, appKey string) error {
	if tenant == "" || appKey == "" {
		return fmt.Errorf("ztnaterm: appResolver 规则缺 tenant/appKey")
	}
	_, n, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("ztnaterm: appResolver CIDR %q 非法: %w", cidrStr, err)
	}
	ar.byTenant[tenant] = append(ar.byTenant[tenant], appRule{cidr: n, dstPort: dstPort, appKey: appKey})
	return nil
}

// Resolve 在 tenant 域内把 (dst, dstPort) 解析为 appKey。无任一匹配 → ("", false)。
// 仅查 tenant 自己的规则集(跨租户隔离);v4/v6 由 net.IPNet.Contains 自然处理同族比较。
func (ar *AppResolver) Resolve(tenant string, dst net.IP, dstPort uint16) (string, bool) {
	for _, r := range ar.byTenant[tenant] {
		if !r.cidr.Contains(dst) {
			continue
		}
		if r.dstPort != 0 && r.dstPort != dstPort {
			continue
		}
		return r.appKey, true
	}
	return "", false
}

// AddSpec 解析并登记一条 spec 字符串(env 注入便捷形式):
//
//	"<tenant>=<cidr>[:port]=<appKey>"   端口可省(=任意端口)
//
// 例:`11111111-...=10.99.0.0/24=internal-app` 或 `t1=10.99.0.5/32:80=web`。
func (ar *AppResolver) AddSpec(spec string) error {
	parts := strings.Split(spec, "=")
	if len(parts) != 3 {
		return fmt.Errorf("ztnaterm: appResolver spec %q 非法,应为 tenant=cidr[:port]=appKey", spec)
	}
	tenant := strings.TrimSpace(parts[0])
	dest := strings.TrimSpace(parts[1])
	appKey := strings.TrimSpace(parts[2])
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
	return ar.Add(tenant, cidrStr, port, appKey)
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
