package data

import "os"

// Config 持有四路 DSN(数据访问层 L2 3.5/3.6 + Slice38a 平台写池):
// 连接串指向同一库,仅登录角色不同;均 NOBYPASSRLS,与 RLS 形成纵深。
//
//	app_rw            租户路径读写
//	app_ro            租户路径只读
//	app_platform_ro   平台跨租户只读(看 tenant_summary / pop_nodes 等)
//	app_platform_rw   平台写池(pop_nodes 等无 RLS 平台表 RW;Slice38c/d CA·KEK 等复用)
type Config struct {
	RWConnString         string // app_rw 连接串
	ROConnString         string // app_ro 连接串
	PlatformConnString   string // app_platform_ro 连接串(可选;空则 InPlatformTx 不可用)
	PlatformRWConnString string // app_platform_rw 连接串(可选;空则 InPlatformTxRW 不可用,平台写端点 503)
}

// ConfigFromEnv 从环境读取 DSN。两者皆空时返回 ok=false(调用方退回 Slice 0 桩)。
//
//	SASE_DB_RW_DSN        例: postgres://app_rw:app_rw_dev@127.0.0.1:5432/sase
//	SASE_DB_RO_DSN        例: postgres://app_ro:app_ro_dev@127.0.0.1:5432/sase
//	SASE_DB_PLATFORM_DSN  例: postgres://app_platform_ro:app_platform_ro_dev@127.0.0.1:5432/sase(可选,平台跨租户只读)
//
// 仅设 RW 时,RO 复用 RW(开发便利;生产应显式区分角色)。PLATFORM 不回退(平台路径须用专用角色;未设则 InPlatformTx 不可用)。
func ConfigFromEnv() (Config, bool) {
	rw := os.Getenv("SASE_DB_RW_DSN")
	ro := os.Getenv("SASE_DB_RO_DSN")
	if rw == "" && ro == "" {
		return Config{}, false
	}
	if ro == "" {
		ro = rw
	}
	if rw == "" {
		rw = ro
	}
	// SASE_DB_PLATFORM_DSN(可选)例: postgres://app_platform_ro:app_platform_ro_dev@127.0.0.1:5432/sase
	// 未设则 InPlatformTx 不可用(平台模块跨租户读需配);不回退到 rw/ro(平台路径须用专用角色)。
	// SASE_DB_PLATFORM_RW_DSN(可选)例: postgres://app_platform_rw:app_platform_rw_dev@127.0.0.1:5432/sase
	// 未设则 InPlatformTxRW 不可用(平台写端点 503);**绝不回退**到 app_rw(平台写不应混入租户写池,
	// 防 Slice38c/d 高敏感操作误走租户角色)。
	return Config{
		RWConnString:         rw,
		ROConnString:         ro,
		PlatformConnString:   os.Getenv("SASE_DB_PLATFORM_DSN"),
		PlatformRWConnString: os.Getenv("SASE_DB_PLATFORM_RW_DSN"),
	}, true
}
