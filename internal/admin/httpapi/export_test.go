package httpapi

import (
	"sync"

	"github.com/ikuai8/sase/internal/ratelimit"
)

// ResetLoginLimiterForTest 重置进程级 /login 限流器单例(仅测试可见,export_test.go 不入生产二进制)。
//
// 为何需要:loginLimiter 是进程级单例(R2),其 IP 桶在整个测试进程内共享 —— 一个测试若
// 把 127.0.0.1 桶打到 429,会污染后续别的 /login 测试。每个用到 /login 的测试在构建路由前
// 调一次本函数,得到干净的限流状态(满 burst),互不干扰。
//
// rate/burst 可覆盖(传 0 用生产默认):限流测试可调小桶以确定性地触发 429,
// 而 cookie 桥接等正常测试用生产默认(不会被自身少量请求耗尽)。
func ResetLoginLimiterForTest(rate, burst float64) {
	r, b := rate, burst
	if r <= 0 {
		r = loginRate
	}
	if b <= 0 {
		b = loginBurst
	}
	loginLimiterOnce = sync.Once{}
	loginLimiterInst = ratelimit.New(r, b)
	// 不在测试单例上启 janitor:测试限流器随进程退出回收,无需周期清扫(且避免测试 goroutine 泄漏)。
	// 用 Do 把 once 标记为已执行,使后续 loginLimiter() 直接返回本实例(不再启生产 janitor)。
	loginLimiterOnce.Do(func() {})
}
