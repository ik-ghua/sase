// Package linkmon 是 SD-WAN CPE 的 WAN 多链路监测与选路(客户端 Agent/Connector·CPE L2:WAN/选路/链路修复)。
//
// 背景:分支 CPE 常有多条 WAN 上联(专线 + 宽带/4G)。需持续探测各链路健康(RTT/丢包),按优先级+健康
// 选活动链路,主链路劣化/失效时亚秒切到次优,链路恢复后回切。
// 目标:提供"选路大脑"——纯逻辑、可注入探测器单测;探测、评分、Best() 选路与 ctx 退出。
// 范围:本包只管选哪条链路;拨号/重连由调用方(cmd/cpe serve 循环)按 Best() 执行。FEC/包级冗余需 L3 包
// 路径(当前隧道为 L7 JSON stand-in),不在本包。
package linkmon

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Link 是一条 WAN 上联到 PoP 的路径。软件 stand-in 以 Addr 区分路径;真实 CPE 还含本地源 IP/接口绑定。
type Link struct {
	Name     string
	Addr     string // 经该上联可达的 PoP 连接器端点
	Priority int    // 越小越优先(主链路 0、备份 1…)
}

// Prober 探测单条链路,返回 RTT;err 非 nil 视为该次探测失败(链路不可达)。
type Prober interface {
	Probe(ctx context.Context, link Link) (time.Duration, error)
}

// LinkStatus 是某链路的健康快照(供日志/可观测)。
type LinkStatus struct {
	Link     Link
	Up       bool
	RTT      time.Duration // EWMA
	LossRate float64       // 最近窗口丢包率
	LastOK   time.Time
}

type health struct {
	window  []bool // 最近 N 次探测结果(true=成功),环形
	idx     int
	filled  int
	rttEWMA time.Duration
	lastOK  time.Time
}

// Config 调参(零值用默认)。
type Config struct {
	Interval      time.Duration // 探测周期(默认 200ms)
	Window        int           // 滑窗大小(默认 5)
	LossThreshold float64       // 丢包率 > 此值判 down(默认 0.5)
	Timeout       time.Duration // 单次探测超时(默认 Interval)
	Alpha         float64       // RTT EWMA 系数(默认 0.3)
}

func (c *Config) withDefaults() {
	if c.Interval <= 0 {
		c.Interval = 200 * time.Millisecond
	}
	if c.Window <= 0 {
		c.Window = 5
	}
	if c.LossThreshold <= 0 {
		c.LossThreshold = 0.5
	}
	if c.Timeout <= 0 {
		c.Timeout = c.Interval
	}
	if c.Alpha <= 0 {
		c.Alpha = 0.3
	}
}

// Monitor 持各链路健康,周期探测并据优先级+健康选最优链路。
type Monitor struct {
	cfg     Config
	prober  Prober
	now     func() time.Time
	mu      sync.RWMutex
	links   []Link // 已按 Priority 升序
	healths map[string]*health
}

// New 构造监测器(links 任意序;内部按 Priority 升序)。
func New(links []Link, prober Prober, cfg Config) *Monitor {
	cfg.withDefaults()
	sorted := append([]Link(nil), links...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Priority < sorted[j].Priority })
	m := &Monitor{cfg: cfg, prober: prober, now: time.Now, links: sorted, healths: map[string]*health{}}
	for _, l := range sorted {
		m.healths[l.Name] = &health{window: make([]bool, cfg.Window)}
	}
	return m
}

// Run 周期探测所有链路,直到 ctx 取消。各链路并发探测(单周期内互不阻塞)。
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	m.probeAll(ctx) // 启动即探一轮,避免首个周期前 Best() 无数据
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.probeAll(ctx)
		}
	}
}

func (m *Monitor) probeAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, l := range m.links {
		wg.Add(1)
		go func(link Link) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
			rtt, err := m.prober.Probe(pctx, link)
			cancel()
			m.record(link.Name, err == nil, rtt)
		}(l)
	}
	wg.Wait()
}

// record 更新某链路一次探测结果。!ok 时 rtt 被忽略(失败探测不计入 RTT EWMA);Prober 失败可返回任意 rtt。
func (m *Monitor) record(name string, ok bool, rtt time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.healths[name]
	if h == nil {
		return
	}
	h.window[h.idx] = ok
	h.idx = (h.idx + 1) % len(h.window)
	if h.filled < len(h.window) {
		h.filled++
	}
	if ok {
		h.lastOK = m.now()
		if h.rttEWMA == 0 {
			h.rttEWMA = rtt
		} else {
			a := m.cfg.Alpha
			h.rttEWMA = time.Duration(a*float64(rtt) + (1-a)*float64(h.rttEWMA))
		}
	}
}

// lossRate 与 up 判定(调用方持锁)。
func (h *health) lossRate() float64 {
	if h.filled == 0 {
		return 1
	}
	fails := 0
	for i := 0; i < h.filled; i++ {
		if !h.window[i] {
			fails++
		}
	}
	return float64(fails) / float64(h.filled)
}

func (m *Monitor) up(h *health) bool {
	return h != nil && h.filled > 0 && h.lossRate() <= m.cfg.LossThreshold
}

// Best 返回当前最优健康链路:按 Priority 升序取第一条 up 的;无 up 链路 → (零值,false)。
func (m *Monitor) Best() (Link, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, l := range m.links {
		if m.up(m.healths[l.Name]) {
			return l, true
		}
	}
	return Link{}, false
}

// IsUp 返回指定链路当前是否健康(未知链路 → false)。
func (m *Monitor) IsUp(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.up(m.healths[name])
}

// Snapshot 返回各链路健康快照(按优先级序),供日志/可观测。
func (m *Monitor) Snapshot() []LinkStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]LinkStatus, 0, len(m.links))
	for _, l := range m.links {
		h := m.healths[l.Name]
		out = append(out, LinkStatus{
			Link: l, Up: m.up(h), RTT: h.rttEWMA, LossRate: h.lossRate(), LastOK: h.lastOK,
		})
	}
	return out
}
