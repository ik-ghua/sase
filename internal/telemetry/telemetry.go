// Package telemetry 是控制面单元③遥测管道的**事件上报**起步:数据面(PoP)经 gRPC 把事件上报控制面,
// 控制面 Ingest 派发给各 Sink(本刀:风险引擎,闭环 DLP→风险→撤销)。
//
// 本刀范围(L1 3.14 / 单元③ 起步):事件信封 + 上报 gRPC + Ingest 派发 + PoP 侧异步缓冲 Reporter +
// DLP FindingSink 适配。**后续**:完整指标(VictoriaMetrics)/采样 Tracing/审计落 ClickHouse、采样、背压策略
// (运维 L2 3.4)。事件 best-effort:不阻塞数据面、缓冲满即丢(计数),与风险引擎"信号 best-effort、权威在 PoP"一致。
package telemetry

import "time"

// 事件类型(kind)。起步仅 DLP 命中(承载风险信号);后续扩展。
const KindDLPFinding = "dlp_finding"

// DLP 命中事件的 attrs 键。
const (
	AttrDLPRule     = "dlp_rule"
	AttrDLPSeverity = "dlp_severity"
	AttrDLPAction   = "dlp_action"
)

// Event 是一条遥测事件(与 proto 解耦,使 Sink 不依赖 proto)。
type Event struct {
	TenantID string
	Subject  string
	JTI      string
	Kind     string
	Attrs    map[string]string
	Ts       time.Time
}

// Sink 消费遥测事件(控制面侧;风险引擎/审计/观测各实现一个)。Handle 须快速返回(Ingest 串行派发)。
type Sink interface {
	Handle(e Event)
}

// SinkFunc 把函数适配为 Sink。
type SinkFunc func(Event)

func (f SinkFunc) Handle(e Event) { f(e) }
