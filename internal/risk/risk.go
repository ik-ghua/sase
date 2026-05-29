// Package risk 是控制面信任/风险引擎(L1 3.8 动态访问控制;L2 `sase-l2-cp-trust-risk-engine.md`)。
//
// 职责:把多维信号(设备姿态 / DLP 命中 / 会话异常…)按 per-tenant per-subject 聚合派生成风险分(0–100)+
// 等级(low/medium/high/critical)+ 可解释因子;**风险突变(升入 critical)→ 触发自适应撤销**(复用既有撤销)。
// **只产 risk 输入与突变事件,不做访问判定**(判定在策略/PEP);**不碰数据面热路径**(L2 3.7 边界)。
//
// 本刀(起步,L2 3.1):规则/加权评分(非 ML)+ 内存状态 + 突变→撤销闭环;信号起步用**姿态 + DLP 命中**
// (DLP 闭环本刀目标)。**后续(L2)**:风险标记/状态入 RLS Postgres、热态 Redis、事件 ClickHouse、CEL 风险
// 规则、risk 进会话凭证 claim 喂 PEP、per-tenant 阈值可配、PoP-DLP 跨进程经遥测管道(单元③)上报。
package risk

import (
	"time"

	"github.com/ikuai8/sase/api/xdsv1"
)

// Level 是风险等级(由 score 分档)。**取值复用契约包 xdsv1 的单一来源**,使 risk 产出的 level 必落在
// PEP 比较的 riskRank 域内——避免双份常量漂移致 PEP 静默 fail-open(评审 B2)。
type Level string

const (
	LevelLow      Level = Level(xdsv1.RiskLow)
	LevelMedium   Level = Level(xdsv1.RiskMedium)
	LevelHigh     Level = Level(xdsv1.RiskHigh)
	LevelCritical Level = Level(xdsv1.RiskCritical)
)

// 默认分档阈值(L2:阈值可按租户配,起步用默认)。
const (
	threshMedium   = 30
	threshHigh     = 60
	threshCritical = 85
)

// levelOf 按分数定级。
func levelOf(score int) Level {
	switch {
	case score >= threshCritical:
		return LevelCritical
	case score >= threshHigh:
		return LevelHigh
	case score >= threshMedium:
		return LevelMedium
	default:
		return LevelLow
	}
}

// 信号默认权重(对 score 的贡献;sum 截顶 100)。L2:起步可配权重,本刀用默认常量。
const (
	WeightPostureNonCompliant = 90 // 姿态非合规 → 单项即 critical(承接 Slice6 posture→revoke 语义)
	WeightDLPHigh             = 50
	WeightDLPMedium           = 25
	WeightDLPLow              = 10
	WeightSessionAnomaly      = 40
)

// Factor 是一个风险贡献因子(可解释性:为何高风险 / 审计)。
type Factor struct {
	ID       string    `json:"id"`     // 如 "posture:jailbroken_rooted" / "dlp:身份证"
	Weight   int       `json:"weight"` // 对 score 的贡献
	ExpireAt time.Time `json:"-"`      // 事件型因子的过期(姿态状态型为零值=不过期,由下次上报替换)
}

// Assessment 是一次风险评估结果(对接凭证 TTL / 审计)。
type Assessment struct {
	Score      int       `json:"risk_score"` // 0–100
	Level      Level     `json:"risk_level"`
	Factors    []Factor  `json:"factors"`
	ComputedAt time.Time `json:"computed_at"`
}
