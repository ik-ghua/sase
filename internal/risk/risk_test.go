package risk

import (
	"testing"
	"time"

	"github.com/ikuai8/sase/internal/dlp"
)

func TestLevelOf(t *testing.T) {
	cases := []struct {
		score int
		want  Level
	}{{0, LevelLow}, {29, LevelLow}, {30, LevelMedium}, {59, LevelMedium}, {60, LevelHigh}, {84, LevelHigh}, {85, LevelCritical}, {100, LevelCritical}}
	for _, c := range cases {
		if got := levelOf(c.score); got != c.want {
			t.Errorf("levelOf(%d)=%s, want %s", c.score, got, c.want)
		}
	}
}

// 突变捕获器
type capture struct {
	n       int
	lastJTI string
	lastA   Assessment
}

func (c *capture) fn(_, _, jti string, a Assessment) { c.n++; c.lastJTI = jti; c.lastA = a }

// 姿态非合规 → 单项即 critical → 触发撤销;恢复合规 → 清除、不再触发。
func TestPostureToRevoke(t *testing.T) {
	cpt := &capture{}
	s := NewService(cpt.fn)

	a := s.ObservePosture("t1", "alice", "jti-1", "jailbroken_rooted")
	if a.Level != LevelCritical {
		t.Fatalf("姿态非合规应 critical,得 %s(score=%d)", a.Level, a.Score)
	}
	if cpt.n != 1 || cpt.lastJTI != "jti-1" {
		t.Fatalf("应触发一次撤销 jti-1,得 n=%d jti=%s", cpt.n, cpt.lastJTI)
	}
	// 恢复合规 → 清除姿态因子,回落 low
	if a := s.ObservePosture("t1", "alice", "jti-2", "compliant"); a.Level != LevelLow {
		t.Fatalf("恢复合规应回 low,得 %s", a.Level)
	}
}

// DLP 闭环:累积命中升入 critical → 触发撤销(带会话 jti);滞后:已 critical 再命中不重复触发。
func TestDLPClosureToRevoke(t *testing.T) {
	cpt := &capture{}
	s := NewService(cpt.fn)

	// 一条 high(50)→ medium,不撤销
	s.Report("t1", "bob", "jti-b", dlp.Finding{RuleName: "身份证", Severity: dlp.SeverityHigh})
	if a := s.Assess("t1", "bob"); a.Level == LevelCritical {
		t.Fatalf("单条 high 不应 critical,得 %s", a.Level)
	}
	if cpt.n != 0 {
		t.Fatalf("未到 critical 不应撤销,得 n=%d", cpt.n)
	}
	// 第二条 high(累积 100)→ critical → 撤销(DLP 命中闭环到动态访问控制)
	s.Report("t1", "bob", "jti-b", dlp.Finding{RuleName: "银行卡", Severity: dlp.SeverityHigh})
	if a := s.Assess("t1", "bob"); a.Level != LevelCritical {
		t.Fatalf("两条 high 应 critical,得 %s(score=%d)", a.Level, a.Score)
	}
	if cpt.n != 1 || cpt.lastJTI != "jti-b" || cpt.lastA.Level != LevelCritical {
		t.Fatalf("DLP 累积应触发一次撤销 jti-b,得 n=%d jti=%s level=%s", cpt.n, cpt.lastJTI, cpt.lastA.Level)
	}
	// 滞后:已 critical 再命中,不重复触发撤销
	s.Report("t1", "bob", "jti-b", dlp.Finding{RuleName: "手机号", Severity: dlp.SeverityHigh})
	if cpt.n != 1 {
		t.Fatalf("已 critical 不应重复撤销,得 n=%d", cpt.n)
	}
}

// 事件型因子按 TTL 衰减:DLP 因子过期后 score 回落。
func TestEventFactorDecay(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewService(nil)
	s.now = func() time.Time { return now }

	s.Report("t1", "carol", "j", dlp.Finding{RuleName: "x", Severity: dlp.SeverityHigh})
	if s.Assess("t1", "carol").Score != WeightDLPHigh {
		t.Fatalf("命中后应有分,得 %d", s.Assess("t1", "carol").Score)
	}
	now = now.Add(eventFactorTTL + time.Minute) // 越过 TTL
	if a := s.Assess("t1", "carol"); a.Score != 0 || a.Level != LevelLow {
		t.Fatalf("事件因子过期后应回落 0/low,得 score=%d level=%s", a.Score, a.Level)
	}
}

// 滞后按 jti:① 同 jti 同 critical 不重复撤;② **会话轮换(新 jti)仍 critical 也再撤**(新会话受保护);
// ③ 降到 critical 以下再升入会再撤(评审 B1/B2)。
func TestHysteresisByJTI(t *testing.T) {
	cpt := &capture{}
	s := NewService(cpt.fn)

	// 姿态非合规(sticky)→ critical,撤 jti-1
	s.ObservePosture("t1", "dave", "jti-1", "jailbroken_rooted")
	if cpt.n != 1 || cpt.lastJTI != "jti-1" {
		t.Fatalf("应撤 jti-1,得 n=%d jti=%s", cpt.n, cpt.lastJTI)
	}
	// 仍非合规、同 jti 再报 → 不重复撤(防抖)
	s.ObservePosture("t1", "dave", "jti-1", "jailbroken_rooted")
	if cpt.n != 1 {
		t.Fatalf("同 jti 同 critical 不应重复撤,得 n=%d", cpt.n)
	}
	// 会话轮换:新 jti-2 仍非合规(critical 维持)→ **新会话须再撤**
	s.ObservePosture("t1", "dave", "jti-2", "jailbroken_rooted")
	if cpt.n != 2 || cpt.lastJTI != "jti-2" {
		t.Fatalf("会话轮换后新 jti-2 应再撤,得 n=%d jti=%s", cpt.n, cpt.lastJTI)
	}
	// 恢复合规(降级)→ 不撤;复位滞后
	s.ObservePosture("t1", "dave", "jti-2", "compliant")
	// 再次非合规(重新升入 critical)→ 再撤
	s.ObservePosture("t1", "dave", "jti-3", "jailbroken_rooted")
	if cpt.n != 3 || cpt.lastJTI != "jti-3" {
		t.Fatalf("降级后再升 critical 应再撤,得 n=%d jti=%s", cpt.n, cpt.lastJTI)
	}
}

// key 用 struct,tenant/subject 含 '/' 也不碰撞。
func TestNoKeyCollision(t *testing.T) {
	s := NewService(nil)
	s.ObservePosture("a/b", "c", "j", "jailbroken_rooted") // (a/b, c) critical
	if s.Assess("a", "b/c").Level != LevelLow {            // (a, b/c) 不应被误并为同一 key
		t.Fatal("struct key 应避免 'a/b'+'c' 与 'a'+'b/c' 碰撞")
	}
}

// per-tenant per-subject 隔离:不同租户/主体状态互不影响。
func TestRiskIsolation(t *testing.T) {
	s := NewService(nil)
	s.ObservePosture("t1", "alice", "j", "jailbroken_rooted") // t1/alice critical
	if s.Assess("t2", "alice").Level != LevelLow {
		t.Fatal("t2/alice 不应受 t1/alice 影响")
	}
	if s.Assess("t1", "bob").Level != LevelLow {
		t.Fatal("t1/bob 不应受 t1/alice 影响")
	}
}
