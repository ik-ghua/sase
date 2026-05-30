package agentd

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeProber 据 name → RTT/可达性注入(单测,不真连网)。
type fakeProber struct {
	rtt  map[string]time.Duration
	down map[string]bool
}

func (f fakeProber) ProbeRTT(_ context.Context, c PoPCandidate) (time.Duration, error) {
	if f.down[c.Name] {
		return 0, errors.New("unreachable")
	}
	return f.rtt[c.Name], nil
}

// TestSelectPicksLowestRTT 验证选 RTT 最低的可达 PoP(去硬编码,实测选优,L2 §3.7)。
func TestSelectPicksLowestRTT(t *testing.T) {
	sel := NewPoPSelector(fakeProber{rtt: map[string]time.Duration{
		"bj": 30 * time.Millisecond,
		"sh": 12 * time.Millisecond,
		"gz": 45 * time.Millisecond,
	}})
	sel.SetCandidates([]PoPCandidate{
		{Name: "bj", HandshakeAddr: "bj:9443"},
		{Name: "sh", HandshakeAddr: "sh:9443"},
		{Name: "gz", HandshakeAddr: "gz:9443"},
	})
	got, err := sel.Select(context.Background())
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.Name != "sh" {
		t.Fatalf("应选 RTT 最低 sh,得 %s", got.Name)
	}
	if sel.Current() != "sh" {
		t.Fatalf("Current 应为 sh,得 %s", sel.Current())
	}
}

// TestSelectSkipsUnreachable 验证不可达候选被跳过,选次优可达者。
func TestSelectSkipsUnreachable(t *testing.T) {
	sel := NewPoPSelector(fakeProber{
		rtt:  map[string]time.Duration{"bj": 10 * time.Millisecond, "sh": 20 * time.Millisecond},
		down: map[string]bool{"bj": true}, // 最优 bj 不可达
	})
	sel.SetCandidates([]PoPCandidate{{Name: "bj", HandshakeAddr: "bj:1"}, {Name: "sh", HandshakeAddr: "sh:1"}})
	got, err := sel.Select(context.Background())
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.Name != "sh" {
		t.Fatalf("bj 不可达应选 sh,得 %s", got.Name)
	}
}

// TestSelectDeterministicTie 验证同 RTT 时按名升序定夺(确定性,抑抖动)。
func TestSelectDeterministicTie(t *testing.T) {
	sel := NewPoPSelector(fakeProber{rtt: map[string]time.Duration{"zz": 10 * time.Millisecond, "aa": 10 * time.Millisecond}})
	sel.SetCandidates([]PoPCandidate{{Name: "zz", HandshakeAddr: "zz:1"}, {Name: "aa", HandshakeAddr: "aa:1"}})
	for i := 0; i < 5; i++ {
		got, err := sel.Select(context.Background())
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if got.Name != "aa" {
			t.Fatalf("同 RTT 应稳定选名序最前 aa,得 %s", got.Name)
		}
	}
}

// TestSelectErrors 验证无候选 / 全部不可达的错误分流。
func TestSelectErrors(t *testing.T) {
	sel := NewPoPSelector(fakeProber{})
	if _, err := sel.Select(context.Background()); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("无候选应 ErrNoCandidates,得 %v", err)
	}
	sel.SetCandidates([]PoPCandidate{{Name: "a", HandshakeAddr: "a:1"}})
	selDown := NewPoPSelector(fakeProber{down: map[string]bool{"a": true}})
	selDown.SetCandidates([]PoPCandidate{{Name: "a", HandshakeAddr: "a:1"}})
	if _, err := selDown.Select(context.Background()); !errors.Is(err, ErrNoHealthy) {
		t.Fatalf("全部不可达应 ErrNoHealthy,得 %v", err)
	}
}

// TestSetCandidatesDedupAndFilter 验证空名/空地址/重名被过滤。
func TestSetCandidatesDedupAndFilter(t *testing.T) {
	sel := NewPoPSelector(fakeProber{})
	sel.SetCandidates([]PoPCandidate{
		{Name: "a", HandshakeAddr: "a:1"},
		{Name: "", HandshakeAddr: "x:1"},  // 空名
		{Name: "b", HandshakeAddr: ""},    // 空地址
		{Name: "a", HandshakeAddr: "a:2"}, // 重名
	})
	if len(sel.Candidates()) != 1 {
		t.Fatalf("应仅留 1 个有效候选,得 %v", sel.Candidates())
	}
}
