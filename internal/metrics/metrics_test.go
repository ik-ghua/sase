package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecorderAccess(t *testing.T) {
	r := NewRecorder()
	r.Access(OutcomeDeny)
	r.Access(OutcomeDeny)
	r.Access(OutcomeAllow)
	r.ObserveUpstream(5 * time.Millisecond)

	if got := r.AccessValue(OutcomeDeny); got != 2 {
		t.Errorf("deny 应 2,得 %v", got)
	}
	if got := r.AccessValue(OutcomeAllow); got != 1 {
		t.Errorf("allow 应 1,得 %v", got)
	}

	// /metrics 暴露
	rr := httptest.NewRecorder()
	r.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "sase_pop_access_total") || !strings.Contains(body, `outcome="deny"`) {
		t.Fatalf("/metrics 应含 access_total 与 deny 序列,得:\n%s", body)
	}
	if !strings.Contains(body, "sase_pop_upstream_seconds") {
		t.Error("/metrics 应含 upstream_seconds 直方图")
	}
}

func TestNilRecorderNoop(_ *testing.T) {
	var r *Recorder                // nil
	r.Access(OutcomeDeny)          // 不应 panic
	r.ObserveUpstream(time.Second) // 不应 panic
}
