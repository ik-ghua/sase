package pop

// 白盒单测(无 DB):锁定 ingress 头过滤的安全契约——Authorization(SASE 凭证)与逐跳头、
// X-Sase-* 控制头必须被剥除,绝不透传给内网上游;普通业务头多值保留。

import (
	"net/http"
	"testing"
)

func TestFilterForwardHeadersStripsSensitive(t *testing.T) {
	src := http.Header{
		"Authorization":     {"Bearer secret-cred"}, // SASE 凭证,必剥
		"Connection":        {"keep-alive"},         // 逐跳头,必剥
		"Transfer-Encoding": {"chunked"},            // 逐跳头,必剥
		"X-Sase-Inspect":    {"1"},                  // SASE 控制头,必剥
		"Content-Type":      {"application/json"},   // 业务头,保留
		"X-Client-Hint":     {"a", "b"},             // 多值业务头,保留全部值
	}
	out := filterForwardHeaders(src)

	for _, k := range []string{"Authorization", "Connection", "Transfer-Encoding", "X-Sase-Inspect"} {
		if v := out.Get(k); v != "" {
			t.Errorf("敏感/逐跳头 %s 必须被剥除,却得 %q", k, v)
		}
	}
	if out.Get("Content-Type") != "application/json" {
		t.Errorf("业务头 Content-Type 应保留,得 %q", out.Get("Content-Type"))
	}
	if got := out.Values("X-Client-Hint"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("多值业务头应全部保留,得 %v", got)
	}
}

// TestFilterForwardHeadersNotAliasInput 验证返回的是新 map,不与入参共享底层(并发安全)。
func TestFilterForwardHeadersNotAliasInput(t *testing.T) {
	src := http.Header{"Content-Type": {"text/plain"}}
	out := filterForwardHeaders(src)
	out.Set("Content-Type", "mutated")
	if src.Get("Content-Type") != "text/plain" {
		t.Error("过滤后修改返回值不应影响入参(不应共享底层 slice/map)")
	}
}
