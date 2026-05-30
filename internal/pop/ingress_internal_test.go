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

// TestFilterForwardHeadersDynamicHopByHop 验证 RFC 7230 §6.1 动态逐跳头(请求方向):
// Connection 头值点名的字段(含大小写不规范、多值、逗号分隔、空 token)一并被剥除,
// 而未被点名的普通业务头透传不受影响。
func TestFilterForwardHeadersDynamicHopByHop(t *testing.T) {
	src := http.Header{
		"Connection":   {"keep-alive, X-Custom-Foo", "x-custom-bar"}, // 点名两个动态逐跳头(含小写)
		"X-Custom-Foo": {"should-be-stripped"},                       // 被 Connection 点名,必剥
		"X-Custom-Bar": {"also-stripped"},                            // 第二值点名(小写),必剥
		"X-Keep-Me":    {"v"},                                        // 未点名业务头,保留
		"Content-Type": {"application/json"},                         // 普通业务头,保留
		"Upgrade":      {"websocket"},                                // 静态逐跳头,必剥
	}
	out := filterForwardHeaders(src)

	for _, k := range []string{"Connection", "X-Custom-Foo", "X-Custom-Bar", "Upgrade"} {
		if v := out.Get(k); v != "" {
			t.Errorf("动态/静态逐跳头 %s 必须被剥除,却得 %q", k, v)
		}
	}
	if out.Get("X-Keep-Me") != "v" {
		t.Errorf("未被 Connection 点名的业务头 X-Keep-Me 应保留,得 %q", out.Get("X-Keep-Me"))
	}
	if out.Get("Content-Type") != "application/json" {
		t.Errorf("普通业务头 Content-Type 应保留,得 %q", out.Get("Content-Type"))
	}
}

// TestFilterForwardHeadersDynamicHopByHopEmptyTokensSafe 验证 Connection 头含空 token / 仅空白 / 多逗号
// 时不误剥业务头、不 panic(健壮性)。
func TestFilterForwardHeadersDynamicHopByHopEmptyTokensSafe(t *testing.T) {
	src := http.Header{
		"Connection":   {" , , close ,"}, // 空 token + Close 连接选项(非真实业务头名)
		"Content-Type": {"text/plain"},   // 业务头,保留
		"X-Keep":       {"k"},            // 业务头,保留(空 token 不应误剥它)
	}
	out := filterForwardHeaders(src)
	if out.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type 应保留,得 %q", out.Get("Content-Type"))
	}
	if out.Get("X-Keep") != "k" {
		t.Errorf("X-Keep 应保留(空 token 不应误剥),得 %q", out.Get("X-Keep"))
	}
}

// TestConnectionHopByHopResponseDirection 验证 connectionHopByHop 对响应头方向同样解析出动态逐跳头集合
// (writeResponse 据此剥除)。
func TestConnectionHopByHopResponseDirection(t *testing.T) {
	respHdr := http.Header{
		"Connection":   {"X-Resp-Hop"},
		"X-Resp-Hop":   {"v"},
		"Content-Type": {"text/html"},
	}
	set := connectionHopByHop(respHdr)
	if !set["X-Resp-Hop"] {
		t.Error("响应方向应识别出 Connection 点名的 X-Resp-Hop 为动态逐跳头")
	}
	if set["Content-Type"] {
		t.Error("未被点名的 Content-Type 不应进动态逐跳头集合")
	}
	// 无 Connection 头 → 返回 nil(零分配快路径)
	if connectionHopByHop(http.Header{"Content-Type": {"x"}}) != nil {
		t.Error("无 Connection 头应返回 nil")
	}
}
