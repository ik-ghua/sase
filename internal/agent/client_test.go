package agent_test

// 客户端全 HTTP 路径单测(无 DB、无 mTLS,httptest 模拟 PoP 接入面):
// 验证 agent.Do 发任意方法 + 请求头 + 请求体,并把 SASE 凭证作 Authorization 头注入;
// 验证 agent.Access(GET 便捷封装)向后兼容。

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ikuai8/sase/internal/agent"
)

func TestDoForwardsMethodHeaderBody(t *testing.T) {
	var gotMethod, gotHint, gotAuthz, gotApp, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHint = r.Header.Get("X-Client-Hint")
		gotAuthz = r.Header.Get("Authorization")
		gotApp = r.URL.Query().Get("app")
		gotPath = r.URL.Query().Get("path")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("X-Resp", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("upstream-said-hi"))
	}))
	defer srv.Close()

	res, err := agent.Do(context.Background(), srv.URL, nil, "tok-abc", agent.Request{
		App:    "app1",
		Path:   "/api/x",
		Method: http.MethodPost,
		Header: http.Header{"X-Client-Hint": {"h1"}},
		Body:   []byte("payload"),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method 应透传 POST,得 %q", gotMethod)
	}
	if gotHint != "h1" {
		t.Errorf("自定义请求头应透传,得 %q", gotHint)
	}
	if gotAuthz != "Bearer tok-abc" {
		t.Errorf("SASE 凭证应作 Authorization 头注入,得 %q", gotAuthz)
	}
	if gotApp != "app1" || gotPath != "/api/x" {
		t.Errorf("app/path 应进 query,得 app=%q path=%q", gotApp, gotPath)
	}
	if string(gotBody) != "payload" {
		t.Errorf("请求体应透传,得 %q", string(gotBody))
	}
	if res.StatusCode != http.StatusCreated {
		t.Errorf("响应状态码应回传 201,得 %d", res.StatusCode)
	}
	if res.Header.Get("X-Resp") != "ok" {
		t.Errorf("响应头应回传,得 %q", res.Header.Get("X-Resp"))
	}
	if string(res.Body) != "upstream-said-hi" {
		t.Errorf("响应体应回传,得 %q", string(res.Body))
	}
}

// TestAccessBackwardCompat 验证旧 GET 封装签名仍工作。
func TestAccessBackwardCompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Access 应发 GET,得 %q", r.Method)
		}
		_, _ = w.Write([]byte("body:" + r.URL.Query().Get("path")))
	}))
	defer srv.Close()

	st, body, err := agent.Access(context.Background(), srv.URL, nil, "tok", "app1", "/p")
	if err != nil {
		t.Fatalf("Access: %v", err)
	}
	if st != http.StatusOK || !strings.Contains(body, "body:/p") {
		t.Fatalf("Access 向后兼容失败:st=%d body=%q", st, body)
	}
}

// TestDoDefaultMethodGET 验证 Method 空时默认 GET。
func TestDoDefaultMethodGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Method))
	}))
	defer srv.Close()
	res, err := agent.Do(context.Background(), srv.URL, nil, "tok", agent.Request{App: "a"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(res.Body) != http.MethodGet {
		t.Fatalf("Method 空应默认 GET,上游收到 %q", string(res.Body))
	}
}
