package agentd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestCredStoreAtomicConcurrent:并发 Set/Token/ExpiresAt 无 data race(-race 检测)。
func TestCredStoreAtomicConcurrent(t *testing.T) {
	cs := &credStore{}
	cs.Set("tok0", "jti0", time.Now())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				cs.Set("tok", "jti", time.Now().Add(time.Duration(n)*time.Second))
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = cs.Token()
				_ = cs.JTI()
				_ = cs.ExpiresAt()
			}
		}()
	}
	wg.Wait()
	if cs.Token() != "tok" {
		t.Fatalf("最终 token 应为 tok,得 %q", cs.Token())
	}
}

// TestRefreshCredHTTP:refreshCred 经 httptest 端点拿到新 cred,且 **请求体不含 groups**(只 current_cred_token + posture)。
func TestRefreshCredHTTP(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(refreshResponse{SessionToken: "newtok", SessionJTI: "newjti", ExpiresIn: 1800})
	}))
	defer srv.Close()

	resp, err := refreshCred(context.Background(), srv.URL, srv.Client(), "curtok", "compliant")
	if err != nil {
		t.Fatalf("refreshCred: %v", err)
	}
	if resp.SessionToken != "newtok" || resp.SessionJTI != "newjti" || resp.ExpiresIn != 1800 {
		t.Fatalf("刷新响应错: %+v", resp)
	}
	if gotBody["current_cred_token"] != "curtok" || gotBody["posture"] != "compliant" {
		t.Fatalf("body 应带 current_cred_token + posture,得 %v", gotBody)
	}
	if _, has := gotBody["groups"]; has {
		t.Fatal("刷新请求体**绝不**含 groups(防 body 提权),却出现 groups 字段")
	}
}

// TestRefreshCredNon200:刷新端点返 403(设备撤销/用户停用)→ refreshCred 返错(loop 据此降级)。
func TestRefreshCredNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := refreshCred(context.Background(), srv.URL, srv.Client(), "curtok", ""); err == nil {
		t.Fatal("403 应返错")
	}
}

// TestRunCredRefreshLoopTriggersAndSignals:凭证近过期 → loop 阈值触发刷新 → credStore 更新 + 发重握手信号。
func TestRunCredRefreshLoopTriggersAndSignals(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		// 回一枚远未来到期的新凭证(刷新后阈值不再立即触发,避免打满)。
		_ = json.NewEncoder(w).Encode(refreshResponse{SessionToken: "refreshed", SessionJTI: "rjti", ExpiresIn: 1800})
	}))
	defer srv.Close()

	d := New(Config{Tenant: "t1", Identity: "dev1"}, &stubNetCapture{}, &fakeProbe{}, nil, fakeProber{})
	d.refreshRetryBackoff = 10 * time.Millisecond // 加速:已过阈值时 wait=retry(测试缩短)
	cs := d.creds
	// 初始凭证已过刷新阈值(到期 now → wait = ExpiresAt-lead < 0 → 用 retry 兜底,立即触发刷新)。
	cs.Set("oldtok", "oldjti", time.Now())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.runCredRefreshLoop(ctx, cs, srv.Client(), srv.URL, 10*time.Minute, d.reconnect)

	select {
	case <-d.reconnect:
		// 收到重握手信号 = 刷新成功路径走通。
	case <-time.After(5 * time.Second):
		t.Fatal("应在阈值触发后刷新并发重握手信号")
	}
	if cs.Token() != "refreshed" || cs.JTI() != "rjti" {
		t.Fatalf("刷新后 credStore 应更新为新凭证,得 token=%q jti=%q", cs.Token(), cs.JTI())
	}
	mu.Lock()
	c := calls
	mu.Unlock()
	if c < 1 {
		t.Fatalf("刷新端点应被调至少一次,得 %d", c)
	}
}
