//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/httpx 单测：GET/POST/表单 / 重试退避 / 上下文取消 / 响应体上限（httptest mock）
//2026/6/11
//***************************************************

package httpx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGetMergesQueryAndHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		// URL 原有参数与 query 参数都应在
		if r.URL.Query().Get("appid") != "a1" || r.URL.Query().Get("code") != "c1" {
			t.Errorf("查询参数合并不符: %s", r.URL.RawQuery)
		}
		if r.Header.Get("X-Req") != "req-v" {
			t.Errorf("每请求 header 未带上: %q", r.Header.Get("X-Req"))
		}
		if r.Header.Get("X-Default") != "def-v" {
			t.Errorf("client 默认 header 未带上: %q", r.Header.Get("X-Default"))
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := New(WithDefaultHeader("X-Default", "def-v"))
	h := http.Header{}
	h.Set("X-Req", "req-v")
	resp, err := c.Get(context.Background(), srv.URL+"?appid=a1", url.Values{"code": {"c1"}}, h)
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if !resp.OK() {
		t.Errorf("status = %d, want 2xx", resp.StatusCode)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := resp.JSON(&out); err != nil || !out.OK {
		t.Errorf("响应解析不符: %+v, err=%v", out, err)
	}
}

func TestPerRequestHeaderOverridesDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Both"); got != "per-request" {
			t.Errorf("同名 header 应以每请求值为准, got %q", got)
		}
	}))
	defer srv.Close()

	c := New(WithDefaultHeader("X-Both", "client-default"))
	h := http.Header{}
	h.Set("X-Both", "per-request")
	if _, err := c.Get(context.Background(), srv.URL, nil, h); err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
}

func TestPostJSON(t *testing.T) {
	type reqBody struct {
		OrderID string `json:"order_id"`
		Amount  int64  `json:"amount"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var in reqBody
		if err := DecodeJSON(mustReadBody(t, r), &in); err != nil {
			t.Errorf("服务端解析请求体失败: %v", err)
		}
		if in.OrderID != "o-1" || in.Amount != 600 {
			t.Errorf("请求体不符: %+v", in)
		}
		w.Write([]byte(`{"paid":true}`))
	}))
	defer srv.Close()

	resp, err := New().PostJSON(context.Background(), srv.URL, reqBody{OrderID: "o-1", Amount: 600}, nil)
	if err != nil {
		t.Fatalf("PostJSON 失败: %v", err)
	}
	var out struct {
		Paid bool `json:"paid"`
	}
	if err := resp.JSON(&out); err != nil || !out.Paid {
		t.Errorf("响应解析不符: %+v, err=%v", out, err)
	}
}

func TestPostJSONRawBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := string(mustReadBody(t, r))
		if body != `{"raw":1}` {
			t.Errorf("原始字节体应原样发送, got %q", body)
		}
	}))
	defer srv.Close()

	if _, err := New().PostJSON(context.Background(), srv.URL, []byte(`{"raw":1}`), nil); err != nil {
		t.Fatalf("PostJSON([]byte) 失败: %v", err)
	}
}

func TestPostForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("解析表单失败: %v", err)
		}
		if r.PostForm.Get("grant_type") != "client_credential" {
			t.Errorf("表单字段不符: %v", r.PostForm)
		}
	}))
	defer srv.Close()

	form := url.Values{"grant_type": {"client_credential"}}
	if _, err := New().PostForm(context.Background(), srv.URL, form, nil); err != nil {
		t.Fatalf("PostForm 失败: %v", err)
	}
}

func TestNoRetryByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	resp, err := New().Get(context.Background(), srv.URL, nil, nil)
	if err != nil {
		t.Fatalf("传输层成功时不应返回 error: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("默认不重试，应只请求 1 次，实际 %d 次", got)
	}
}

func TestRetryOn5xxThenSuccess(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := New(WithRetry(3, time.Millisecond))
	resp, err := c.Get(context.Background(), srv.URL, nil, nil)
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if !resp.OK() || resp.String() != "ok" {
		t.Errorf("最终应成功, status=%d body=%q", resp.StatusCode, resp.String())
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("应请求 3 次（2 次失败 + 1 次成功），实际 %d 次", got)
	}
}

func TestRetryExhaustedReturnsLastResponse(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(WithRetry(2, time.Millisecond))
	resp, err := c.Get(context.Background(), srv.URL, nil, nil)
	if err != nil {
		t.Fatalf("重试耗尽但传输层成功，应返回最后一次响应而非 error: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("应请求 3 次（1 首次 + 2 重试），实际 %d 次", got)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(WithRetry(3, time.Millisecond))
	resp, err := c.Get(context.Background(), srv.URL, nil, nil)
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("4xx 是确定性失败不应重试，实际请求 %d 次", got)
	}
}

func TestContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := New().Get(ctx, srv.URL, nil, nil); err == nil {
		t.Error("context 超时应返回错误")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("应在 context 超时附近返回，实际耗时 %v", elapsed)
	}
}

func TestMaxBodySize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()

	if _, err := New(WithMaxBodySize(10)).Get(context.Background(), srv.URL, nil, nil); err == nil {
		t.Error("响应体超限应返回错误")
	}
	// 恰好等于上限 → 不报错
	resp, err := New(WithMaxBodySize(100)).Get(context.Background(), srv.URL, nil, nil)
	if err != nil {
		t.Fatalf("恰好等于上限不应报错: %v", err)
	}
	if len(resp.Body) != 100 {
		t.Errorf("body 长度 = %d, want 100", len(resp.Body))
	}
}

func TestDecodeJSONErrorSnippet(t *testing.T) {
	var v map[string]any
	err := DecodeJSON([]byte("<html>bad gateway</html>"), &v)
	if err == nil {
		t.Fatal("非 JSON 应返回错误")
	}
	if !strings.Contains(err.Error(), "<html>") {
		t.Errorf("错误信息应附原文片段便于定位: %v", err)
	}
}

func TestJoinURL(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"https://api.example.com", "v1/order", "https://api.example.com/v1/order"},
		{"https://api.example.com/", "/v1/order", "https://api.example.com/v1/order"},
		{"https://api.example.com/", "v1/order", "https://api.example.com/v1/order"},
	}
	for _, tc := range cases {
		if got := JoinURL(tc.base, tc.path); got != tc.want {
			t.Errorf("JoinURL(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}

// mustReadBody 读取请求体（测试辅助）。
func mustReadBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("读取请求体失败: %v", err)
	}
	return data
}
