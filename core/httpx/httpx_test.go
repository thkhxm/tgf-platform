//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/httpx 单测：GET/POST/表单 / 重试退避 / 上下文取消 / 响应体上限（httptest mock）
//2026/6/11
//***************************************************

package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const canarySecret = "canary-session-key-do-not-log"

type echoingJSONValue struct{}

func (*echoingJSONValue) UnmarshalJSON(data []byte) error {
	return errors.New("echoed input: " + string(data))
}

var errJSONSentinel = errors.New("sentinel: " + canarySecret)

type sentinelEchoingJSONError struct {
	data string
}

func (e *sentinelEchoingJSONError) Error() string {
	return "echoed input: " + e.data
}

func (*sentinelEchoingJSONError) Unwrap() error {
	return errJSONSentinel
}

type sentinelEchoingJSONValue struct{}

func (*sentinelEchoingJSONValue) UnmarshalJSON(data []byte) error {
	return &sentinelEchoingJSONError{data: string(data)}
}

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

func TestSafeSummaryRedactsResponseBody(t *testing.T) {
	body := []byte(`{"access_token":"` + canarySecret + `"}`)
	resp := &Response{
		StatusCode: http.StatusUnauthorized,
		Header: http.Header{
			"Content-Type": {`application/json; charset=utf-8; secret="` + canarySecret + `"`},
		},
		Body: body,
	}

	summary := resp.SafeSummary()
	if strings.Contains(summary, canarySecret) {
		t.Fatalf("安全摘要泄露 canary secret: %s", summary)
	}
	for _, want := range []string{`status=401`, `content_type="json"`, `body_bytes=`} {
		if !strings.Contains(summary, want) {
			t.Errorf("SafeSummary() = %q，缺少 %q", summary, want)
		}
	}
	// String 的原始行为是公开兼容面；修复只迁移日志/错误调用方，不改变消费语义。
	if got := resp.String(); got != string(body) {
		t.Errorf("String() 兼容行为改变: got %q", got)
	}
}

func TestSafeSummaryClassifiesContentTypeWithoutEchoingRemoteTokens(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        string
	}{
		{"缺失", "", "unknown"},
		{"JSON", "application/json; charset=utf-8", "json"},
		{"JSON suffix", "application/problem+json", "json"},
		{"HTML", "text/html", "html"},
		{"XHTML", "application/xhtml+xml", "html"},
		{"文本", "text/plain", "text"},
		{"XML", "application/atom+xml", "xml"},
		{"二进制", "application/octet-stream", "binary"},
		{"二进制顶级类型", "image/png", "binary"},
		{"其他", "application/protobuf", "other"},
		{"canary 位于 type", canarySecret + "/json", "json"},
		{"canary 位于 subtype", "application/" + canarySecret, "other"},
		{"canary 位于 JSON suffix subtype", "application/" + canarySecret + "+json", "json"},
		{"非法参数", `application/json; secret="` + canarySecret, "invalid"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			if tc.contentType != "" {
				header.Set("Content-Type", tc.contentType)
			}
			resp := &Response{StatusCode: http.StatusBadGateway, Header: header, Body: []byte(canarySecret)}
			summary := resp.SafeSummary()
			if strings.Contains(summary, canarySecret) {
				t.Fatalf("SafeSummary() 回显远端 canary: %q", summary)
			}
			if want := `content_type="` + tc.want + `"`; !strings.Contains(summary, want) {
				t.Errorf("SafeSummary() = %q，期望包含 %q", summary, want)
			}
			if got := safeContentType(header); got != tc.want {
				t.Errorf("safeContentType() = %q，期望 %q", got, tc.want)
			}
		})
	}
}

func TestDecodeJSONErrorRedactsBodyAndEchoingCause(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		out        any
		wantSyntax bool
		wantType   bool
	}{
		{"语法错误", []byte(`{"access_token":"` + canarySecret + `"`), &map[string]any{}, true, false},
		{"类型错误", []byte(`{"count":"` + canarySecret + `"}`), &struct {
			Count int `json:"count"`
		}{}, false, true},
		{"自定义解析器回显原文", []byte(`"` + canarySecret + `"`), &echoingJSONValue{}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := DecodeJSON(tc.data, tc.out)
			if err == nil {
				t.Fatal("期望 JSON 解析错误")
			}
			for chainErr := err; chainErr != nil; chainErr = errors.Unwrap(chainErr) {
				if strings.Contains(chainErr.Error(), canarySecret) {
					t.Fatalf("错误链泄露 canary secret: %v", chainErr)
				}
			}
			if !strings.Contains(err.Error(), SafeBodySummary(tc.data)) {
				t.Errorf("解析错误缺少安全长度摘要: %v", err)
			}
			var syntaxErr *json.SyntaxError
			if got := errors.As(err, &syntaxErr); got != tc.wantSyntax {
				t.Errorf("errors.As(*json.SyntaxError) = %v，期望 %v", got, tc.wantSyntax)
			}
			var typeErr *json.UnmarshalTypeError
			if got := errors.As(err, &typeErr); got != tc.wantType {
				t.Errorf("errors.As(*json.UnmarshalTypeError) = %v，期望 %v", got, tc.wantType)
			}
			if !tc.wantSyntax && !tc.wantType && errors.Unwrap(err) != nil {
				t.Errorf("未知自定义 cause 不应进入安全错误链: %v", errors.Unwrap(err))
			}
		})
	}
}

func TestDecodeJSONErrorPreservesSentinelWithoutExposingCustomCause(t *testing.T) {
	data := []byte(`"` + canarySecret + `"`)
	err := DecodeJSON(data, &sentinelEchoingJSONValue{})
	if err == nil {
		t.Fatal("期望 JSON 解析错误")
	}
	if !errors.Is(err, errJSONSentinel) {
		t.Fatal("errors.Is 应保留自定义 UnmarshalJSON 错误的 sentinel 兼容性")
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("未知自定义 cause 不应进入安全错误链: %v", unwrapped)
	}
	var customErr *sentinelEchoingJSONError
	if errors.As(err, &customErr) {
		t.Fatalf("errors.As 不应暴露未知自定义 cause: %v", customErr)
	}
	for chainErr := err; chainErr != nil; chainErr = errors.Unwrap(chainErr) {
		if strings.Contains(chainErr.Error(), canarySecret) {
			t.Fatalf("错误链泄露 canary secret: %v", chainErr)
		}
	}
}

func TestDecodeJSONSyntaxErrorDoesNotExposeInvalidCharacter(t *testing.T) {
	data := []byte("Z" + canarySecret)
	err := DecodeJSON(data, &map[string]any{})
	if err == nil {
		t.Fatal("期望 JSON 语法错误")
	}
	for chainErr := err; chainErr != nil; chainErr = errors.Unwrap(chainErr) {
		if strings.Contains(chainErr.Error(), canarySecret) || strings.Contains(chainErr.Error(), "invalid character 'Z'") {
			t.Fatalf("错误链泄露无效输入字符或正文: %v", chainErr)
		}
	}
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Fatal("errors.As 应保留 *json.SyntaxError 类型兼容性")
	}
	if syntaxErr.Offset != 1 {
		t.Fatalf("SyntaxError.Offset = %d, want 1", syntaxErr.Offset)
	}
	if strings.Contains(syntaxErr.Error(), "'Z'") {
		t.Fatalf("清洗后的 SyntaxError 回显输入字符: %q", syntaxErr.Error())
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
