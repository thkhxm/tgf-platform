//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：构造配置 / access_token 缓存单测——httptest mock 平台应答，不打真实抖音
//2026/6/11
//***************************************************

package douyin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// newTestDouyin 构造两个 base 都指向同一 httptest server 的实例。
func newTestDouyin(t *testing.T, baseURL string, mutate func(*Config)) *Douyin {
	t.Helper()
	cfg := Config{
		AppID:            "tt0123456789abcdef",
		AppSecret:        "secret_test",
		PayCallbackToken: "cb_token_test",
		MinigameBaseURL:  baseURL,
		ToutiaoBaseURL:   baseURL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return d
}

// tokenHandler 返回成功 token 应答并自增计数。
func tokenHandler(calls *atomic.Int64, token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"err_no": 0, "err_tips": "success",
			"data": map[string]any{"access_token": token, "expires_in": 7200},
		})
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"缺 AppID", Config{AppSecret: "s"}},
		{"缺 AppSecret", Config{AppID: "tt1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("期望配置校验失败，实际返回 nil error")
			}
		})
	}
	t.Run("MustNew 非法配置 panic", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("期望 panic")
			}
		}()
		MustNew(Config{})
	})
	t.Run("Name", func(t *testing.T) {
		d := MustNew(Config{AppID: "tt1", AppSecret: "s"})
		if got := d.Name(); got != "douyin" {
			t.Fatalf("Name() = %q, 期望 \"douyin\"", got)
		}
	})
}

// TestAccessTokenRequest 断言 v2/token 请求构造（路径 / 方法 / JSON 字段）。
func TestAccessTokenRequest(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, 期望 POST", r.Method)
		}
		if r.URL.Path != "/mgplatform/api/apps/v2/token" {
			t.Errorf("path = %s, 期望 /mgplatform/api/apps/v2/token", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %s, 期望 application/json", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("解析请求体失败: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"err_no":0,"err_tips":"success","data":{"access_token":"tok-1","expires_in":7200}}`))
	}))
	defer srv.Close()

	d := newTestDouyin(t, srv.URL, nil)
	tok, err := d.accessToken(context.Background())
	if err != nil {
		t.Fatalf("accessToken 失败: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("token = %q, 期望 tok-1", tok)
	}
	want := map[string]string{
		"appid":      "tt0123456789abcdef",
		"secret":     "secret_test",
		"grant_type": "client_credential",
	}
	for k, v := range want {
		if gotBody[k] != v {
			t.Errorf("请求体 %s = %q, 期望 %q", k, gotBody[k], v)
		}
	}
}

// TestAccessTokenCache 缓存行为：未过期复用（只打一次平台）、临近过期刷新、
// invalidateToken 强制刷新。
func TestAccessTokenCache(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(tokenHandler(&calls, "tok-cache"))
	defer srv.Close()

	d := newTestDouyin(t, srv.URL, nil)
	now := time.Now()
	d.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if _, err := d.accessToken(context.Background()); err != nil {
			t.Fatalf("第 %d 次 accessToken 失败: %v", i+1, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("未过期复用：平台被调 %d 次, 期望 1 次（重复获取会把上一个 token 有效期缩到 5 分钟）", got)
	}

	// 推进到「距过期不足刷新余量」（7200s - 4min < margin 5min）→ 应刷新。
	now = now.Add(7200*time.Second - 4*time.Minute)
	if _, err := d.accessToken(context.Background()); err != nil {
		t.Fatalf("过期刷新失败: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("临近过期应刷新：平台被调 %d 次, 期望 2 次", got)
	}

	// invalidateToken 后强制刷新。
	d.invalidateToken()
	if _, err := d.accessToken(context.Background()); err != nil {
		t.Fatalf("invalidate 后刷新失败: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("invalidate 后应刷新：平台被调 %d 次, 期望 3 次", got)
	}
}

// TestAccessTokenErrors 平台错误码映射（错误码表见 token.go accessTokenPath 注释）。
func TestAccessTokenErrors(t *testing.T) {
	tests := []struct {
		name          string
		respBody      string
		respStatus    int
		wantCode      string
		wantRetryable bool
	}{
		{"40017 secret 错误", `{"err_no":40017,"err_tips":"bad secret"}`, 200, "40017", false},
		{"40015 appid 错误", `{"err_no":40015,"err_tips":"bad appid"}`, 200, "40015", false},
		{"40020 grant_type 错误", `{"err_no":40020,"err_tips":"bad grant_type"}`, 200, "40020", false},
		{"-1 系统错误可重试", `{"err_no":-1,"err_tips":"system error"}`, 200, "-1", true},
		{"缺 access_token 字段", `{"err_no":0,"err_tips":"success","data":{}}`, 200, "", false},
		{"HTTP 500 可重试", `boom`, 500, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.respStatus)
				_, _ = w.Write([]byte(tc.respBody))
			}))
			defer srv.Close()

			d := newTestDouyin(t, srv.URL, nil)
			_, err := d.accessToken(context.Background())
			if err == nil {
				t.Fatal("期望失败，实际成功")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error, 实际 %T: %v", err, err)
			}
			if pe.Code != tc.wantCode {
				t.Errorf("Code = %q, 期望 %q", pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetryable)
			}
			if pe.Platform != "douyin" || pe.Op != "get_access_token" {
				t.Errorf("Platform/Op = %s/%s, 期望 douyin/get_access_token", pe.Platform, pe.Op)
			}
		})
	}
}
