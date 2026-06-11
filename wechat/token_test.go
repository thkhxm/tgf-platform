//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：内置 stable_token 管理器单测——请求构造 / 缓存 / 过期刷新 / 错误分类 / 钩子替换
//2026/6/11
//***************************************************

package wechat

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

// TestAccessTokenStable 成功路径：断言请求构造（POST /cgi-bin/stable_token、
// JSON 体三字段）与缓存行为（有效期内不重复请求、过期后刷新）。
func TestAccessTokenStable(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, 期望 POST", r.Method)
		}
		if r.URL.Path != "/cgi-bin/stable_token" {
			t.Errorf("path = %s, 期望 /cgi-bin/stable_token", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("请求体解析失败: %v", err)
		}
		if body["grant_type"] != "client_credential" {
			t.Errorf("grant_type = %v, 期望 client_credential", body["grant_type"])
		}
		if body["appid"] != "wx_appid_test" || body["secret"] != "wx_secret_test" {
			t.Errorf("appid/secret = %v/%v", body["appid"], body["secret"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ACCESS_TOKEN_1","expires_in":7200}`))
	}))
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, nil)
	// 固定时钟便于断言缓存过期逻辑。
	base := time.Unix(1_770_000_000, 0)
	now := base
	wc.now = func() time.Time { return now }

	tok, err := wc.accessToken(context.Background())
	if err != nil {
		t.Fatalf("accessToken 失败: %v", err)
	}
	if tok != "ACCESS_TOKEN_1" {
		t.Fatalf("token = %q", tok)
	}
	// 有效期内重复调用走缓存。
	if _, err := wc.accessToken(context.Background()); err != nil {
		t.Fatalf("二次 accessToken 失败: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("有效期内重复调用发起了 %d 次 HTTP 请求, 期望 1", got)
	}
	// 越过本地缓存有效期（expires_in - 60s 余量）后刷新。
	now = base.Add(7200*time.Second - 30*time.Second)
	if _, err := wc.accessToken(context.Background()); err != nil {
		t.Fatalf("过期后 accessToken 失败: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("缓存过期后请求次数 = %d, 期望 2", got)
	}
}

// TestAccessTokenErrors 错误路径：errcode 分类与字段缺失。
func TestAccessTokenErrors(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantCode      string
		wantRetryable bool
	}{
		{"40013 invalid appid（确定性）", `{"errcode":40013,"errmsg":"invalid appid"}`, "40013", false},
		{"40125 secret 错误（确定性）", `{"errcode":40125,"errmsg":"invalid secret"}`, "40125", false},
		{"-1 系统繁忙（可重试）", `{"errcode":-1,"errmsg":"system error"}`, "-1", true},
		{"缺 access_token（协议异常）", `{"expires_in":7200}`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			wc := newTestWeChat(t, srv.URL, nil)
			_, err := wc.accessToken(context.Background())
			if err == nil {
				t.Fatal("期望错误")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error，实际 %T", err)
			}
			if pe.Op != "stable_token" || pe.Code != tc.wantCode {
				t.Errorf("Op/Code = %s/%s, 期望 stable_token/%s", pe.Op, pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetryable)
			}
		})
	}
}

// TestAccessTokenFunc 注入 Config.AccessTokenFunc 时完全绕过内置管理器。
func TestAccessTokenFunc(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, func(c *Config) {
		c.AccessTokenFunc = func(ctx context.Context) (string, error) { return "INJECTED_TOKEN", nil }
	})
	tok, err := wc.accessToken(context.Background())
	if err != nil {
		t.Fatalf("accessToken 失败: %v", err)
	}
	if tok != "INJECTED_TOKEN" {
		t.Errorf("token = %q, 期望 INJECTED_TOKEN", tok)
	}
	if called {
		t.Error("注入 AccessTokenFunc 后不应请求平台")
	}
}
