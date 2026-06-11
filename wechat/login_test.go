//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：VerifyLogin 单测——httptest mock 平台应答（成功 / 各错误码 / 字段缺失），不打真实微信
//2026/6/11
//***************************************************

package wechat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// newTestWeChat 构造指向 httptest server 的实例。
func newTestWeChat(t *testing.T, baseURL string, mutate func(*Config)) *WeChat {
	t.Helper()
	cfg := Config{
		AppID:     "wx_appid_test",
		AppSecret: "wx_secret_test",
		BaseURL:   baseURL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	w, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return w
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"缺 AppID", Config{AppSecret: "s"}},
		{"缺 AppSecret", Config{AppID: "a"}},
		{"Env 非法", Config{AppID: "a", AppSecret: "s", Env: 2}},
		{"BizID 非法", Config{AppID: "a", AppSecret: "s", BizID: 3}},
		{"AuditScene 非法", Config{AppID: "a", AppSecret: "s", AuditScene: 6}},
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
		w := MustNew(Config{AppID: "a", AppSecret: "s"})
		if got := w.Name(); got != "wechat" {
			t.Fatalf("Name() = %q, 期望 \"wechat\"", got)
		}
	})
	t.Run("AuditScene 默认 1 资料", func(t *testing.T) {
		w := MustNew(Config{AppID: "a", AppSecret: "s"})
		if w.cfg.AuditScene != SceneProfile {
			t.Fatalf("AuditScene 默认 = %d, 期望 %d", w.cfg.AuditScene, SceneProfile)
		}
	})
}

// TestVerifyLoginSuccess 成功路径：断言请求构造（路径 / 方法 / 查询参数）与身份映射。
func TestVerifyLoginSuccess(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, 期望 GET", r.Method)
		}
		if r.URL.Path != "/sns/jscode2session" {
			t.Errorf("path = %s, 期望 /sns/jscode2session", r.URL.Path)
		}
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"openid":"openid-1","session_key":"sk-base64==","unionid":"unionid-9"}`))
	}))
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, nil)
	identity, err := wc.VerifyLogin(context.Background(), "js-code-1")
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}

	// 请求查询参数断言（官方四参数）
	wantQuery := map[string]string{
		"appid":      "wx_appid_test",
		"secret":     "wx_secret_test",
		"js_code":    "js-code-1",
		"grant_type": "authorization_code",
	}
	for k, want := range wantQuery {
		if got := gotQuery.Get(k); got != want {
			t.Errorf("query[%s] = %q, 期望 %q", k, got, want)
		}
	}

	// 身份映射断言
	if identity.Platform != "wechat" {
		t.Errorf("Platform = %q", identity.Platform)
	}
	if identity.OpenID != "openid-1" {
		t.Errorf("OpenID = %q, 期望 openid-1", identity.OpenID)
	}
	if identity.SessionKey != "sk-base64==" {
		t.Errorf("SessionKey = %q, 期望 sk-base64==", identity.SessionKey)
	}
	if identity.UnionID != "unionid-9" {
		t.Errorf("UnionID = %q, 期望 unionid-9", identity.UnionID)
	}
}

// TestVerifyLoginNoUnionID 未绑定开放平台时 unionid 缺省为空。
func TestVerifyLoginNoUnionID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"openid":"openid-1","session_key":"sk"}`))
	}))
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, nil)
	identity, err := wc.VerifyLogin(context.Background(), "js-code-1")
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}
	if identity.UnionID != "" {
		t.Errorf("UnionID = %q, 期望空", identity.UnionID)
	}
}

// TestVerifyLoginErrors 错误路径：平台错误码 / HTTP 异常 / 字段缺失 / 非 JSON，
// 断言错误分类（Code / HTTPStatus / Retryable）。
func TestVerifyLoginErrors(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		body          string
		wantCode      string
		wantRetryable bool
	}{
		{
			name:          "40029 code 无效（确定性失败）",
			status:        http.StatusOK, // 微信业务错误通常 HTTP 200
			body:          `{"errcode":40029,"errmsg":"invalid code"}`,
			wantCode:      "40029",
			wantRetryable: false,
		},
		{
			name:          "40226 高风险用户拦截（确定性失败）",
			status:        http.StatusOK,
			body:          `{"errcode":40226,"errmsg":"code blocked"}`,
			wantCode:      "40226",
			wantRetryable: false,
		},
		{
			name:          "-1 系统繁忙（可重试）",
			status:        http.StatusOK,
			body:          `{"errcode":-1,"errmsg":"system error"}`,
			wantCode:      "-1",
			wantRetryable: true,
		},
		{
			name:          "45011 分钟级限频（可重试）",
			status:        http.StatusOK,
			body:          `{"errcode":45011,"errmsg":"api minute-quota reach limit"}`,
			wantCode:      "45011",
			wantRetryable: true,
		},
		{
			name:          "5xx 非 JSON（暂时性，可重试）",
			status:        http.StatusBadGateway,
			body:          `<html>bad gateway</html>`,
			wantCode:      "",
			wantRetryable: true,
		},
		{
			name:          "200 但缺 session_key（协议异常）",
			status:        http.StatusOK,
			body:          `{"openid":"o1"}`,
			wantCode:      "",
			wantRetryable: false,
		},
		{
			name:          "200 但缺 openid（协议异常）",
			status:        http.StatusOK,
			body:          `{"session_key":"sk"}`,
			wantCode:      "",
			wantRetryable: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			wc := newTestWeChat(t, srv.URL, nil)
			_, err := wc.VerifyLogin(context.Background(), "code-x")
			if err == nil {
				t.Fatal("期望返回错误，实际 nil")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error，实际 %T: %v", err, err)
			}
			if pe.Platform != "wechat" || pe.Op != "code2session" {
				t.Errorf("Platform/Op = %s/%s", pe.Platform, pe.Op)
			}
			if pe.Code != tc.wantCode {
				t.Errorf("Code = %q, 期望 %q", pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetryable)
			}
			if pe.HTTPStatus != tc.status {
				t.Errorf("HTTPStatus = %d, 期望 %d", pe.HTTPStatus, tc.status)
			}
			if errs.IsRetryable(err) != tc.wantRetryable {
				t.Errorf("errs.IsRetryable = %v, 期望 %v", errs.IsRetryable(err), tc.wantRetryable)
			}
		})
	}

	t.Run("空 credential 不发请求", func(t *testing.T) {
		called := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		defer srv.Close()
		wc := newTestWeChat(t, srv.URL, nil)
		if _, err := wc.VerifyLogin(context.Background(), ""); err == nil {
			t.Fatal("期望错误")
		}
		if called {
			t.Error("空 credential 不应发起 HTTP 请求")
		}
	})

	t.Run("网络错误（可重试）", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // 立即关闭制造连接拒绝
		wc := newTestWeChat(t, srv.URL, nil)
		_, err := wc.VerifyLogin(context.Background(), "code-x")
		if err == nil {
			t.Fatal("期望网络错误")
		}
		if !errs.IsRetryable(err) {
			t.Errorf("网络错误应可重试: %v", err)
		}
	})
}
