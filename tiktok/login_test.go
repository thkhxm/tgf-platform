//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：VerifyLogin 单测——httptest mock 平台应答（成功 / 各错误码 / 字段缺失），不打真实 TikTok
//2026/6/11
//***************************************************

package tiktok

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// newTestTikTok 构造指向 httptest server 的实例。
func newTestTikTok(t *testing.T, baseURL string, mutate func(*Config)) *TikTok {
	t.Helper()
	cfg := Config{
		ClientKey:    "ck_test",
		ClientSecret: "cs_test",
		BaseURL:      baseURL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	tk, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return tk
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"缺 ClientKey", Config{ClientSecret: "s"}},
		{"缺 ClientSecret", Config{ClientKey: "k"}},
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
		tk := MustNew(Config{ClientKey: "k", ClientSecret: "s"})
		if got := tk.Name(); got != "tiktok" {
			t.Fatalf("Name() = %q, 期望 \"tiktok\"", got)
		}
	})
}

// TestVerifyLoginSuccess 成功路径：断言请求构造（路径 / 方法 / Content-Type /
// 表单字段）与身份映射。
func TestVerifyLoginSuccess(t *testing.T) {
	tests := []struct {
		name            string
		redirectURI     string // 空 = Minis 流程（省略 redirect_uri）
		wantRedirectURI bool
	}{
		{"LoginKit 流程（带 redirect_uri）", "https://game.example.com/cb", true},
		{"Minis 流程（省略 redirect_uri）", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotForm url.Values
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, 期望 POST", r.Method)
				}
				if r.URL.Path != "/v2/oauth/token/" {
					t.Errorf("path = %s, 期望 /v2/oauth/token/", r.URL.Path)
				}
				if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
					t.Errorf("Content-Type = %s, 期望 application/x-www-form-urlencoded", ct)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("ParseForm: %v", err)
				}
				gotForm = r.PostForm
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{
					"access_token":"act.example12345","expires_in":86400,
					"open_id":"open-id-1","refresh_expires_in":31536000,
					"refresh_token":"rft.example","scope":"user.info.basic","token_type":"Bearer"}`))
			}))
			defer srv.Close()

			tk := newTestTikTok(t, srv.URL, func(c *Config) { c.RedirectURI = tc.redirectURI })
			identity, err := tk.VerifyLogin(context.Background(), "code-1")
			if err != nil {
				t.Fatalf("VerifyLogin 失败: %v", err)
			}

			// 请求表单断言
			wantFields := map[string]string{
				"client_key":    "ck_test",
				"client_secret": "cs_test",
				"code":          "code-1",
				"grant_type":    "authorization_code",
			}
			for k, want := range wantFields {
				if got := gotForm.Get(k); got != want {
					t.Errorf("form[%s] = %q, 期望 %q", k, got, want)
				}
			}
			if tc.wantRedirectURI {
				if got := gotForm.Get("redirect_uri"); got != tc.redirectURI {
					t.Errorf("form[redirect_uri] = %q, 期望 %q", got, tc.redirectURI)
				}
			} else if _, has := gotForm["redirect_uri"]; has {
				t.Error("Minis 流程不应携带 redirect_uri（官方明确省略）")
			}

			// 身份映射断言
			if identity.Platform != "tiktok" {
				t.Errorf("Platform = %q", identity.Platform)
			}
			if identity.OpenID != "open-id-1" {
				t.Errorf("OpenID = %q, 期望 open-id-1", identity.OpenID)
			}
			if identity.UnionID != "" {
				t.Errorf("未开 FetchUserInfo，UnionID 应为空，实际 %q", identity.UnionID)
			}
			if identity.SessionKey != "" {
				t.Errorf("TikTok 无 session_key，SessionKey 应为空，实际 %q", identity.SessionKey)
			}
			wantRaw := map[string]string{
				"access_token":       "act.example12345",
				"refresh_token":      "rft.example",
				"expires_in":         "86400",
				"refresh_expires_in": "31536000",
				"scope":              "user.info.basic",
				"token_type":         "Bearer",
			}
			for k, want := range wantRaw {
				if got := identity.Raw[k]; got != want {
					t.Errorf("Raw[%s] = %q, 期望 %q", k, got, want)
				}
			}
		})
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
			name:   "平台 OAuth 错误（确定性失败，不可重试）",
			status: http.StatusBadRequest,
			body:   `{"error":"invalid_grant","error_description":"Authorization code is expired.","log_id":"20260611_abc"}`,
			// 错误码原样透传，业务可按码分支
			wantCode:      "invalid_grant",
			wantRetryable: false,
		},
		{
			name:          "5xx 非 JSON（暂时性，可重试）",
			status:        http.StatusBadGateway,
			body:          `<html>bad gateway</html>`,
			wantCode:      "",
			wantRetryable: true,
		},
		{
			name:          "429 限频（可重试）",
			status:        http.StatusTooManyRequests,
			body:          `{"error":"rate_limit_exceeded","error_description":"too many requests"}`,
			wantCode:      "rate_limit_exceeded",
			wantRetryable: true,
		},
		{
			name:          "200 但缺 open_id（协议异常）",
			status:        http.StatusOK,
			body:          `{"access_token":"act.x","expires_in":86400}`,
			wantCode:      "",
			wantRetryable: false,
		},
		{
			name:          "200 但缺 access_token（协议异常）",
			status:        http.StatusOK,
			body:          `{"open_id":"o1","expires_in":86400}`,
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

			tk := newTestTikTok(t, srv.URL, nil)
			_, err := tk.VerifyLogin(context.Background(), "code-x")
			if err == nil {
				t.Fatal("期望返回错误，实际 nil")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error，实际 %T: %v", err, err)
			}
			if pe.Platform != "tiktok" || pe.Op != "oauth_token" {
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
		tk := newTestTikTok(t, srv.URL, nil)
		if _, err := tk.VerifyLogin(context.Background(), ""); err == nil {
			t.Fatal("期望错误")
		}
		if called {
			t.Error("空 credential 不应发起 HTTP 请求")
		}
	})

	t.Run("网络错误（可重试）", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // 立即关闭制造连接拒绝
		tk := newTestTikTok(t, srv.URL, nil)
		_, err := tk.VerifyLogin(context.Background(), "code-x")
		if err == nil {
			t.Fatal("期望网络错误")
		}
		if !errs.IsRetryable(err) {
			t.Errorf("网络错误应可重试: %v", err)
		}
	})
}

// TestVerifyLoginFetchUserInfo FetchUserInfo 开启时的 user/info 链路。
func TestVerifyLoginFetchUserInfo(t *testing.T) {
	const accessToken = "act.user-token-1"

	// mockServer 返回 token 应答 + 可定制的 user/info 应答。
	mockServer := func(t *testing.T, userInfoStatus int, userInfoBody string, gotAuth *string) *httptest.Server {
		t.Helper()
		mux := http.NewServeMux()
		mux.HandleFunc("/v2/oauth/token/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"` + accessToken + `","expires_in":86400,"open_id":"open-id-1","refresh_token":"r","scope":"user.info.basic","token_type":"Bearer"}`))
		})
		mux.HandleFunc("/v2/user/info/", func(w http.ResponseWriter, r *http.Request) {
			*gotAuth = r.Header.Get("Authorization")
			if got := r.URL.Query().Get("fields"); got != "open_id,union_id" {
				t.Errorf("fields = %q, 期望 open_id,union_id", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(userInfoStatus)
			_, _ = w.Write([]byte(userInfoBody))
		})
		return httptest.NewServer(mux)
	}

	t.Run("成功补取 union_id（且必须用刚换到的用户 token）", func(t *testing.T) {
		var gotAuth string
		srv := mockServer(t, http.StatusOK,
			`{"data":{"user":{"open_id":"open-id-1","union_id":"union-id-9"}},"error":{"code":"ok","message":"","log_id":"lg1"}}`,
			&gotAuth)
		defer srv.Close()

		tk := newTestTikTok(t, srv.URL, func(c *Config) { c.FetchUserInfo = true })
		identity, err := tk.VerifyLogin(context.Background(), "code-1")
		if err != nil {
			t.Fatalf("VerifyLogin 失败: %v", err)
		}
		// 关键断言（历史踩坑点）：user/info 鉴权必须是「用户 OAuth token」，
		// 即 oauth/token 刚返回的 access_token，绝不是 client token。
		if want := "Bearer " + accessToken; gotAuth != want {
			t.Errorf("Authorization = %q, 期望 %q", gotAuth, want)
		}
		if identity.UnionID != "union-id-9" {
			t.Errorf("UnionID = %q, 期望 union-id-9", identity.UnionID)
		}
	})

	t.Run("user/info 平台错误（token 种类错等）整体失败", func(t *testing.T) {
		var gotAuth string
		srv := mockServer(t, http.StatusUnauthorized,
			`{"data":{},"error":{"code":"access_token_invalid","message":"The access token is invalid or not found in the request.","log_id":"lg2"}}`,
			&gotAuth)
		defer srv.Close()

		tk := newTestTikTok(t, srv.URL, func(c *Config) { c.FetchUserInfo = true })
		_, err := tk.VerifyLogin(context.Background(), "code-1")
		if err == nil {
			t.Fatal("期望错误")
		}
		pe, ok := errs.AsPlatformError(err)
		if !ok {
			t.Fatalf("期望 *errs.Error，实际 %T", err)
		}
		if pe.Op != "user_info" || pe.Code != "access_token_invalid" {
			t.Errorf("Op/Code = %s/%s, 期望 user_info/access_token_invalid", pe.Op, pe.Code)
		}
		if pe.Retryable {
			t.Error("凭据类错误不应标记可重试")
		}
	})

	t.Run("user/info open_id 与 token 应答不一致（防串号）", func(t *testing.T) {
		var gotAuth string
		srv := mockServer(t, http.StatusOK,
			`{"data":{"user":{"open_id":"other-open-id","union_id":"u"}},"error":{"code":"ok"}}`,
			&gotAuth)
		defer srv.Close()

		tk := newTestTikTok(t, srv.URL, func(c *Config) { c.FetchUserInfo = true })
		_, err := tk.VerifyLogin(context.Background(), "code-1")
		if err == nil {
			t.Fatal("期望串号防御错误")
		}
		var pe *errs.Error
		if !errors.As(err, &pe) || pe.Op != "user_info" {
			t.Fatalf("期望 user_info 平台错误，实际: %v", err)
		}
	})
}
