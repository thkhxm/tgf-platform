//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：VerifyLogin / VerifyLoginAnonymous 单测——httptest mock 平台应答
//2026/6/11
//***************************************************

package douyin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// TestVerifyLoginSuccess 成功路径：断言请求构造（路径 / 方法 / query 字段 /
// content-type 头）与身份映射。
func TestVerifyLoginSuccess(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, 期望 GET", r.Method)
		}
		if r.URL.Path != "/mgplatform/api/apps/jscode2session" {
			t.Errorf("path = %s, 期望 /mgplatform/api/apps/jscode2session", r.URL.Path)
		}
		// 文档把 content-type: application/json 标注为必填请求头（虽是 GET）。
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %s, 期望 application/json", ct)
		}
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"error":0,"session_key":"sk-1","openid":"openid-1",
			"anonymous_openid":"","unionid":"unionid-1"}`))
	}))
	defer srv.Close()

	d := newTestDouyin(t, srv.URL, nil)
	identity, err := d.VerifyLogin(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}

	wantQuery := map[string]string{
		"appid":  "tt0123456789abcdef",
		"secret": "secret_test",
		"code":   "code-1",
	}
	for k, want := range wantQuery {
		if got := gotQuery.Get(k); got != want {
			t.Errorf("query %s = %q, 期望 %q", k, got, want)
		}
	}
	if gotQuery.Has("anonymous_code") {
		t.Error("非匿名登录不应携带 anonymous_code")
	}

	if identity.Platform != "douyin" {
		t.Errorf("Platform = %q, 期望 douyin", identity.Platform)
	}
	if identity.OpenID != "openid-1" {
		t.Errorf("OpenID = %q, 期望 openid-1", identity.OpenID)
	}
	if identity.UnionID != "unionid-1" {
		t.Errorf("UnionID = %q, 期望 unionid-1", identity.UnionID)
	}
	if identity.SessionKey != "sk-1" {
		t.Errorf("SessionKey = %q, 期望 sk-1", identity.SessionKey)
	}
}

// TestVerifyLoginErrors 错误路径：平台错误码 / 字段缺失 / HTTP 异常 / 非 JSON。
func TestVerifyLoginErrors(t *testing.T) {
	tests := []struct {
		name          string
		respBody      string
		respStatus    int
		wantCode      string
		wantRetryable bool
	}{
		// 错误码表见 login.go code2SessionPath 注释；errcode 是详细错误号。
		{"40018 code 错误", `{"error":40018,"errcode":40018,"errmsg":"bad code"}`, 200, "40018", false},
		{"40015 appid 错误", `{"error":40015,"errcode":40015,"errmsg":"bad appid"}`, 200, "40015", false},
		{"40017 secret 错误", `{"error":40017,"errcode":40017,"errmsg":"bad secret"}`, 200, "40017", false},
		{"40014 未传必要参数", `{"error":40014,"errcode":40014,"errmsg":"missing param"}`, 200, "40014", false},
		{"-1 系统错误可重试", `{"error":-1,"errcode":-1,"errmsg":"system error"}`, 200, "-1", true},
		{"errcode 缺失回退 error", `{"error":40018,"message":"bad code"}`, 200, "40018", false},
		{"成功却缺 openid", `{"error":0,"session_key":"sk"}`, 200, "", false},
		{"HTTP 500 可重试", `oops`, 500, "", true},
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
			_, err := d.VerifyLogin(context.Background(), "code-x")
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
		})
	}

	t.Run("空 credential 不发请求", func(t *testing.T) {
		d := newTestDouyin(t, "http://127.0.0.1:1", nil) // 不可达地址：若发请求必失败成传输错误
		_, err := d.VerifyLogin(context.Background(), "")
		if err == nil {
			t.Fatal("期望失败")
		}
		pe, _ := errs.AsPlatformError(err)
		if pe == nil || pe.Retryable {
			t.Fatalf("空 credential 应为确定性失败: %v", err)
		}
	})
}

// TestVerifyLoginAnonymous 匿名登录：anonymous_code → anonymous_openid 映射。
func TestVerifyLoginAnonymous(t *testing.T) {
	t.Run("成功", func(t *testing.T) {
		var gotQuery url.Values
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.Query()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":0,"anonymous_openid":"anon-1"}`))
		}))
		defer srv.Close()

		d := newTestDouyin(t, srv.URL, nil)
		identity, err := d.VerifyLoginAnonymous(context.Background(), "anon-code-1")
		if err != nil {
			t.Fatalf("VerifyLoginAnonymous 失败: %v", err)
		}
		if got := gotQuery.Get("anonymous_code"); got != "anon-code-1" {
			t.Errorf("query anonymous_code = %q, 期望 anon-code-1", got)
		}
		if gotQuery.Has("code") {
			t.Error("匿名登录不应携带 code")
		}
		if identity.OpenID != "anon-1" {
			t.Errorf("OpenID = %q, 期望 anon-1", identity.OpenID)
		}
		if identity.Raw["anonymous"] != "true" {
			t.Errorf("Raw[anonymous] = %q, 期望 true", identity.Raw["anonymous"])
		}
	})

	t.Run("40019 anonymous code 错误", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":40019,"errcode":40019,"errmsg":"bad anonymous code"}`))
		}))
		defer srv.Close()

		d := newTestDouyin(t, srv.URL, nil)
		_, err := d.VerifyLoginAnonymous(context.Background(), "anon-bad")
		if got := errs.CodeOf(err); got != "40019" {
			t.Fatalf("CodeOf = %q, 期望 40019（err=%v）", got, err)
		}
	})

	t.Run("成功却缺 anonymous_openid", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":0}`))
		}))
		defer srv.Close()

		d := newTestDouyin(t, srv.URL, nil)
		if _, err := d.VerifyLoginAnonymous(context.Background(), "anon-x"); err == nil {
			t.Fatal("期望协议异常失败，实际成功")
		}
	})
}
