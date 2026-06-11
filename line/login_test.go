//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description line：VerifyLogin 单测——httptest mock 平台应答（成功 / 各错误 / 字段缺失 / 防御性双查），不打真实 LINE
//2026/6/11
//***************************************************

package line

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// testChannelID 单测用 Channel ID（mock 应答的 aud 须与之一致）。
const testChannelID = "1234567890"

// newTestLine 构造指向 httptest server 的实例（时钟固定，便于 exp 断言）。
func newTestLine(t *testing.T, baseURL string, mutate func(*Config)) *Line {
	t.Helper()
	cfg := Config{
		ChannelID:     testChannelID,
		ChannelSecret: "channel_secret_test",
		BaseURL:       baseURL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return l
}

// okPayload 构造一份合法的 verify 成功应答（exp 取 now+1h）。
func okPayload(now time.Time) string {
	return `{
		"iss":"https://access.line.me",
		"sub":"U1234567890abcdef1234567890abcdef",
		"aud":"` + testChannelID + `",
		"exp":` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `,
		"iat":` + strconv.FormatInt(now.Add(-time.Minute).Unix(), 10) + `,
		"auth_time":` + strconv.FormatInt(now.Add(-2*time.Minute).Unix(), 10) + `,
		"nonce":"0987654asdf",
		"amr":["pwd","mfa"],
		"name":"Taro Line",
		"picture":"https://sample_line.me/aBcdefg123456",
		"email":"taro@example.com"}`
}

func TestNewValidation(t *testing.T) {
	t.Run("缺 ChannelID", func(t *testing.T) {
		if _, err := New(Config{ChannelSecret: "s"}); err == nil {
			t.Fatal("期望配置校验失败，实际返回 nil error")
		}
	})
	t.Run("ChannelSecret 可空（仅登录场景）", func(t *testing.T) {
		if _, err := New(Config{ChannelID: "c"}); err != nil {
			t.Fatalf("仅 ChannelID 应可构造: %v", err)
		}
	})
	t.Run("MustNew 非法配置 panic", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("期望 panic")
			}
		}()
		MustNew(Config{})
	})
	t.Run("Name", func(t *testing.T) {
		l := MustNew(Config{ChannelID: "c"})
		if got := l.Name(); got != "line" {
			t.Fatalf("Name() = %q, 期望 \"line\"", got)
		}
	})
}

// TestVerifyLoginSuccess 成功路径：断言请求构造（路径 / 方法 / Content-Type /
// 表单字段）与身份映射（含 JSON 包封 credential 的 nonce / user_id 透传）。
func TestVerifyLoginSuccess(t *testing.T) {
	tests := []struct {
		name       string
		credential string
		wantNonce  string
		wantUserID string
	}{
		{"纯 ID token", "eyJraWQiOiIx.fake.token", "", ""},
		{"JSON 包封（带 nonce + user_id）",
			`{"id_token":"eyJraWQiOiIx.fake.token","nonce":"0987654asdf","user_id":"U1234567890abcdef1234567890abcdef"}`,
			"0987654asdf", "U1234567890abcdef1234567890abcdef"},
		{"JSON 包封（仅 id_token）", `{"id_token":"eyJraWQiOiIx.fake.token"}`, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotForm url.Values
			now := time.Now()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, 期望 POST", r.Method)
				}
				if r.URL.Path != "/oauth2/v2.1/verify" {
					t.Errorf("path = %s, 期望 /oauth2/v2.1/verify", r.URL.Path)
				}
				if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
					t.Errorf("Content-Type = %s, 期望 application/x-www-form-urlencoded", ct)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("ParseForm: %v", err)
				}
				gotForm = r.PostForm
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(okPayload(now)))
			}))
			defer srv.Close()

			l := newTestLine(t, srv.URL, nil)
			identity, err := l.VerifyLogin(context.Background(), tc.credential)
			if err != nil {
				t.Fatalf("VerifyLogin 失败: %v", err)
			}

			// 请求表单断言（字段名以官方文档为准：id_token / client_id / nonce / user_id）。
			if got := gotForm.Get("id_token"); got != "eyJraWQiOiIx.fake.token" {
				t.Errorf("form id_token = %q", got)
			}
			if got := gotForm.Get("client_id"); got != testChannelID {
				t.Errorf("form client_id = %q, 期望 %q", got, testChannelID)
			}
			if got := gotForm.Get("nonce"); got != tc.wantNonce {
				t.Errorf("form nonce = %q, 期望 %q", got, tc.wantNonce)
			}
			if got := gotForm.Get("user_id"); got != tc.wantUserID {
				t.Errorf("form user_id = %q, 期望 %q", got, tc.wantUserID)
			}

			// 身份映射断言。
			if identity.Platform != "line" {
				t.Errorf("Platform = %q", identity.Platform)
			}
			if identity.OpenID != "U1234567890abcdef1234567890abcdef" {
				t.Errorf("OpenID = %q, 期望 sub 值", identity.OpenID)
			}
			if identity.UnionID != "" || identity.SessionKey != "" {
				t.Errorf("UnionID/SessionKey 应为空: %q / %q", identity.UnionID, identity.SessionKey)
			}
			wantRaw := map[string]string{
				"iss":     "https://access.line.me",
				"aud":     testChannelID,
				"nonce":   "0987654asdf",
				"amr":     "pwd,mfa",
				"name":    "Taro Line",
				"picture": "https://sample_line.me/aBcdefg123456",
				"email":   "taro@example.com",
			}
			for k, want := range wantRaw {
				if got := identity.Raw[k]; got != want {
					t.Errorf("Raw[%q] = %q, 期望 %q", k, got, want)
				}
			}
			for _, k := range []string{"exp", "iat", "auth_time"} {
				if identity.Raw[k] == "" {
					t.Errorf("Raw[%q] 缺失", k)
				}
			}
		})
	}
}

// TestVerifyLoginOptionalFieldsAbsent 可选字段缺席时 Raw 不应有空键
// （官方文档：auth_time / nonce / amr / name / picture / email 均为条件返回）。
func TestVerifyLoginOptionalFieldsAbsent(t *testing.T) {
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"iss":"https://access.line.me","sub":"sub-1","aud":"` + testChannelID + `",
			"exp":` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `,"iat":` + strconv.FormatInt(now.Unix(), 10) + `}`))
	}))
	defer srv.Close()

	l := newTestLine(t, srv.URL, nil)
	identity, err := l.VerifyLogin(context.Background(), "tok")
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}
	for _, k := range []string{"auth_time", "nonce", "amr", "name", "picture", "email"} {
		if _, ok := identity.Raw[k]; ok {
			t.Errorf("可选字段缺席时 Raw 不应有键 %q", k)
		}
	}
}

// TestVerifyLoginPlatformError 平台校验失败：错误码 / 描述映射与不可重试分类
// （error_description 取值表与 HTTP 400 行为均来自官方文档 + 真实 endpoint 实测）。
func TestVerifyLoginPlatformError(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantCode    string
		wantRetry   bool
		wantMsgPart string
	}{
		{"JWS 格式错（实测应答）", http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"JWS format error"}`,
			"invalid_request", false, "JWS format error"},
		{"签名非法", http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"Invalid IdToken."}`,
			"invalid_request", false, "Invalid IdToken."},
		{"签发方非法", http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"Invalid IdToken Issuer."}`,
			"invalid_request", false, "Issuer"},
		{"已过期", http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"IdToken expired."}`,
			"invalid_request", false, "expired"},
		{"aud 不符", http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"Invalid IdToken Audience."}`,
			"invalid_request", false, "Audience"},
		{"nonce 不符", http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"Invalid IdToken Nonce."}`,
			"invalid_request", false, "Nonce"},
		{"user_id 不符", http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"Invalid IdToken Subject Identifier."}`,
			"invalid_request", false, "Subject"},
		{"限频 429 可重试", http.StatusTooManyRequests,
			`{"error":"rate_limit","error_description":"too many requests"}`,
			"rate_limit", true, "too many"},
		{"服务端 500 可重试", http.StatusInternalServerError,
			`{"error":"server_error","error_description":"internal"}`,
			"server_error", true, "internal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			l := newTestLine(t, srv.URL, nil)
			_, err := l.VerifyLogin(context.Background(), "tok")
			if err == nil {
				t.Fatal("期望失败，实际成功")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error，实际 %T: %v", err, err)
			}
			if pe.Code != tc.wantCode {
				t.Errorf("Code = %q, 期望 %q", pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetry {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetry)
			}
			if pe.HTTPStatus != tc.status {
				t.Errorf("HTTPStatus = %d, 期望 %d", pe.HTTPStatus, tc.status)
			}
			if !strings.Contains(pe.Message, tc.wantMsgPart) {
				t.Errorf("Message = %q, 期望含 %q", pe.Message, tc.wantMsgPart)
			}
		})
	}
}

// TestVerifyLoginProtocolAnomaly 协议异常与防御性双查：缺 sub / iss 不符 /
// aud 不符 / exp 过期 / 非 JSON 应答 / 200 之外的无 error 应答。
func TestVerifyLoginProtocolAnomaly(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		status    int
		body      string
		wantRetry bool
	}{
		{"缺 sub", http.StatusOK,
			`{"iss":"https://access.line.me","aud":"` + testChannelID + `","exp":` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `}`, false},
		{"iss 不符", http.StatusOK,
			`{"iss":"https://evil.example.com","sub":"s","aud":"` + testChannelID + `","exp":` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `}`, false},
		{"aud 不符", http.StatusOK,
			`{"iss":"https://access.line.me","sub":"s","aud":"9999999999","exp":` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `}`, false},
		{"exp 已过期", http.StatusOK,
			`{"iss":"https://access.line.me","sub":"s","aud":"` + testChannelID + `","exp":` + strconv.FormatInt(now.Add(-time.Hour).Unix(), 10) + `}`, false},
		{"非 JSON 应答（HTML 错误页, 503）", http.StatusServiceUnavailable, `<html>busy</html>`, true},
		{"非 JSON 应答（HTML 错误页, 200）", http.StatusOK, `<html>weird</html>`, false},
		{"无 error 的 404", http.StatusNotFound, `{}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			l := newTestLine(t, srv.URL, nil)
			_, err := l.VerifyLogin(context.Background(), "tok")
			if err == nil {
				t.Fatal("期望失败，实际成功")
			}
			if got := errs.IsRetryable(err); got != tc.wantRetry {
				t.Errorf("IsRetryable = %v, 期望 %v（err=%v）", got, tc.wantRetry, err)
			}
		})
	}
}

// TestVerifyLoginBadCredential 入参非法：空 credential / JSON 包封缺 id_token /
// JSON 包封非法——不应发出任何 HTTP 请求。
func TestVerifyLoginBadCredential(t *testing.T) {
	tests := []struct {
		name       string
		credential string
	}{
		{"空 credential", ""},
		{"纯空白", "   "},
		{"JSON 包封缺 id_token", `{"nonce":"n"}`},
		{"JSON 包封非法", `{"id_token":`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("入参非法不应发出 HTTP 请求")
			}))
			defer srv.Close()

			l := newTestLine(t, srv.URL, nil)
			_, err := l.VerifyLogin(context.Background(), tc.credential)
			if err == nil {
				t.Fatal("期望失败，实际成功")
			}
			if errs.IsRetryable(err) {
				t.Errorf("入参错误不应可重试: %v", err)
			}
		})
	}
}

// TestVerifyLoginTransportError 传输层失败（server 直接断连）应可重试。
func TestVerifyLoginTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // 立即关闭，连接必然失败

	l := newTestLine(t, srv.URL, nil)
	_, err := l.VerifyLogin(context.Background(), "tok")
	if err == nil {
		t.Fatal("期望失败，实际成功")
	}
	if !errs.IsRetryable(err) {
		t.Errorf("传输层失败应可重试: %v", err)
	}
	var pe *errs.Error
	if !errors.As(err, &pe) {
		t.Fatalf("期望 *errs.Error: %v", err)
	}
	if pe.Platform != "line" || pe.Op != "verify_id_token" {
		t.Errorf("Platform/Op = %q/%q", pe.Platform, pe.Op)
	}
}
