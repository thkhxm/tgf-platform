//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description facebook：VerifyLogin 单测——debug_token 校验 / 错误映射 / appsecret_proof / FetchUserInfo
//2026/6/11
//***************************************************

package facebook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
)

const (
	testAppID     = "772899436149321"
	testAppSecret = "as_test_secret"
	testUserToken = "EAAuser-token-1"
)

// hmacHex 独立实现 HMAC-SHA256 hex（与被测代码互为印证）。
func hmacHex(key, data string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// newLoginFacebook 构造指向 httptest server 的实例。
func newLoginFacebook(t *testing.T, baseURL string, mutate func(*Config)) *Facebook {
	t.Helper()
	cfg := Config{AppID: testAppID, AppSecret: testAppSecret, BaseURL: baseURL}
	if mutate != nil {
		mutate(&cfg)
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return f
}

// TestVerifyLogin 表驱动覆盖 debug_token 的成功映射与各失败分支。
func TestVerifyLogin(t *testing.T) {
	tests := []struct {
		name string
		// handler 返回 (status, body)
		status int
		body   string
		// 期望
		wantErr       bool
		wantCode      string // errs.CodeOf
		wantRetryable bool
		check         func(t *testing.T, id map[string]string, openID string)
	}{
		{
			name:   "合法 token → 标准化身份",
			status: 200,
			body: `{"data":{"app_id":"` + testAppID + `","application":"MyGame","expires_at":1765432100,` +
				`"data_access_expires_at":1775432100,"is_valid":true,"issued_at":1755432100,` +
				`"scopes":["public_profile","email"],"user_id":"10226735999000000"}}`,
			check: func(t *testing.T, raw map[string]string, openID string) {
				if openID != "10226735999000000" {
					t.Errorf("OpenID = %q", openID)
				}
				if raw["application"] != "MyGame" || raw["scopes"] != "public_profile,email" {
					t.Errorf("Raw 映射不符: %v", raw)
				}
				if raw["expires_at"] != "1765432100" || raw["issued_at"] != "1755432100" {
					t.Errorf("时间字段透传不符: %v", raw)
				}
			},
		},
		{
			name:   "data.error（input_token 失效）→ 平台码 190 不可重试",
			status: 200,
			body: `{"data":{"app_id":"` + testAppID + `","error":{"code":190,"message":"Invalid OAuth access token.","subcode":460},` +
				`"is_valid":false,"scopes":[]}}`,
			wantErr:  true,
			wantCode: "190",
		},
		{
			name:    "is_valid=false（无 data.error）→ 拒绝",
			status:  200,
			body:    `{"data":{"app_id":"` + testAppID + `","is_valid":false,"user_id":"10226735999000000","scopes":[]}}`,
			wantErr: true,
		},
		{
			name:    "app_id 归属他人应用 → 防串号拒绝",
			status:  200,
			body:    `{"data":{"app_id":"999000999000999","is_valid":true,"user_id":"10226735999000000","scopes":[]}}`,
			wantErr: true,
		},
		{
			name:    "缺 user_id（疑似 app token 被当用户凭据）→ 拒绝",
			status:  200,
			body:    `{"data":{"app_id":"` + testAppID + `","is_valid":true,"scopes":[]}}`,
			wantErr: true,
		},
		{
			name:          "顶层 Graph 错误 code=4（限频）→ 可重试",
			status:        403,
			body:          `{"error":{"message":"Application request limit reached","type":"OAuthException","code":4,"fbtrace_id":"AbCd"}}`,
			wantErr:       true,
			wantCode:      "4",
			wantRetryable: true,
		},
		{
			name:          "顶层 Graph 错误 code=190（app token 无效）→ 不可重试",
			status:        401,
			body:          `{"error":{"message":"Invalid OAuth access token.","type":"OAuthException","code":190,"error_subcode":460}}`,
			wantErr:       true,
			wantCode:      "190",
			wantRetryable: false,
		},
		{
			name:          "500 + HTML 错误页 → 解析失败可重试",
			status:        500,
			body:          `<html>Internal Server Error</html>`,
			wantErr:       true,
			wantRetryable: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/"+DefaultGraphVersion+"/debug_token" {
					t.Errorf("意外的请求路径: %s", r.URL.Path)
				}
				q := r.URL.Query()
				if got := q.Get("input_token"); got != testUserToken {
					t.Errorf("input_token = %q", got)
				}
				appToken := testAppID + "|" + testAppSecret
				if got := q.Get("access_token"); got != appToken {
					t.Errorf("access_token = %q, 期望 app_id|app_secret 形式 %q", got, appToken)
				}
				if got := q.Get("appsecret_proof"); got != hmacHex(testAppSecret, appToken) {
					t.Errorf("appsecret_proof = %q 与 HMAC-SHA256(app_secret, access_token) 不符", got)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			f := newLoginFacebook(t, srv.URL, nil)
			identity, err := f.VerifyLogin(context.Background(), testUserToken)
			if tc.wantErr {
				if err == nil {
					t.Fatal("期望失败，实际成功")
				}
				if tc.wantCode != "" && errs.CodeOf(err) != tc.wantCode {
					t.Errorf("CodeOf = %q, 期望 %q（err=%v）", errs.CodeOf(err), tc.wantCode, err)
				}
				if errs.IsRetryable(err) != tc.wantRetryable {
					t.Errorf("IsRetryable = %v, 期望 %v（err=%v）", errs.IsRetryable(err), tc.wantRetryable, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望成功，实际: %v", err)
			}
			if identity.Platform != PlatformName {
				t.Errorf("Platform = %q", identity.Platform)
			}
			if identity.UnionID != "" || identity.SessionKey != "" {
				t.Errorf("Facebook 无 UnionID/SessionKey 概念，应为空: %+v", identity)
			}
			if tc.check != nil {
				tc.check(t, identity.Raw, identity.OpenID)
			}
		})
	}
}

// TestVerifyLoginEmptyCredential 空凭据直接拒绝（不发请求）。
func TestVerifyLoginEmptyCredential(t *testing.T) {
	f := newLoginFacebook(t, "http://127.0.0.1:0", nil)
	if _, err := f.VerifyLogin(context.Background(), ""); err == nil {
		t.Fatal("空 credential 应失败")
	}
}

// TestVerifyLoginFetchUserInfo FetchUserInfo 开启时补取 /me 昵称 + 串号防护。
func TestVerifyLoginFetchUserInfo(t *testing.T) {
	const userID = "10226735999000000"
	debugBody := `{"data":{"app_id":"` + testAppID + `","is_valid":true,"user_id":"` + userID + `","scopes":["public_profile"]}}`

	tests := []struct {
		name    string
		meBody  string
		wantErr bool
		want    string // Raw["name"]
	}{
		{
			name:   "id 一致 → 补取 name",
			meBody: `{"id":"` + userID + `","name":"Tim Huang"}`,
			want:   "Tim Huang",
		},
		{
			name:    "/me 返回的 id 与 user_id 不一致 → 串号拒绝",
			meBody:  `{"id":"other-id","name":"Eve"}`,
			wantErr: true,
		},
		{
			name:    "/me 返回 Graph 错误 → 整体失败不静默降级",
			meBody:  `{"error":{"message":"perm","type":"OAuthException","code":10}}`,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/" + DefaultGraphVersion + "/debug_token":
					_, _ = w.Write([]byte(debugBody))
				case "/" + DefaultGraphVersion + "/me":
					q := r.URL.Query()
					if got := q.Get("access_token"); got != testUserToken {
						t.Errorf("/me access_token = %q, 应为用户 token", got)
					}
					if got := q.Get("appsecret_proof"); got != hmacHex(testAppSecret, testUserToken) {
						t.Errorf("/me appsecret_proof = %q 与 HMAC(app_secret, 用户token) 不符", got)
					}
					if got := q.Get("fields"); got != "id,name" {
						t.Errorf("/me fields = %q", got)
					}
					_, _ = w.Write([]byte(tc.meBody))
				default:
					t.Errorf("意外的请求路径: %s", r.URL.Path)
				}
			}))
			defer srv.Close()

			f := newLoginFacebook(t, srv.URL, func(c *Config) { c.FetchUserInfo = true })
			identity, err := f.VerifyLogin(context.Background(), testUserToken)
			if tc.wantErr {
				if err == nil {
					t.Fatal("期望失败，实际成功")
				}
				return
			}
			if err != nil {
				t.Fatalf("期望成功，实际: %v", err)
			}
			if identity.Raw["name"] != tc.want {
				t.Errorf(`Raw["name"] = %q, 期望 %q`, identity.Raw["name"], tc.want)
			}
		})
	}
}

// TestNewConfigValidation 构造期配置校验。
func TestNewConfigValidation(t *testing.T) {
	if _, err := New(Config{AppSecret: "s"}); err == nil {
		t.Error("缺 AppID 应失败")
	}
	if _, err := New(Config{AppID: "a"}); err == nil {
		t.Error("缺 AppSecret 应失败")
	}
	f, err := New(Config{AppID: "a", AppSecret: "s"})
	if err != nil {
		t.Fatalf("合法配置 New 失败: %v", err)
	}
	if f.Name() != PlatformName {
		t.Errorf("Name() = %q", f.Name())
	}
	if f.cfg.GraphVersion != DefaultGraphVersion || f.cfg.BaseURL != DefaultBaseURL {
		t.Errorf("默认值未生效: %+v", f.cfg)
	}
}
