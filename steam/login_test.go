//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description steam：VerifyLogin 单测——httptest mock 平台应答（成功 / 各错误形态 / 字段缺失），不打真实 Steam
//2026/6/11
//***************************************************

package steam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// newTestSteam 构造指向 httptest server 的实例。
func newTestSteam(t *testing.T, baseURL string, mutate func(*Config)) *Steam {
	t.Helper()
	cfg := Config{
		AppID:     440,
		WebAPIKey: "key_test",
		BaseURL:   baseURL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return s
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"缺 AppID", Config{WebAPIKey: "k"}},
		{"缺 WebAPIKey", Config{AppID: 440}},
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
		s := MustNew(Config{AppID: 440, WebAPIKey: "k"})
		if got := s.Name(); got != "steam" {
			t.Fatalf("Name() = %q, 期望 \"steam\"", got)
		}
	})
}

// validTicketHex 测试用的合法 hex 票据。
const validTicketHex = "08071000abcdef"

// TestVerifyLoginSuccess 成功路径：断言请求构造（方法 / 路径 / query 参数）与身份映射。
// mock 应答按 NEEDS-DOC 中记录的事实结构（result 在 params 内），同时覆盖
// ownersteamid / vacbanned 等未硬依赖字段的 Raw 透传。
func TestVerifyLoginSuccess(t *testing.T) {
	tests := []struct {
		name         string
		identity     string // 空 = 不传 identity 参数
		wantIdentity bool
	}{
		{"带 identity", "tgf-gateway", true},
		{"不带 identity", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotQuery url.Values
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("method = %s, 期望 GET", r.Method)
				}
				if r.URL.Path != "/ISteamUserAuth/AuthenticateUserTicket/v1/" {
					t.Errorf("path = %s, 期望 /ISteamUserAuth/AuthenticateUserTicket/v1/", r.URL.Path)
				}
				gotQuery = r.URL.Query()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"params":{
					"result":"OK","steamid":"76561197960287930",
					"ownersteamid":"76561197960287930","vacbanned":false,"publisherbanned":false}}}`))
			}))
			defer srv.Close()

			s := newTestSteam(t, srv.URL, func(c *Config) { c.Identity = tc.identity })
			identity, err := s.VerifyLogin(context.Background(), validTicketHex)
			if err != nil {
				t.Fatalf("VerifyLogin 失败: %v", err)
			}

			// 请求 query 断言
			wantFields := map[string]string{
				"key":    "key_test",
				"appid":  "440",
				"ticket": validTicketHex,
			}
			for k, want := range wantFields {
				if got := gotQuery.Get(k); got != want {
					t.Errorf("query[%s] = %q, 期望 %q", k, got, want)
				}
			}
			if tc.wantIdentity {
				if got := gotQuery.Get("identity"); got != tc.identity {
					t.Errorf("query[identity] = %q, 期望 %q", got, tc.identity)
				}
			} else if gotQuery.Has("identity") {
				t.Error("不应携带 identity 参数")
			}

			// 身份映射断言
			if identity.Platform != "steam" {
				t.Errorf("Platform = %q, 期望 \"steam\"", identity.Platform)
			}
			if identity.OpenID != "76561197960287930" {
				t.Errorf("OpenID = %q, 期望 76561197960287930", identity.OpenID)
			}
			if identity.UnionID != "" || identity.SessionKey != "" {
				t.Errorf("UnionID/SessionKey 应为空, got %q/%q", identity.UnionID, identity.SessionKey)
			}
			// 未硬依赖字段透传 Raw
			if got := identity.Raw["ownersteamid"]; got != "76561197960287930" {
				t.Errorf("Raw[ownersteamid] = %q, 期望 76561197960287930", got)
			}
			if got := identity.Raw["vacbanned"]; got != "false" {
				t.Errorf("Raw[vacbanned] = %q, 期望 false（布尔字面量透传）", got)
			}
		})
	}
}

// TestVerifyLoginResultAtResponseLevel result 出现在 response 层（ISteamMicroTxn
// 包封形态）时同样兼容。
func TestVerifyLoginResultAtResponseLevel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"result":"OK","params":{"steamid":"76561197960287930"}}}`))
	}))
	defer srv.Close()

	s := newTestSteam(t, srv.URL, nil)
	identity, err := s.VerifyLogin(context.Background(), validTicketHex)
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}
	if identity.OpenID != "76561197960287930" {
		t.Fatalf("OpenID = %q, 期望 76561197960287930", identity.OpenID)
	}
}

// TestVerifyLoginErrors 错误路径表驱动：本地参数校验 / 平台业务错误 / HTML 错误页 /
// 限频与 5xx 的可重试分类 / 字段缺失协议异常。
func TestVerifyLoginErrors(t *testing.T) {
	tests := []struct {
		name          string
		credential    string
		handler       http.HandlerFunc // nil = 不应发出请求
		wantCode      string
		wantRetryable bool
		wantHTTP      int
	}{
		{
			name:       "credential 为空",
			credential: "",
		},
		{
			name:       "credential 非 hex（误传 base64）",
			credential: "dGlja2V0+/==",
		},
		{
			name:       "业务错误：票据无效（error 块，errorcode 数字形态）",
			credential: validTicketHex,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"error":{"errorcode":3,"errordesc":"Invalid parameter"}}}`))
			},
			wantCode: "3",
			wantHTTP: 200,
		},
		{
			name:       "业务错误：errorcode 字符串形态兼容",
			credential: validTicketHex,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"error":{"errorcode":"101","errordesc":"Ticket expired"}}}`))
			},
			wantCode: "101",
			wantHTTP: 200,
		},
		{
			name:       "result 非 OK（params 层）",
			credential: validTicketHex,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"params":{"result":"Failure"}}}`))
			},
			wantCode: "Failure",
			wantHTTP: 200,
		},
		{
			name:       "403 + HTML 错误页（key 无效，实测形态，确定性失败）",
			credential: validTicketHex,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`<html><head><title>Forbidden</title></head><body>Access is denied.</body></html>`))
			},
			wantCode:      "403",
			wantRetryable: false,
			wantHTTP:      403,
		},
		{
			name:       "429 限频（可重试）",
			credential: validTicketHex,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantCode:      "429",
			wantRetryable: true,
			wantHTTP:      429,
		},
		{
			name:       "500 + HTML（可重试）",
			credential: validTicketHex,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("<html>Internal Server Error</html>"))
			},
			wantCode:      "500",
			wantRetryable: true,
			wantHTTP:      500,
		},
		{
			name:       "200 但缺 steamid（协议异常）",
			credential: validTicketHex,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"params":{"result":"OK"}}}`))
			},
			wantHTTP: 200,
		},
		{
			name:       "200 + 非 JSON 应答（解析失败）",
			credential: validTicketHex,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("not json"))
			},
			wantHTTP: 200,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseURL := "http://127.0.0.1:0" // handler 为 nil 时不应发请求，给个必失败地址兜底
			if tc.handler != nil {
				srv := httptest.NewServer(tc.handler)
				defer srv.Close()
				baseURL = srv.URL
			}
			s := newTestSteam(t, baseURL, nil)
			_, err := s.VerifyLogin(context.Background(), tc.credential)
			if err == nil {
				t.Fatal("期望失败，实际成功")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error, got %T: %v", err, err)
			}
			if pe.Platform != "steam" || pe.Op != opAuthTicket {
				t.Errorf("Platform/Op = %s/%s, 期望 steam/%s", pe.Platform, pe.Op, opAuthTicket)
			}
			if tc.wantCode != "" && pe.Code != tc.wantCode {
				t.Errorf("Code = %q, 期望 %q", pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetryable)
			}
			if tc.wantHTTP != 0 && pe.HTTPStatus != tc.wantHTTP {
				t.Errorf("HTTPStatus = %d, 期望 %d", pe.HTTPStatus, tc.wantHTTP)
			}
		})
	}
}

// TestVerifyLoginNetworkError 传输层失败（连接拒绝）应标记可重试。
func TestVerifyLoginNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // 立即关闭制造连接拒绝

	s := newTestSteam(t, srv.URL, nil)
	_, err := s.VerifyLogin(context.Background(), validTicketHex)
	if err == nil {
		t.Fatal("期望失败，实际成功")
	}
	if !errs.IsRetryable(err) {
		t.Fatalf("网络错误应标记可重试: %v", err)
	}
}
