//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：内容安全单测——gameMsgSecCheck 映射 / mediaCheckAsync / AuditImage 不支持语义
//2026/6/11
//***************************************************

package wechat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// stableTokenHandler 给 mux 挂内置 token 管理器需要的 stable_token 应答。
func stableTokenHandler(mux *http.ServeMux) {
	mux.HandleFunc("/cgi-bin/stable_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT_TEST","expires_in":7200}`))
	})
}

// TestAuditTextSuccess 成功路径：断言请求构造与 suggest → 标准化建议映射。
func TestAuditTextSuccess(t *testing.T) {
	tests := []struct {
		name           string
		respResult     string
		wantPass       bool
		wantSuggestion string
		wantLabels     []string
	}{
		{
			name:           "pass 通过",
			respResult:     `{"suggest":"pass","label":100}`,
			wantPass:       true,
			wantSuggestion: platform.SuggestionPass,
			wantLabels:     nil,
		},
		{
			name:           "risky 拦截（官方语义）→ reject",
			respResult:     `{"suggest":"risky","label":10001,"replaced_content":"最新***攻略团"}`,
			wantPass:       false,
			wantSuggestion: platform.SuggestionReject,
			wantLabels:     []string{"10001:营销广告"},
		},
		{
			name:           "review → review（防御官方笔误的第三种值）",
			respResult:     `{"suggest":"review","label":21000}`,
			wantPass:       false,
			wantSuggestion: platform.SuggestionReview,
			wantLabels:     []string{"21000:其他"},
		},
		{
			name:           "未知 suggest 保守归 review",
			respResult:     `{"suggest":"whatever","label":99999}`,
			wantPass:       false,
			wantSuggestion: platform.SuggestionReview,
			wantLabels:     []string{"99999"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			stableTokenHandler(mux)
			var gotBody map[string]any
			var gotToken string
			mux.HandleFunc("/wxa/game/content_spam/msg_sec_check", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, 期望 POST", r.Method)
				}
				gotToken = r.URL.Query().Get("access_token")
				if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
					t.Errorf("请求体解析失败: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok","trace_id":"trace-1","result":` + tc.respResult + `}`))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			wc := newTestWeChat(t, srv.URL, func(c *Config) { c.AuditScene = SceneChat })
			res, err := wc.AuditText(context.Background(), "openid-1", "待审文本")
			if err != nil {
				t.Fatalf("AuditText 失败: %v", err)
			}

			// 请求断言（官方必填字段：openid / version=2 / scene / content）
			if gotToken != "AT_TEST" {
				t.Errorf("access_token = %q, 期望 AT_TEST", gotToken)
			}
			if gotBody["openid"] != "openid-1" {
				t.Errorf("body.openid = %v", gotBody["openid"])
			}
			if gotBody["version"] != float64(2) {
				t.Errorf("body.version = %v, 期望 2（官方固定值）", gotBody["version"])
			}
			if gotBody["scene"] != float64(SceneChat) {
				t.Errorf("body.scene = %v, 期望 %d", gotBody["scene"], SceneChat)
			}
			if gotBody["content"] != "待审文本" {
				t.Errorf("body.content = %v", gotBody["content"])
			}

			// 结果映射断言
			if res.Platform != "wechat" {
				t.Errorf("Platform = %q", res.Platform)
			}
			if res.Pass != tc.wantPass {
				t.Errorf("Pass = %v, 期望 %v", res.Pass, tc.wantPass)
			}
			if res.Suggestion != tc.wantSuggestion {
				t.Errorf("Suggestion = %q, 期望 %q", res.Suggestion, tc.wantSuggestion)
			}
			if res.TraceID != "trace-1" {
				t.Errorf("TraceID = %q, 期望 trace-1", res.TraceID)
			}
			if len(res.Labels) != len(tc.wantLabels) {
				t.Fatalf("Labels = %v, 期望 %v", res.Labels, tc.wantLabels)
			}
			for i := range tc.wantLabels {
				if res.Labels[i] != tc.wantLabels[i] {
					t.Errorf("Labels[%d] = %q, 期望 %q", i, res.Labels[i], tc.wantLabels[i])
				}
			}
		})
	}
}

// TestAuditTextErrors 错误路径：errcode 分类（含 40001 作废 token 缓存）。
func TestAuditTextErrors(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantCode      string
		wantRetryable bool
	}{
		{"40129 场景值错误（确定性）", `{"errcode":40129,"errmsg":"scene invalid"}`, "40129", false},
		{"43104 appid 与 openid 不匹配（确定性）", `{"errcode":43104,"errmsg":"mismatch"}`, "43104", false},
		{"750032 分钟级限频（可重试）", `{"errcode":750032,"errmsg":"minute quota"}`, "750032", true},
		{"750033 当日限额（确定性）", `{"errcode":750033,"errmsg":"daily quota"}`, "750033", false},
		{"40001 token 失效（重取后可重试）", `{"errcode":40001,"errmsg":"invalid credential"}`, "40001", true},
		{"缺 result.suggest（协议异常）", `{"errcode":0,"errmsg":"ok","trace_id":"t"}`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			stableTokenHandler(mux)
			mux.HandleFunc("/wxa/game/content_spam/msg_sec_check", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			wc := newTestWeChat(t, srv.URL, nil)
			_, err := wc.AuditText(context.Background(), "openid-1", "text")
			if err == nil {
				t.Fatal("期望错误")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error，实际 %T", err)
			}
			if pe.Op != "msg_sec_check" || pe.Code != tc.wantCode {
				t.Errorf("Op/Code = %s/%s, 期望 msg_sec_check/%s", pe.Op, pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetryable)
			}
		})
	}

	t.Run("40001 作废内置 token 缓存", func(t *testing.T) {
		mux := http.NewServeMux()
		stableTokenHandler(mux)
		mux.HandleFunc("/wxa/game/content_spam/msg_sec_check", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errcode":40001,"errmsg":"invalid credential"}`))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		wc := newTestWeChat(t, srv.URL, nil)
		// 先填充缓存。
		if _, err := wc.accessToken(context.Background()); err != nil {
			t.Fatalf("预热 token 失败: %v", err)
		}
		_, _ = wc.AuditText(context.Background(), "openid-1", "text")
		wc.token.mu.Lock()
		cached := wc.token.token
		wc.token.mu.Unlock()
		if cached != "" {
			t.Errorf("40001 后应作废 token 缓存，实际仍为 %q", cached)
		}
	})

	t.Run("openid / 文本为空不发请求", func(t *testing.T) {
		called := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		defer srv.Close()
		wc := newTestWeChat(t, srv.URL, nil)
		if _, err := wc.AuditText(context.Background(), "", "text"); err == nil {
			t.Error("openid 为空应报错")
		}
		if _, err := wc.AuditText(context.Background(), "openid", ""); err == nil {
			t.Error("文本为空应报错")
		}
		if called {
			t.Error("参数非法不应发起 HTTP 请求")
		}
	})
}

// TestAuditImageUnsupported AuditImage 恒返回 ErrAuditImageUnsupported（微信
// 不提供原始字节同步图片审核，1.0 已停更——绝不调用废弃接口将就）。
func TestAuditImageUnsupported(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, nil)
	_, err := wc.AuditImage(context.Background(), "openid-1", []byte{0xFF, 0xD8})
	if err == nil {
		t.Fatal("期望 ErrAuditImageUnsupported")
	}
	if !errors.Is(err, ErrAuditImageUnsupported) {
		t.Errorf("errors.Is(ErrAuditImageUnsupported) = false: %v", err)
	}
	if called {
		t.Error("AuditImage 不应发起任何 HTTP 请求")
	}
}

// TestAuditMediaAsync 异步多媒体检测：请求构造 / trace_id 返回 / 参数校验。
func TestAuditMediaAsync(t *testing.T) {
	mux := http.NewServeMux()
	stableTokenHandler(mux)
	var gotBody map[string]any
	mux.HandleFunc("/wxa/media_check_async", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("请求体解析失败: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok","trace_id":"media-trace-1"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, nil)
	traceID, err := wc.AuditMediaAsync(context.Background(), "openid-1", "https://cdn.example.com/a.png", MediaTypeImage, SceneComment)
	if err != nil {
		t.Fatalf("AuditMediaAsync 失败: %v", err)
	}
	if traceID != "media-trace-1" {
		t.Errorf("traceID = %q, 期望 media-trace-1", traceID)
	}
	want := map[string]any{
		"media_url":  "https://cdn.example.com/a.png",
		"media_type": float64(MediaTypeImage),
		"version":    float64(2),
		"scene":      float64(SceneComment),
		"openid":     "openid-1",
	}
	for k, v := range want {
		if gotBody[k] != v {
			t.Errorf("body.%s = %v, 期望 %v", k, gotBody[k], v)
		}
	}

	t.Run("参数校验不发请求", func(t *testing.T) {
		if _, err := wc.AuditMediaAsync(context.Background(), "o", "https://x", 3, SceneComment); err == nil {
			t.Error("media_type 非法应报错")
		}
		if _, err := wc.AuditMediaAsync(context.Background(), "o", "https://x", MediaTypeImage, SceneChat); err == nil {
			t.Error("mediaCheckAsync 无聊天场景（官方枚举 1-4），scene=5 应报错")
		}
	})
}

// TestParseMediaCheckEvent 异步结果推送解析与标准化映射（官方推送示例）。
func TestParseMediaCheckEvent(t *testing.T) {
	// 官方文档「异步检测结果推送示例」原样（api_mediacheckasync.html，2026-06-11 拉取）。
	official := `{
		"ToUserName":"gh_9df7d78a1234","FromUserName":"o4_t144jTUSEoxydysUA2E234_tc",
		"CreateTime":1626959646,"MsgType":"event","Event":"wxa_media_check",
		"appid":"wx8f16a5be77871234","trace_id":"60f96f1d-3845297a-1976a3ae","version":2,
		"detail":[{"strategy":"content_model","errcode":0,"suggest":"pass","label":100,"prob":90}],
		"errcode":0,"errmsg":"ok","result":{"suggest":"pass","label":100}}`
	ev, err := ParseMediaCheckEvent([]byte(official))
	if err != nil {
		t.Fatalf("ParseMediaCheckEvent 失败: %v", err)
	}
	if ev.TraceID != "60f96f1d-3845297a-1976a3ae" {
		t.Errorf("TraceID = %q", ev.TraceID)
	}
	res := ev.ToAuditResult()
	if !res.Pass || res.Suggestion != platform.SuggestionPass {
		t.Errorf("Pass/Suggestion = %v/%q, 期望 true/pass", res.Pass, res.Suggestion)
	}
	if res.TraceID != ev.TraceID {
		t.Errorf("AuditResult.TraceID = %q", res.TraceID)
	}

	t.Run("errcode 非 0 结果无效", func(t *testing.T) {
		bad := `{"Event":"wxa_media_check","errcode":-1008,"errmsg":"download fail","trace_id":"t"}`
		if _, err := ParseMediaCheckEvent([]byte(bad)); err == nil {
			t.Error("errcode=-1008（下载失败）应报错")
		}
	})
	t.Run("非 wxa_media_check 事件", func(t *testing.T) {
		other := `{"Event":"debug_demo","errcode":0}`
		if _, err := ParseMediaCheckEvent([]byte(other)); err == nil {
			t.Error("非目标事件应报错")
		}
	})
}
