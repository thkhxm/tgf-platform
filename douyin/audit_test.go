//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：AuditText / AuditImage / AuditImageURL 单测——httptest mock 内容安全应答
//2026/6/11
//***************************************************

package douyin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// newAuditServer 同一 server 同时挂 token 与两个内容安全 endpoint。
func newAuditServer(t *testing.T, textHandler, imageHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var tokenCalls atomic.Int64
	mux := http.NewServeMux()
	mux.Handle("/mgplatform/api/apps/v2/token", tokenHandler(&tokenCalls, "tok-audit"))
	if textHandler != nil {
		mux.Handle("/api/v2/tags/text/antidirt", textHandler)
	}
	if imageHandler != nil {
		mux.Handle("/api/v2/tags/image", imageHandler)
	}
	return httptest.NewServer(mux)
}

// TestAuditTextMapping 判定映射：prob=1 / hit=true → reject；全 0 → pass。
func TestAuditTextMapping(t *testing.T) {
	tests := []struct {
		name           string
		respBody       string
		wantPass       bool
		wantSuggestion string
		wantLabels     int
	}{
		{
			// 官方正常响应示例（content-safety-check 文档，2026-06-11 拉取）。
			"prob=1 命中违规",
			`{"log_id":"log-1","data":[{"code":0,"task_id":"t1","data_id":null,"cached":false,
				"predicts":[{"prob":1,"model_name":"antidirt","target":"default"}],"msg":"ok"}]}`,
			false, platform.SuggestionReject, 1,
		},
		{
			"prob=0 通过",
			`{"log_id":"log-2","data":[{"code":0,"task_id":"t2",
				"predicts":[{"prob":0,"model_name":"antidirt","target":"default"}],"msg":"ok"}]}`,
			true, platform.SuggestionPass, 0,
		},
		{
			"hit=true 命中（prob 为小数也拦截）",
			`{"log_id":"log-3","data":[{"code":0,"task_id":"t3",
				"predicts":[{"prob":0.4,"hit":true,"model_name":"antidirt","target":"default"}],"msg":"ok"}]}`,
			false, platform.SuggestionReject, 1,
		},
		{
			// NEEDS-DOC 纪律：小数 prob 无 hit 不判违规，原样透传（见 audit.go 注释）。
			"小数 prob 无 hit 不拦截",
			`{"log_id":"log-4","data":[{"code":0,"task_id":"t4",
				"predicts":[{"prob":0.97,"model_name":"antidirt","target":"default"}],"msg":"ok"}]}`,
			true, platform.SuggestionPass, 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAuditServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, 期望 POST", r.Method)
				}
				if got := r.Header.Get("X-Token"); got != "tok-audit" {
					t.Errorf("X-Token = %q, 期望 tok-audit", got)
				}
				var body struct {
					Tasks []map[string]string `json:"tasks"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("解析请求体失败: %v", err)
				} else if len(body.Tasks) != 1 || body.Tasks[0]["content"] != "待检测文本" {
					t.Errorf("tasks = %+v, 期望 [{content:待检测文本}]", body.Tasks)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.respBody))
			}, nil)
			defer srv.Close()

			d := newTestDouyin(t, srv.URL, nil)
			result, err := d.AuditText(context.Background(), "openid-1", "待检测文本")
			if err != nil {
				t.Fatalf("AuditText 失败: %v", err)
			}
			if result.Pass != tc.wantPass {
				t.Errorf("Pass = %v, 期望 %v", result.Pass, tc.wantPass)
			}
			if result.Suggestion != tc.wantSuggestion {
				t.Errorf("Suggestion = %q, 期望 %q", result.Suggestion, tc.wantSuggestion)
			}
			if len(result.Labels) != tc.wantLabels {
				t.Errorf("Labels = %v, 期望 %d 个", result.Labels, tc.wantLabels)
			}
			if result.TraceID == "" {
				t.Error("TraceID（log_id）不应为空")
			}
		})
	}
}

// TestAuditTextErrors 错误路径：401 token 失效（可重试 + 作废缓存）/ 400 / task 级失败 / 空文本。
func TestAuditTextErrors(t *testing.T) {
	tests := []struct {
		name          string
		respBody      string
		wantCode      string
		wantRetryable bool
	}{
		// 错误码表见 audit.go auditTextPath 注释。
		{"401 token 失效可重试", `{"code":401,"message":"token invalid"}`, "401", true},
		{"400 tasks 为空", `{"code":400,"message":"tasks empty"}`, "400", false},
		{"task 级 code 失败", `{"log_id":"l","data":[{"code":-1,"task_id":"t","msg":"inner fail"}]}`, "-1", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAuditServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.respBody))
			}, nil)
			defer srv.Close()

			d := newTestDouyin(t, srv.URL, nil)
			_, err := d.AuditText(context.Background(), "openid-1", "文本")
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

	t.Run("空文本不发请求", func(t *testing.T) {
		d := newTestDouyin(t, "http://127.0.0.1:1", nil)
		if _, err := d.AuditText(context.Background(), "openid-1", ""); err == nil {
			t.Fatal("期望失败")
		}
	})
}

// TestAuditImageBytesUnsupported 合约的 []byte 入参在抖音不受支持——恒返回
// ErrImageBytesUnsupported（平台只接受图片 URL，见 audit.go）。
func TestAuditImageBytesUnsupported(t *testing.T) {
	d := newTestDouyin(t, "http://127.0.0.1:1", nil)
	_, err := d.AuditImage(context.Background(), "openid-1", []byte{0xFF, 0xD8})
	if !errors.Is(err, ErrImageBytesUnsupported) {
		t.Fatalf("期望 ErrImageBytesUnsupported, 实际: %v", err)
	}
}

// TestAuditImageURL 图片 URL 检测：请求构造（targets/tasks）与判定映射。
func TestAuditImageURL(t *testing.T) {
	t.Run("默认 targets 与命中映射", func(t *testing.T) {
		var gotBody struct {
			Targets []string            `json:"targets"`
			Tasks   []map[string]string `json:"tasks"`
		}
		srv := newAuditServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Errorf("解析请求体失败: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			// 仿官方示例：ocr 命中（prob=1）+ porn 小数 prob 未命中。
			_, _ = w.Write([]byte(`{"log_id":"log-img","data":[{"code":0,"task_id":"t1",
				"predicts":[{"prob":1,"model_name":"image_ocr","target":"ad"},
				{"prob":0.0005,"model_name":"image_porn","target":"porn"}],"msg":"ok"}]}`))
		})
		defer srv.Close()

		d := newTestDouyin(t, srv.URL, nil)
		result, err := d.AuditImageURL(context.Background(), "openid-1", "https://img.example.com/a.jpg")
		if err != nil {
			t.Fatalf("AuditImageURL 失败: %v", err)
		}
		if len(gotBody.Targets) != 2 || gotBody.Targets[0] != "ad" || gotBody.Targets[1] != "porn" {
			t.Errorf("targets = %v, 期望默认 [ad porn]", gotBody.Targets)
		}
		if len(gotBody.Tasks) != 1 || gotBody.Tasks[0]["image"] != "https://img.example.com/a.jpg" {
			t.Errorf("tasks = %+v, 期望 [{image:URL}]", gotBody.Tasks)
		}
		if result.Pass {
			t.Error("ocr prob=1 应判违规")
		}
		if len(result.Labels) != 1 || result.Labels[0] != "image_ocr/ad" {
			t.Errorf("Labels = %v, 期望 [image_ocr/ad]", result.Labels)
		}
		if result.Raw["image_porn/porn"] != "0.0005" {
			t.Errorf("Raw[image_porn/porn] = %q, 期望 0.0005 原样透传", result.Raw["image_porn/porn"])
		}
	})

	t.Run("自定义 targets", func(t *testing.T) {
		var gotTargets []string
		srv := newAuditServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Targets []string `json:"targets"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotTargets = body.Targets
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"log_id":"l","data":[{"code":0,"task_id":"t","predicts":[],"msg":"ok"}]}`))
		})
		defer srv.Close()

		d := newTestDouyin(t, srv.URL, nil)
		result, err := d.AuditImageURL(context.Background(), "", "https://img.example.com/b.jpg", "porn")
		if err != nil {
			t.Fatalf("AuditImageURL 失败: %v", err)
		}
		if len(gotTargets) != 1 || gotTargets[0] != "porn" {
			t.Errorf("targets = %v, 期望 [porn]", gotTargets)
		}
		if !result.Pass {
			t.Error("无 predicts 命中应 Pass")
		}
	})

	t.Run("空 URL 不发请求", func(t *testing.T) {
		d := newTestDouyin(t, "http://127.0.0.1:1", nil)
		if _, err := d.AuditImageURL(context.Background(), "", ""); err == nil {
			t.Fatal("期望失败")
		}
	})
}
