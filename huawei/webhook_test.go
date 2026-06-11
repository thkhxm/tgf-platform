//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：VerifyWebhook 单测——关键事件通知 v2 结构/时间戳/验签/防重放 + Body 重置
//2026/6/11
//***************************************************

package huawei

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// webhookHuawei 构造 webhook 校验态实例（默认已配 IAP 公钥，单机内存去重）。
func webhookHuawei(t *testing.T, mutate func(*Config)) *Huawei {
	t.Helper()
	cfg := Config{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		IAPPublicKey: testIAPPublicKeyB64(t),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return h
}

// orderWebhookBody 构造 ORDER 事件通知 v2 包体（字段表见 webhook.go
// webhookNotification 注释的官方文档引用；ORDER 通知不携带签名字段）。
func orderWebhookBody(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	body := map[string]any{
		"version":       "v2",
		"eventType":     "ORDER",
		"notifyTime":    time.Now().UnixMilli(),
		"applicationId": testClientID,
		"orderNotification": map[string]any{
			"version":          "v2",
			"notificationType": 1, // 1=支付成功
			"purchaseToken":    testPurchaseToken,
			"productId":        testProductID,
		},
	}
	if mutate != nil {
		mutate(body)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("序列化 ORDER 通知失败: %v", err)
	}
	return raw
}

// subWebhookBody 构造 SUBSCRIPTION 事件通知 v2 包体：statusUpdateNotification
// 为 JSON 字符串，notificationSignature 用测试私钥对其原样字节签名。
// mutateSub 调整 subNotification（篡改/删字段用），mutate 调整顶层。
func subWebhookBody(t *testing.T, mutateSub func(map[string]any), mutate func(map[string]any)) []byte {
	t.Helper()
	status := map[string]any{
		"environment":      "PROD",
		"notificationType": 0, // INITIAL_BUY
		"subscriptionId":   testSubscriptionID,
		"purchaseToken":    testPurchaseToken,
		"productId":        testProductID,
	}
	statusJSON, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("序列化 statusUpdateNotification 失败: %v", err)
	}
	sub := map[string]any{
		"version":                  "v2",
		"statusUpdateNotification": string(statusJSON),
		"notificationSignature":    signIAPData(t, string(statusJSON), ""),
	}
	if mutateSub != nil {
		mutateSub(sub)
	}
	body := map[string]any{
		"version":         "v2",
		"eventType":       "SUBSCRIPTION",
		"notifyTime":      time.Now().UnixMilli(),
		"applicationId":   testClientID,
		"subNotification": sub,
	}
	if mutate != nil {
		mutate(body)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("序列化 SUBSCRIPTION 通知失败: %v", err)
	}
	return raw
}

// newWebhookRequest 构造回调请求。
func newWebhookRequest(body []byte) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/platform/huawei/webhook", bytes.NewReader(body))
}

func TestVerifyWebhook(t *testing.T) {
	cases := []struct {
		name      string
		mutateCfg func(*Config)
		body      func(t *testing.T) []byte
		wantErrIs error // nil 且 !wantOK = 只断言失败
		wantOK    bool
	}{
		{
			name:   "成功_ORDER通知",
			wantOK: true,
			body:   func(t *testing.T) []byte { return orderWebhookBody(t, nil) },
		},
		{
			name:   "成功_SUBSCRIPTION通知_默认SHA256WithRSA",
			wantOK: true,
			body:   func(t *testing.T) []byte { return subWebhookBody(t, nil, nil) },
		},
		{
			name:   "成功_SUBSCRIPTION通知_PSS算法",
			wantOK: true,
			body: func(t *testing.T) []byte {
				return subWebhookBody(t, func(sub map[string]any) {
					status := sub["statusUpdateNotification"].(string)
					sub["notificationSignature"] = signIAPData(t, status, "SHA256WithRSA/PSS")
					sub["signatureAlgorithm"] = "SHA256WithRSA/PSS"
				}, nil)
			},
		},
		{
			name:      "失败_回调体为空",
			body:      func(t *testing.T) []byte { return nil },
			wantErrIs: ErrWebhookMalformedBody,
		},
		{
			name:      "失败_回调体非JSON",
			body:      func(t *testing.T) []byte { return []byte("not json") },
			wantErrIs: ErrWebhookMalformedBody,
		},
		{
			name: "失败_通知版本v1",
			body: func(t *testing.T) []byte {
				return orderWebhookBody(t, func(b map[string]any) { b["version"] = "v1" })
			},
			wantErrIs: ErrWebhookUnsupportedVersion,
		},
		{
			name: "失败_applicationId串单",
			body: func(t *testing.T) []byte {
				return orderWebhookBody(t, func(b map[string]any) { b["applicationId"] = "999999999" })
			},
			wantErrIs: ErrWebhookAppMismatch,
		},
		{
			name: "失败_缺notifyTime",
			body: func(t *testing.T) []byte {
				return orderWebhookBody(t, func(b map[string]any) { delete(b, "notifyTime") })
			},
			wantErrIs: ErrWebhookMalformedBody,
		},
		{
			name: "失败_notifyTime过旧",
			body: func(t *testing.T) []byte {
				return orderWebhookBody(t, func(b map[string]any) {
					b["notifyTime"] = time.Now().Add(-DefaultWebhookTolerance - time.Minute).UnixMilli()
				})
			},
			wantErrIs: ErrWebhookTimestampOutOfWindow,
		},
		{
			name: "失败_notifyTime超前",
			body: func(t *testing.T) []byte {
				return orderWebhookBody(t, func(b map[string]any) {
					b["notifyTime"] = time.Now().Add(DefaultWebhookTolerance + time.Minute).UnixMilli()
				})
			},
			wantErrIs: ErrWebhookTimestampOutOfWindow,
		},
		{
			name: "失败_SUBSCRIPTION缺通知体",
			body: func(t *testing.T) []byte {
				return subWebhookBody(t, nil, func(b map[string]any) { delete(b, "subNotification") })
			},
			wantErrIs: ErrWebhookMalformedBody,
		},
		{
			name: "失败_SUBSCRIPTION缺签名",
			body: func(t *testing.T) []byte {
				return subWebhookBody(t, func(sub map[string]any) {
					delete(sub, "notificationSignature")
				}, nil)
			},
			wantErrIs: ErrWebhookMalformedBody,
		},
		{
			name: "失败_SUBSCRIPTION内容篡改保留原签名",
			body: func(t *testing.T) []byte {
				return subWebhookBody(t, func(sub map[string]any) {
					sub["statusUpdateNotification"] = `{"notificationType":3,"subscriptionId":"evil"}`
				}, nil)
			},
			wantErrIs: ErrWebhookSignatureMismatch,
		},
		{
			name:      "失败_SUBSCRIPTION未配置IAP公钥",
			mutateCfg: func(c *Config) { c.IAPPublicKey = "" },
			body:      func(t *testing.T) []byte { return subWebhookBody(t, nil, nil) },
		},
		{
			name: "失败_ORDER缺purchaseToken",
			body: func(t *testing.T) []byte {
				return orderWebhookBody(t, func(b map[string]any) {
					b["orderNotification"].(map[string]any)["purchaseToken"] = ""
				})
			},
			wantErrIs: ErrWebhookMalformedBody,
		},
		{
			name: "失败_未知eventType",
			body: func(t *testing.T) []byte {
				return orderWebhookBody(t, func(b map[string]any) { b["eventType"] = "REFUND" })
			},
			wantErrIs: ErrWebhookMalformedBody,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := webhookHuawei(t, tc.mutateCfg)
			body := tc.body(t)
			req := newWebhookRequest(body)
			err := h.VerifyWebhook(req)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("VerifyWebhook 应通过，实际失败: %v", err)
				}
				// 合约硬要求：Body 必须被重置，业务 handler 能读到原文。
				got, readErr := io.ReadAll(req.Body)
				if readErr != nil {
					t.Fatalf("重读 Body 失败: %v", readErr)
				}
				if !bytes.Equal(got, body) {
					t.Error("VerifyWebhook 后 Body 与原文不一致（未正确重置）")
				}
				return
			}
			if err == nil {
				t.Fatal("VerifyWebhook 应失败，实际通过")
			}
			if _, ok := errs.AsPlatformError(err); !ok {
				t.Errorf("错误应为 *errs.Error，实际 %T: %v", err, err)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("错误链应命中 %v，实际: %v", tc.wantErrIs, err)
			}
		})
	}
}

// TestVerifyWebhookReplay 校验防重放：同一通知第二次投递被拦截
// （ORDER 以回调体哈希、SUBSCRIPTION 以签名为去重 key）。
func TestVerifyWebhookReplay(t *testing.T) {
	t.Run("ORDER", func(t *testing.T) {
		h := webhookHuawei(t, nil)
		body := orderWebhookBody(t, nil)
		if err := h.VerifyWebhook(newWebhookRequest(body)); err != nil {
			t.Fatalf("首次投递应通过，实际失败: %v", err)
		}
		err := h.VerifyWebhook(newWebhookRequest(body))
		if !errors.Is(err, ErrWebhookReplayed) {
			t.Fatalf("重复投递应返回 ErrWebhookReplayed，实际: %v", err)
		}
	})
	t.Run("SUBSCRIPTION", func(t *testing.T) {
		h := webhookHuawei(t, nil)
		body := subWebhookBody(t, nil, nil)
		if err := h.VerifyWebhook(newWebhookRequest(body)); err != nil {
			t.Fatalf("首次投递应通过，实际失败: %v", err)
		}
		err := h.VerifyWebhook(newWebhookRequest(body))
		if !errors.Is(err, ErrWebhookReplayed) {
			t.Fatalf("重复投递应返回 ErrWebhookReplayed，实际: %v", err)
		}
	})
}

// TestVerifyWebhookCustomSeen 校验注入的去重钩子收到正确的 key 前缀与 ttl
// （多实例部署的共享存储扩展点）。
func TestVerifyWebhookCustomSeen(t *testing.T) {
	var gotKey string
	var gotTTL time.Duration
	h := webhookHuawei(t, func(c *Config) {
		c.WebhookSeen = func(key string, ttl time.Duration) bool {
			gotKey, gotTTL = key, ttl
			return false
		}
	})

	if err := h.VerifyWebhook(newWebhookRequest(orderWebhookBody(t, nil))); err != nil {
		t.Fatalf("ORDER 校验失败: %v", err)
	}
	if !strings.HasPrefix(gotKey, "order:") {
		t.Errorf("ORDER 去重 key = %q, 期望 order: 前缀（回调体哈希）", gotKey)
	}
	if want := 2 * DefaultWebhookTolerance; gotTTL != want {
		t.Errorf("去重 ttl = %v, 期望 2×容忍窗口 %v", gotTTL, want)
	}

	if err := h.VerifyWebhook(newWebhookRequest(subWebhookBody(t, nil, nil))); err != nil {
		t.Fatalf("SUBSCRIPTION 校验失败: %v", err)
	}
	if !strings.HasPrefix(gotKey, "sub:") {
		t.Errorf("SUBSCRIPTION 去重 key = %q, 期望 sub: 前缀（通知签名）", gotKey)
	}
}

// TestVerifyWebhookBodyTooLarge 校验回调体超限拦截。
func TestVerifyWebhookBodyTooLarge(t *testing.T) {
	h := webhookHuawei(t, func(c *Config) { c.WebhookMaxBodySize = 8 })
	if err := h.VerifyWebhook(newWebhookRequest(orderWebhookBody(t, nil))); err == nil {
		t.Fatal("回调体超过上限应失败")
	}
}

// TestReadAndRestoreBody 校验 Body 读取与重置的边界行为。
func TestReadAndRestoreBody(t *testing.T) {
	t.Run("nil_Body按空payload处理并重置", func(t *testing.T) {
		req := &http.Request{}
		raw, err := readAndRestoreBody(req, 16)
		if err != nil || len(raw) != 0 {
			t.Fatalf("nil Body 应返回空 payload，实际 raw=%q err=%v", raw, err)
		}
		if req.Body == nil {
			t.Fatal("Body 应被重置为可读空 reader")
		}
		rest, _ := io.ReadAll(req.Body)
		if len(rest) != 0 {
			t.Errorf("重置后的空 Body 应读到 0 字节，实际 %d", len(rest))
		}
	})
	t.Run("正常读取并重置", func(t *testing.T) {
		req := newWebhookRequest([]byte("hello"))
		raw, err := readAndRestoreBody(req, 16)
		if err != nil || string(raw) != "hello" {
			t.Fatalf("读取失败: raw=%q err=%v", raw, err)
		}
		rest, _ := io.ReadAll(req.Body)
		if string(rest) != "hello" {
			t.Errorf("重置后 Body = %q, 期望原文 hello", rest)
		}
	})
	t.Run("恰好超限报错", func(t *testing.T) {
		req := newWebhookRequest(bytes.Repeat([]byte("a"), 17))
		if _, err := readAndRestoreBody(req, 16); err == nil {
			t.Fatal("超限应报错")
		}
	})
}
