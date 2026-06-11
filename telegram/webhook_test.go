//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description telegram：VerifyWebhook 单测——secret token / 防重放 / body 重置 / 超限，表驱动
//2026/6/11
//***************************************************

package telegram

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testWebhookSecret = "tgf_test_secret-token_01"

// newWebhookTelegram 构造带 secret token 的被测实例。
func newWebhookTelegram(t *testing.T, mutate func(*Config)) *Telegram {
	t.Helper()
	cfg := Config{BotToken: testBotToken, WebhookSecretToken: testWebhookSecret}
	if mutate != nil {
		mutate(&cfg)
	}
	tg, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return tg
}

func TestVerifyWebhook_TableDriven(t *testing.T) {
	const goodBody = `{"update_id":700000001,"message":{"date":1749600000,"successful_payment":{"currency":"XTR","total_amount":50,"invoice_payload":"order-1001","telegram_payment_charge_id":"stch_AbCdEf123456"}}}`

	tests := []struct {
		name    string
		mutate  func(*Config)
		secret  string // header 值；"-" 表示不带 header
		body    string
		wantErr error  // 期望 errors.Is 命中的哨兵；nil 表示期望通过
		errSub  string // 期望错误信息片段
	}{
		{
			name:   "成功_secret正确",
			secret: testWebhookSecret,
			body:   goodBody,
		},
		{
			name:    "失败_未配置secret_failclosed",
			mutate:  func(c *Config) { c.WebhookSecretToken = "" },
			secret:  testWebhookSecret,
			body:    goodBody,
			wantErr: ErrWebhookSecretNotConfigured,
		},
		{
			name:    "失败_缺少header",
			secret:  "-",
			body:    goodBody,
			wantErr: ErrWebhookMissingSecretToken,
		},
		{
			name:    "失败_secret不匹配",
			secret:  "wrong-secret",
			body:    goodBody,
			wantErr: ErrWebhookSecretTokenMismatch,
		},
		{
			name:    "失败_body非JSON",
			secret:  testWebhookSecret,
			body:    "not-json",
			wantErr: ErrWebhookMalformedBody,
		},
		{
			name:    "失败_缺update_id",
			secret:  testWebhookSecret,
			body:    `{"message":{"text":"hi"}}`,
			wantErr: ErrWebhookMalformedBody,
		},
		{
			name:    "失败_update_id为0",
			secret:  testWebhookSecret,
			body:    `{"update_id":0}`,
			wantErr: ErrWebhookMalformedBody,
		},
		{
			name:   "失败_body超限",
			mutate: func(c *Config) { c.WebhookMaxBodySize = 16 },
			secret: testWebhookSecret,
			body:   goodBody,
			errSub: "超过上限",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tg := newWebhookTelegram(t, tc.mutate)
			req := httptest.NewRequest("POST", "/webhook/telegram", strings.NewReader(tc.body))
			if tc.secret != "-" {
				req.Header.Set("X-Telegram-Bot-Api-Secret-Token", tc.secret)
			}
			err := tg.VerifyWebhook(req)
			if tc.wantErr == nil && tc.errSub == "" {
				if err != nil {
					t.Fatalf("期望通过, 得到错误: %v", err)
				}
				// 合约硬要求：Body 必须被重置，handler 仍能读到原文
				got, _ := io.ReadAll(req.Body)
				if string(got) != tc.body {
					t.Errorf("Body 未正确重置: %q", got)
				}
				return
			}
			if err == nil {
				t.Fatal("期望错误, 得到通过")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("errors.Is 未命中期望哨兵, err=%v", err)
			}
			if tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("错误信息 %q 不含 %q", err.Error(), tc.errSub)
			}
		})
	}
}

// TestVerifyWebhook_Replay 验证同一 update_id 重复投递被拦截、不同 id 放行。
func TestVerifyWebhook_Replay(t *testing.T) {
	tg := newWebhookTelegram(t, nil)

	send := func(body string) error {
		req := httptest.NewRequest("POST", "/webhook/telegram", strings.NewReader(body))
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", testWebhookSecret)
		return tg.VerifyWebhook(req)
	}

	if err := send(`{"update_id":700000001}`); err != nil {
		t.Fatalf("首次投递应通过: %v", err)
	}
	err := send(`{"update_id":700000001}`)
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Errorf("重复投递应被防重放拦截, err=%v", err)
	}
	if err := send(`{"update_id":700000002}`); err != nil {
		t.Errorf("不同 update_id 应放行: %v", err)
	}
}

// TestVerifyWebhook_SeenInjection 验证注入的共享去重钩子被使用（多实例部署位）。
func TestVerifyWebhook_SeenInjection(t *testing.T) {
	var gotKey string
	var gotTTL time.Duration
	tg := newWebhookTelegram(t, func(c *Config) {
		c.WebhookReplayTTL = 7 * time.Minute
		c.WebhookSeen = func(key string, ttl time.Duration) bool {
			gotKey, gotTTL = key, ttl
			return true // 模拟共享存储里已存在 → 重放
		}
	})
	req := httptest.NewRequest("POST", "/webhook/telegram", strings.NewReader(`{"update_id":42}`))
	req.Header.Set("X-Telegram-Bot-Api-Secret-Token", testWebhookSecret)
	err := tg.VerifyWebhook(req)
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Errorf("注入钩子返回 true 应判重放, err=%v", err)
	}
	if gotKey != "42" {
		t.Errorf("去重 key = %q, 期望 \"42\"", gotKey)
	}
	if gotTTL != 7*time.Minute {
		t.Errorf("去重 ttl = %v, 期望 7m", gotTTL)
	}
}

// TestVerifyWebhook_BodyRestoredOnError 验证验签失败路径（重放）下 Body 同样被重置。
func TestVerifyWebhook_BodyRestoredOnError(t *testing.T) {
	tg := newWebhookTelegram(t, nil)
	body := `{"update_id":900000001}`
	send := func() (*bytes.Buffer, error) {
		req := httptest.NewRequest("POST", "/webhook/telegram", strings.NewReader(body))
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", testWebhookSecret)
		err := tg.VerifyWebhook(req)
		buf := &bytes.Buffer{}
		_, _ = io.Copy(buf, req.Body)
		return buf, err
	}
	if buf, err := send(); err != nil || buf.String() != body {
		t.Fatalf("首次: err=%v body=%q", err, buf.String())
	}
	buf, err := send()
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("第二次应判重放: %v", err)
	}
	if buf.String() != body {
		t.Errorf("错误路径 Body 未重置: %q", buf.String())
	}
}
