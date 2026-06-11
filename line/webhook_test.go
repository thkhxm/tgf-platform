//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description line：VerifyWebhook 单测——验签 / 时间戳窗口 / 防重放 / Body 重置（含篡改与重投场景），表驱动
//2026/6/11
//***************************************************

package line

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/sign"
)

const testWebhookSecret = "channel_secret_test"

// fixedNow 单测固定时钟。
var fixedNow = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

// newWebhookLine 构造用于 webhook 单测的实例（固定时钟）。
func newWebhookLine(t *testing.T, mutate func(*Config)) *Line {
	t.Helper()
	cfg := Config{
		ChannelID:     testChannelID,
		ChannelSecret: testWebhookSecret,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	l.now = func() time.Time { return fixedNow }
	return l
}

// webhookBody 构造一份官方结构的回调体（事件字段结构见 line-openapi webhook.yml）。
func webhookBody(timestampMs int64, redelivery bool, eventID string) []byte {
	return []byte(`{"destination":"U0123456789abcdef0123456789abcdef","events":[{` +
		`"type":"message","mode":"active","timestamp":` + strconv.FormatInt(timestampMs, 10) + `,` +
		`"webhookEventId":"` + eventID + `",` +
		`"deliveryContext":{"isRedelivery":` + strconv.FormatBool(redelivery) + `}}]}`)
}

func TestVerifyWebhookSuccess(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"单事件（窗口内）", webhookBody(fixedNow.UnixMilli()-30_000, false, "01H810YECXQQZ37VAXPF6H9E6T")},
		{"空 events（官方 Verify 探测）", []byte(`{"destination":"U0123456789abcdef0123456789abcdef","events":[]}`)},
		{"官方重投（isRedelivery=true, 时间戳过旧仍放行）",
			webhookBody(fixedNow.Add(-2*time.Hour).UnixMilli(), true, "01H810YECXQQZ37VAXPF6H9E6T")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newWebhookLine(t, nil)
			r := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(tc.body))
			r.Header.Set("x-line-signature", sign.HMACSHA256Base64([]byte(testWebhookSecret), tc.body))

			if err := l.VerifyWebhook(r); err != nil {
				t.Fatalf("VerifyWebhook 失败: %v", err)
			}
			// 合约硬要求：Body 必须被重置，业务 handler 能再读到原文。
			got, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("重读 Body 失败: %v", err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Errorf("Body 重置后内容不一致")
			}
		})
	}
}

// TestVerifyWebhookSignatureFailures 验签链路失败：缺密钥 / 缺 header /
// 非法 base64 / 密钥不符 / body 被篡改。
func TestVerifyWebhookSignatureFailures(t *testing.T) {
	body := webhookBody(fixedNow.UnixMilli(), false, "01H810YECXQQZ37VAXPF6H9E6T")
	goodSig := sign.HMACSHA256Base64([]byte(testWebhookSecret), body)

	tests := []struct {
		name     string
		mutate   func(*Config)
		sig      string
		body     []byte
		sentinel error
	}{
		{"ChannelSecret 未配置", func(c *Config) { c.ChannelSecret = "" }, goodSig, body, ErrWebhookSecretMissing},
		{"缺签名 header", nil, "", body, ErrWebhookMissingSignature},
		{"签名非法 base64", nil, "!!!not-base64!!!", body, ErrWebhookMalformedSignature},
		{"密钥不符", nil, sign.HMACSHA256Base64([]byte("wrong_secret"), body), body, ErrWebhookSignatureMismatch},
		{"body 被篡改", nil, goodSig, bytes.Replace(body, []byte("message"), []byte("tampere"), 1), ErrWebhookSignatureMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newWebhookLine(t, tc.mutate)
			r := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(tc.body))
			if tc.sig != "" {
				r.Header.Set("x-line-signature", tc.sig)
			}
			err := l.VerifyWebhook(r)
			if err == nil {
				t.Fatal("期望失败，实际通过")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("err = %v, 期望沿链匹配 %v", err, tc.sentinel)
			}
		})
	}
}

// TestVerifyWebhookTimestampWindow 事件时间戳窗口（毫秒）：过旧 / 超前拒绝，
// 窗口内放行；重投事件跳过窗口（见成功用例）。
func TestVerifyWebhookTimestampWindow(t *testing.T) {
	tests := []struct {
		name    string
		tsMs    int64
		wantErr bool
	}{
		{"窗口内（-4m59s）", fixedNow.Add(-4*time.Minute - 59*time.Second).UnixMilli(), false},
		{"过旧（-5m1s）", fixedNow.Add(-5*time.Minute - time.Second).UnixMilli(), true},
		{"超前（+5m1s）", fixedNow.Add(5*time.Minute + time.Second).UnixMilli(), true},
		{"超前但窗口内（+1m）", fixedNow.Add(time.Minute).UnixMilli(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newWebhookLine(t, nil)
			body := webhookBody(tc.tsMs, false, "01H810YECXQQZ37VAXPF6H9E6T")
			r := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(body))
			r.Header.Set("x-line-signature", sign.HMACSHA256Base64([]byte(testWebhookSecret), body))

			err := l.VerifyWebhook(r)
			if tc.wantErr {
				if !errors.Is(err, ErrWebhookTimestampOutOfWindow) {
					t.Errorf("err = %v, 期望 ErrWebhookTimestampOutOfWindow", err)
				}
			} else if err != nil {
				t.Errorf("期望通过，实际失败: %v", err)
			}
		})
	}
}

// TestVerifyWebhookReplay 防重放：同一请求（同签名）第二次投递被拦截；
// 不同 body（签名不同）不受影响。
func TestVerifyWebhookReplay(t *testing.T) {
	l := newWebhookLine(t, nil)
	body := webhookBody(fixedNow.UnixMilli(), false, "01H810YECXQQZ37VAXPF6H9E6T")
	sig := sign.HMACSHA256Base64([]byte(testWebhookSecret), body)

	r1 := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(body))
	r1.Header.Set("x-line-signature", sig)
	if err := l.VerifyWebhook(r1); err != nil {
		t.Fatalf("首次投递应通过: %v", err)
	}

	r2 := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(body))
	r2.Header.Set("x-line-signature", sig)
	if err := l.VerifyWebhook(r2); !errors.Is(err, ErrWebhookReplayed) {
		t.Errorf("重放应被拦截，err = %v", err)
	}

	// 不同事件（不同 body → 不同签名）不受去重影响。
	body3 := webhookBody(fixedNow.UnixMilli(), false, "01H810YECXQQZ37VAXPF6H9E6U")
	r3 := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(body3))
	r3.Header.Set("x-line-signature", sign.HMACSHA256Base64([]byte(testWebhookSecret), body3))
	if err := l.VerifyWebhook(r3); err != nil {
		t.Errorf("不同事件不应被去重拦截: %v", err)
	}
}

// TestVerifyWebhookSeenInjection 注入自定义去重钩子：断言 key 是签名值、
// ttl 是 2×容忍窗口。
func TestVerifyWebhookSeenInjection(t *testing.T) {
	var gotKey string
	var gotTTL time.Duration
	l := newWebhookLine(t, func(c *Config) {
		c.WebhookTolerance = 3 * time.Minute
		c.WebhookSeen = func(key string, ttl time.Duration) bool {
			gotKey, gotTTL = key, ttl
			return false
		}
	})
	body := webhookBody(fixedNow.UnixMilli(), false, "01H810YECXQQZ37VAXPF6H9E6T")
	sig := sign.HMACSHA256Base64([]byte(testWebhookSecret), body)
	r := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(body))
	r.Header.Set("x-line-signature", sig)

	if err := l.VerifyWebhook(r); err != nil {
		t.Fatalf("VerifyWebhook 失败: %v", err)
	}
	if gotKey != sig {
		t.Errorf("去重 key = %q, 期望签名值", gotKey)
	}
	if gotTTL != 6*time.Minute {
		t.Errorf("去重 ttl = %v, 期望 2×容忍窗口 = 6m", gotTTL)
	}
}

// TestVerifyWebhookBodyAnomaly 体积超限与结构非法：超大 body / 非 JSON body
// （已验签后才解析，结构非法仍拒绝）。
func TestVerifyWebhookBodyAnomaly(t *testing.T) {
	t.Run("body 超过上限", func(t *testing.T) {
		l := newWebhookLine(t, func(c *Config) { c.WebhookMaxBodySize = 16 })
		body := []byte(`{"destination":"x","events":[]}`) // > 16 字节
		r := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(body))
		r.Header.Set("x-line-signature", sign.HMACSHA256Base64([]byte(testWebhookSecret), body))
		if err := l.VerifyWebhook(r); err == nil {
			t.Fatal("超限 body 应失败")
		}
	})
	t.Run("验签通过但 body 非 JSON", func(t *testing.T) {
		l := newWebhookLine(t, nil)
		body := []byte(`not-json`)
		r := httptest.NewRequest("POST", "/webhook/line", bytes.NewReader(body))
		r.Header.Set("x-line-signature", sign.HMACSHA256Base64([]byte(testWebhookSecret), body))
		err := l.VerifyWebhook(r)
		if !errors.Is(err, ErrWebhookMalformedBody) {
			t.Errorf("err = %v, 期望 ErrWebhookMalformedBody", err)
		}
	})
}

// TestMemorySeen 内置去重表：首见 false、重复 true、过期后重新可见。
func TestMemorySeen(t *testing.T) {
	m := newMemorySeen()
	if m.seen("k1", 50*time.Millisecond) {
		t.Error("首见应返回 false")
	}
	if !m.seen("k1", 50*time.Millisecond) {
		t.Error("窗口内重复应返回 true")
	}
	time.Sleep(60 * time.Millisecond)
	if m.seen("k1", 50*time.Millisecond) {
		t.Error("过期后应重新可见（返回 false）")
	}
}
