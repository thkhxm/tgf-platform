//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：VerifyWebhook 单测——验签 / 时间戳窗口 / 防重放 / Body 重置
//2026/6/11
//***************************************************

package tiktok

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testWebhookSecret = "cs_test"

// signWebhook 按官方算法（HMAC-SHA256(client_secret, t + "." + body) 十六进制）
// 生成签名，模拟 TikTok 侧签名行为（与实现独立实现一遍，互为印证）。
func signWebhook(secret, ts, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + body))
	return hex.EncodeToString(mac.Sum(nil))
}

// newWebhookTikTok 构造固定时钟的实例。
func newWebhookTikTok(t *testing.T, fixedNow time.Time, mutate func(*Config)) *TikTok {
	t.Helper()
	cfg := Config{ClientKey: "ck_test", ClientSecret: testWebhookSecret}
	if mutate != nil {
		mutate(&cfg)
	}
	tk, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	tk.now = func() time.Time { return fixedNow }
	return tk
}

// buildWebhookRequest 构造带 Tiktok-Signature header 的回调请求。
func buildWebhookRequest(body, sigHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://game.example.com/webhook/tiktok", strings.NewReader(body))
	if sigHeader != "" {
		// 官方示例 header 名写作 "Tiktok-Signature"（http.Header 大小写不敏感）
		r.Header.Set("Tiktok-Signature", sigHeader)
	}
	return r
}

// TestVerifyWebhook 表驱动覆盖验签 / header 解析 / 时间戳窗口的各分支。
func TestVerifyWebhook(t *testing.T) {
	now := time.Unix(1765432100, 0)
	nowTS := strconv.FormatInt(now.Unix(), 10)
	const payload = `{"client_key":"ck_test","event":"minis.trade_order.redeem.success","create_time":1765432099,"user_openid":"open-id-1","content":"{\"trade_order_id\":\"TOID1\",\"order_id\":\"biz-1\"}"}`

	tests := []struct {
		name      string
		sigHeader func() string
		body      string
		wantErr   error // nil = 期望通过；否则 errors.Is 断言哨兵
	}{
		{
			name:      "合法签名 + 窗口内时间戳 → 通过",
			sigHeader: func() string { return "t=" + nowTS + ",s=" + signWebhook(testWebhookSecret, nowTS, payload) },
			body:      payload,
			wantErr:   nil,
		},
		{
			name: "大写十六进制签名同样通过（hex 解码大小写不敏感）",
			sigHeader: func() string {
				return "t=" + nowTS + ",s=" + strings.ToUpper(signWebhook(testWebhookSecret, nowTS, payload))
			},
			body:    payload,
			wantErr: nil,
		},
		{
			name:      "缺签名 header",
			sigHeader: func() string { return "" },
			body:      payload,
			wantErr:   ErrWebhookMissingSignature,
		},
		{
			name:      "header 缺 s 元素",
			sigHeader: func() string { return "t=" + nowTS },
			body:      payload,
			wantErr:   ErrWebhookMalformedSignature,
		},
		{
			name:      "header 缺 t 元素",
			sigHeader: func() string { return "s=" + signWebhook(testWebhookSecret, nowTS, payload) },
			body:      payload,
			wantErr:   ErrWebhookMalformedSignature,
		},
		{
			name:      "签名错误（密钥不符）",
			sigHeader: func() string { return "t=" + nowTS + ",s=" + signWebhook("wrong-secret", nowTS, payload) },
			body:      payload,
			wantErr:   ErrWebhookSignatureMismatch,
		},
		{
			name:      "签名非法（非 hex）",
			sigHeader: func() string { return "t=" + nowTS + ",s=zzzz" },
			body:      payload,
			wantErr:   ErrWebhookSignatureMismatch,
		},
		{
			name: "body 被篡改",
			sigHeader: func() string {
				return "t=" + nowTS + ",s=" + signWebhook(testWebhookSecret, nowTS, payload)
			},
			body:    `{"tampered":true}`,
			wantErr: ErrWebhookSignatureMismatch,
		},
		{
			name: "时间戳被单独篡改（签名随之失配）",
			sigHeader: func() string {
				other := strconv.FormatInt(now.Unix()-1, 10)
				return "t=" + nowTS + ",s=" + signWebhook(testWebhookSecret, other, payload)
			},
			body:    payload,
			wantErr: ErrWebhookSignatureMismatch,
		},
		{
			name: "签名有效但时间戳过旧（超出 5 分钟窗口）",
			sigHeader: func() string {
				old := strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10)
				return "t=" + old + ",s=" + signWebhook(testWebhookSecret, old, payload)
			},
			body:    payload,
			wantErr: ErrWebhookTimestampOutOfWindow,
		},
		{
			name: "签名有效但时间戳超前（超出窗口）",
			sigHeader: func() string {
				future := strconv.FormatInt(now.Add(6*time.Minute).Unix(), 10)
				return "t=" + future + ",s=" + signWebhook(testWebhookSecret, future, payload)
			},
			body:    payload,
			wantErr: ErrWebhookTimestampOutOfWindow,
		},
		{
			name: "时间戳非十进制（即便签名按原串算对也判格式非法）",
			sigHeader: func() string {
				return "t=abc,s=" + signWebhook(testWebhookSecret, "abc", payload)
			},
			body:    payload,
			wantErr: ErrWebhookMalformedSignature,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tk := newWebhookTikTok(t, now, nil)
			r := buildWebhookRequest(tc.body, tc.sigHeader())
			err := tk.VerifyWebhook(r)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("期望通过，实际: %v", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("期望 errors.Is(err, %v)，实际: %v", tc.wantErr, err)
			}
			// 合约硬要求：无论结果如何，Body 必须被重置，业务 handler 可再读。
			got, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Fatalf("重读 Body 失败: %v", readErr)
			}
			if string(got) != tc.body {
				t.Errorf("Body 未正确重置: %q != %q", got, tc.body)
			}
		})
	}
}

// TestVerifyWebhookReplay 防重放：同一合法请求第二次投递被拦截。
func TestVerifyWebhookReplay(t *testing.T) {
	now := time.Unix(1765432100, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	const payload = `{"event":"e1"}`
	sig := "t=" + ts + ",s=" + signWebhook(testWebhookSecret, ts, payload)

	tk := newWebhookTikTok(t, now, nil)
	if err := tk.VerifyWebhook(buildWebhookRequest(payload, sig)); err != nil {
		t.Fatalf("首次投递应通过: %v", err)
	}
	err := tk.VerifyWebhook(buildWebhookRequest(payload, sig))
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("重放应被拦截，实际: %v", err)
	}

	// 不同 payload（不同签名）不受影响
	const payload2 = `{"event":"e2"}`
	sig2 := "t=" + ts + ",s=" + signWebhook(testWebhookSecret, ts, payload2)
	if err := tk.VerifyWebhook(buildWebhookRequest(payload2, sig2)); err != nil {
		t.Fatalf("不同事件不应被去重拦截: %v", err)
	}
}

// TestVerifyWebhookCustomSeen 注入自定义去重钩子（多实例共享存储场景）。
func TestVerifyWebhookCustomSeen(t *testing.T) {
	now := time.Unix(1765432100, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	const payload = `{"event":"e1"}`
	wantKey := signWebhook(testWebhookSecret, ts, payload)

	var gotKey string
	var gotTTL time.Duration
	tk := newWebhookTikTok(t, now, func(c *Config) {
		c.WebhookSeen = func(key string, ttl time.Duration) bool {
			gotKey, gotTTL = key, ttl
			return true // 模拟共享存储里已存在 → 重放
		}
	})
	err := tk.VerifyWebhook(buildWebhookRequest(payload, "t="+ts+",s="+wantKey))
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("期望重放拦截，实际: %v", err)
	}
	if gotKey != wantKey {
		t.Errorf("去重 key = %q, 期望签名值 %q", gotKey, wantKey)
	}
	if gotTTL != 2*DefaultWebhookTolerance {
		t.Errorf("去重 ttl = %v, 期望 %v", gotTTL, 2*DefaultWebhookTolerance)
	}

	// 验签失败的请求不应进入去重表（垃圾签名不可污染共享存储）
	gotKey = ""
	_ = tk.VerifyWebhook(buildWebhookRequest(payload, "t="+ts+",s="+signWebhook("wrong", ts, payload)))
	if gotKey != "" {
		t.Error("验签失败的请求不应调用去重钩子")
	}
}

// TestVerifyWebhookBodyTooLarge 回调体超限拒绝。
func TestVerifyWebhookBodyTooLarge(t *testing.T) {
	now := time.Unix(1765432100, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	body := strings.Repeat("x", 128)
	sig := "t=" + ts + ",s=" + signWebhook(testWebhookSecret, ts, body)

	tk := newWebhookTikTok(t, now, func(c *Config) { c.WebhookMaxBodySize = 64 })
	if err := tk.VerifyWebhook(buildWebhookRequest(body, sig)); err == nil {
		t.Fatal("超限回调体应被拒绝")
	}
}

// TestMemorySeen 内存去重表：首见 / 重复 / 过期复位。
func TestMemorySeen(t *testing.T) {
	m := newMemorySeen()
	if m.seen("k1", 30*time.Millisecond) {
		t.Fatal("首见应返回 false")
	}
	if !m.seen("k1", 30*time.Millisecond) {
		t.Fatal("窗口内重复应返回 true")
	}
	if m.seen("k2", 30*time.Millisecond) {
		t.Fatal("不同 key 应互不影响")
	}
	time.Sleep(50 * time.Millisecond)
	if m.seen("k1", 30*time.Millisecond) {
		t.Fatal("过期后应视为首见")
	}
}

// TestParseSignatureHeader header 解析的边界。
func TestParseSignatureHeader(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantTS  string
		wantSig string
		wantOK  bool
	}{
		{"标准格式", "t=1633174587,s=abc123", "1633174587", "abc123", true},
		{"元素首尾空格被剥离", " t=1633174587 , s=abc123 ", "1633174587", "abc123", true},
		{"逗号后空格", "t=1633174587, s=abc123", "1633174587", "abc123", true},
		{"顺序颠倒", "s=abc123,t=1633174587", "1633174587", "abc123", true},
		{"缺 t", "s=abc123", "", "abc123", false},
		{"缺 s", "t=1633174587", "1633174587", "", false},
		{"空串", "", "", "", false},
		{"无等号元素被忽略", "x,t=1,s=2", "1", "2", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, sig, ok := parseSignatureHeader(tc.header)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, 期望 %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if ts != tc.wantTS || sig != tc.wantSig {
				t.Errorf("(ts, sig) = (%q, %q), 期望 (%q, %q)", ts, sig, tc.wantTS, tc.wantSig)
			}
		})
	}
}
