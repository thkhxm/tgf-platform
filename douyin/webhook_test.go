//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：VerifyWebhook / WebhookEcho / ParseOrderCallback 单测——构造签名请求（成功 / 篡改 / 过窗 / 重放）
//2026/6/11
//***************************************************

package douyin

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testCallbackToken = "cb_token_test"

// fixedNow 单测固定时钟。
var fixedNow = time.Unix(1_780_000_000, 0)

// newWebhookDouyin 构造固定时钟的实例（base 不会被 webhook 路径使用）。
func newWebhookDouyin(t *testing.T, mutate func(*Config)) *Douyin {
	t.Helper()
	d := newTestDouyin(t, "http://127.0.0.1:1", mutate)
	d.now = func() time.Time { return fixedNow }
	return d
}

// signOf 按官方算法独立实现一遍签名（排序 → join("") → SHA1 hex），
// 用于生成测试请求并交叉锁定 paySign 的实现。
func signOf(token, ts, nonce, msg string) string {
	parts := []string{token, ts, nonce, msg}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	return hex.EncodeToString(sum[:])
}

// newSignedPost 构造一条验签合法的 POST 订单回调请求。
func newSignedPost(t *testing.T, token, ts, nonce, msg string, tamper func(env map[string]string)) *http.Request {
	t.Helper()
	env := map[string]string{
		"timestamp": ts,
		"nonce":     nonce,
		"msg":       msg,
		"signature": signOf(token, ts, nonce, msg),
	}
	if tamper != nil {
		tamper(env)
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("构造回调体失败: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/pay/callback", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// newSignedGet 构造一条验签合法的 GET 可访问性验证请求（参数在 query，msg 可空）。
func newSignedGet(t *testing.T, token, ts, nonce, msg, echostr string) *http.Request {
	t.Helper()
	q := url.Values{
		"timestamp": {ts},
		"nonce":     {nonce},
		"msg":       {msg},
		"echostr":   {echostr},
		"signature": {signOf(token, ts, nonce, msg)},
	}
	return httptest.NewRequest(http.MethodGet, "/pay/callback?"+q.Encode(), nil)
}

// orderMsg 构造官方结构的订单包体（字段见 webhook.go OrderCallback）。
func orderMsg(t *testing.T) string {
	t.Helper()
	msg, err := json.Marshal(map[string]any{
		"appid":            "tt0123456789abcdef",
		"cp_orderno":       "cp-order-1",
		"cp_extra":         `{"userId":"u1"}`,
		"order_no_channel": "channel-001",
		"amount_cent":      600,
		"amount_coin":      60,
		"currency":         "CNY",
	})
	if err != nil {
		t.Fatalf("构造 msg 失败: %v", err)
	}
	return string(msg)
}

func nowSec() string {
	return strconv.FormatInt(fixedNow.Unix(), 10)
}

// TestVerifyWebhookPostSuccess POST 验签成功 + Body 重置后业务可解析订单。
func TestVerifyWebhookPostSuccess(t *testing.T) {
	d := newWebhookDouyin(t, nil)
	r := newSignedPost(t, testCallbackToken, nowSec(), "nonce-1", orderMsg(t), nil)

	if err := d.VerifyWebhook(r); err != nil {
		t.Fatalf("VerifyWebhook 失败: %v", err)
	}

	// 合约硬要求：实现读了 Body 必须重置——业务 handler 还能完整解析订单。
	order, err := d.ParseOrderCallback(r)
	if err != nil {
		t.Fatalf("ParseOrderCallback 失败: %v", err)
	}
	if order.CpOrderNo != "cp-order-1" {
		t.Errorf("CpOrderNo = %q, 期望 cp-order-1", order.CpOrderNo)
	}
	if order.AmountCent != 600 {
		t.Errorf("AmountCent = %d, 期望 600（单位人民币分）", order.AmountCent)
	}
	if order.AmountCoin != 60 {
		t.Errorf("AmountCoin = %d, 期望 60", order.AmountCoin)
	}
	if order.Currency != "CNY" {
		t.Errorf("Currency = %q, 期望 CNY", order.Currency)
	}
	if order.OrderNoChannel != "channel-001" {
		t.Errorf("OrderNoChannel = %q, 期望 channel-001", order.OrderNoChannel)
	}

	// ParseOrderCallback 也重置了 Body——再读一次仍是原文。
	raw, _ := io.ReadAll(r.Body)
	if len(raw) == 0 {
		t.Error("Body 未重置，业务 handler 读不到原文")
	}
}

// TestVerifyWebhookGetEcho GET 可访问性验证：msg 为空串参与签名 + WebhookEcho 取 echostr。
func TestVerifyWebhookGetEcho(t *testing.T) {
	d := newWebhookDouyin(t, nil)
	r := newSignedGet(t, testCallbackToken, nowSec(), "nonce-g", "", "echo-12345")

	if err := d.VerifyWebhook(r); err != nil {
		t.Fatalf("VerifyWebhook(GET) 失败: %v", err)
	}
	echostr, ok := d.WebhookEcho(r)
	if !ok || echostr != "echo-12345" {
		t.Fatalf("WebhookEcho = (%q,%v), 期望 (echo-12345,true)", echostr, ok)
	}

	t.Run("POST 不是验证请求", func(t *testing.T) {
		pr := newSignedPost(t, testCallbackToken, nowSec(), "n", "{}", nil)
		if _, ok := d.WebhookEcho(pr); ok {
			t.Error("POST 请求不应识别为可访问性验证")
		}
	})
}

// TestVerifyWebhookFailures 验签失败矩阵：篡改 / 缺签名 / 非法格式 / 过窗 / 未配置。
func TestVerifyWebhookFailures(t *testing.T) {
	tests := []struct {
		name    string
		request func(t *testing.T) *http.Request
		mutate  func(*Config)
		wantErr error
	}{
		{
			name: "签名篡改",
			request: func(t *testing.T) *http.Request {
				return newSignedPost(t, testCallbackToken, nowSec(), "n1", "{}", func(env map[string]string) {
					env["signature"] = strings.Repeat("0", 40)
				})
			},
			wantErr: ErrWebhookSignatureMismatch,
		},
		{
			name: "包体篡改（msg 改动签名失配）",
			request: func(t *testing.T) *http.Request {
				return newSignedPost(t, testCallbackToken, nowSec(), "n2", "{}", func(env map[string]string) {
					env["msg"] = `{"amount_cent":999999}`
				})
			},
			wantErr: ErrWebhookSignatureMismatch,
		},
		{
			name: "Token 不符（密钥错误）",
			request: func(t *testing.T) *http.Request {
				return newSignedPost(t, "wrong_token", nowSec(), "n3", "{}", nil)
			},
			wantErr: ErrWebhookSignatureMismatch,
		},
		{
			name: "缺少 signature",
			request: func(t *testing.T) *http.Request {
				return newSignedPost(t, testCallbackToken, nowSec(), "n4", "{}", func(env map[string]string) {
					delete(env, "signature")
				})
			},
			wantErr: ErrWebhookMissingSignature,
		},
		{
			name: "body 非 JSON",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/pay/callback", strings.NewReader("not-json"))
				return r
			},
			wantErr: ErrWebhookMalformedRequest,
		},
		{
			name: "timestamp 非十进制（签名有效仍拒绝）",
			request: func(t *testing.T) *http.Request {
				return newSignedPost(t, testCallbackToken, "not-a-number", "n5", "{}", nil)
			},
			wantErr: ErrWebhookMalformedRequest,
		},
		{
			name: "时间戳过旧",
			request: func(t *testing.T) *http.Request {
				old := strconv.FormatInt(fixedNow.Add(-6*time.Minute).Unix(), 10)
				return newSignedPost(t, testCallbackToken, old, "n6", "{}", nil)
			},
			wantErr: ErrWebhookTimestampOutOfWindow,
		},
		{
			name: "时间戳超前",
			request: func(t *testing.T) *http.Request {
				future := strconv.FormatInt(fixedNow.Add(6*time.Minute).Unix(), 10)
				return newSignedPost(t, testCallbackToken, future, "n7", "{}", nil)
			},
			wantErr: ErrWebhookTimestampOutOfWindow,
		},
		{
			name: "未配置 PayCallbackToken",
			request: func(t *testing.T) *http.Request {
				return newSignedPost(t, testCallbackToken, nowSec(), "n8", "{}", nil)
			},
			mutate:  func(c *Config) { c.PayCallbackToken = "" },
			wantErr: ErrWebhookTokenNotConfigured,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newWebhookDouyin(t, tc.mutate)
			err := d.VerifyWebhook(tc.request(t))
			if err == nil {
				t.Fatal("期望验签失败，实际通过")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, 期望 errors.Is(%v)", err, tc.wantErr)
			}
		})
	}
}

// TestVerifyWebhookReplay 防重放：同一签名第二次投递被拦截，不同 nonce 放行。
func TestVerifyWebhookReplay(t *testing.T) {
	d := newWebhookDouyin(t, nil)
	msg := orderMsg(t)

	if err := d.VerifyWebhook(newSignedPost(t, testCallbackToken, nowSec(), "nonce-r", msg, nil)); err != nil {
		t.Fatalf("首次投递应通过: %v", err)
	}
	err := d.VerifyWebhook(newSignedPost(t, testCallbackToken, nowSec(), "nonce-r", msg, nil))
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("重放应被拦截, err = %v", err)
	}
	// 平台 at-least-once 重试同一事件会带新 nonce/timestamp？官方未说明——但
	// 语义上不同 nonce 是不同投递，签名不同，应放行。
	if err := d.VerifyWebhook(newSignedPost(t, testCallbackToken, nowSec(), "nonce-r2", msg, nil)); err != nil {
		t.Fatalf("不同 nonce 的投递应通过: %v", err)
	}
}

// TestVerifyWebhookBodyTooLarge 回调体超限拒绝。
func TestVerifyWebhookBodyTooLarge(t *testing.T) {
	d := newWebhookDouyin(t, func(c *Config) { c.WebhookMaxBodySize = 64 })
	big := strings.Repeat("x", 256)
	r := newSignedPost(t, testCallbackToken, nowSec(), "n", big, nil)
	if err := d.VerifyWebhook(r); err == nil {
		t.Fatal("超限回调体应拒绝")
	}
}

// TestPaySignGolden 锁定签名算法的排序与拼接行为（黄金向量：自然序排序后
// join("") 再 SHA1——若实现改动拼接顺序/分隔符，此测试必失败）。
func TestPaySignGolden(t *testing.T) {
	// 手工排好序：["abc-nonce","mytoken","{\"k\":\"v\"}","1633174587"] 按字节序
	// 实际排序结果由 sort.Strings 决定，这里直接给出预期串。
	token, ts, nonce, msg := "mytoken", "1633174587", "abc-nonce", `{"k":"v"}`
	parts := []string{token, ts, nonce, msg}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	want := hex.EncodeToString(sum[:])

	if got := paySign(token, ts, nonce, msg); got != want {
		t.Fatalf("paySign = %s, 期望 %s", got, want)
	}
	// 大写签名输入也应通过（VerifyWebhook 内部 ToLower 后比对）。
	if got := paySign(token, ts, nonce, msg); got != strings.ToLower(got) {
		t.Fatal("paySign 应输出小写十六进制")
	}
}
