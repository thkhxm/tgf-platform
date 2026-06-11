//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description facebook：VerifyPayment 单测——signedRequest 验签 / 字段核对 / 金额换算 / mock 交易识别
//2026/6/11
//***************************************************

package facebook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf/v2/platform"
)

// makeSignedRequest 按官方协议（HMAC-SHA256(key=secret, data=base64url(载荷))，
// 签名段 base64url 编码，"." 拼接）构造 signedRequest——与实现独立实现一遍，
// 互为印证。
func makeSignedRequest(secret, payloadJSON string) string {
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigB64 + "." + payloadB64
}

// validPayload 官方文档 2021-08-25 后形态的标准载荷（id 类字段为字符串）。
const validPayload = `{"algorithm":"HMAC-SHA256","app_id":"` + testAppID + `","is_consumed":false,` +
	`"issued_at":1628530124,"payment_action_type":"charge","payment_id":"2373285299469015",` +
	`"product_id":"sample_product","purchase_price":{"amount":"0.89","currency":"USD"},` +
	`"purchase_time":1628171348,"purchase_token":"10102867843382867"}`

func newPaymentFacebook(t *testing.T) *Facebook {
	t.Helper()
	f, err := New(Config{AppID: testAppID, AppSecret: testAppSecret})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return f
}

// TestVerifyPayment 表驱动覆盖验签 / 核对 / 映射的各分支。
func TestVerifyPayment(t *testing.T) {
	tests := []struct {
		name    string
		receipt platform.PaymentReceipt
		wantErr error // nil = 期望成功；否则 errors.Is 断言哨兵
		// wantPlainErr 表示期望失败但无哨兵（算法声明异常等）
		wantPlainErr bool
		check        func(t *testing.T, r *platform.PaymentResult)
	}{
		{
			name: "合法 signedRequest → 标准化结果",
			receipt: platform.PaymentReceipt{
				Platform: PlatformName,
				OrderID:  "biz-001",
				Payload:  makeSignedRequest(testAppSecret, validPayload),
			},
			check: func(t *testing.T, r *platform.PaymentResult) {
				if !r.Paid {
					t.Error("Paid 应为 true")
				}
				if r.Sandbox {
					t.Error("非 mock 交易 Sandbox 应为 false")
				}
				if r.OrderID != "biz-001" {
					t.Errorf("OrderID = %q", r.OrderID)
				}
				if r.TransactionID != "2373285299469015" {
					t.Errorf("TransactionID = %q, 应为 payment_id", r.TransactionID)
				}
				if r.ProductID != "sample_product" {
					t.Errorf("ProductID = %q", r.ProductID)
				}
				// "0.89" USD → 最小单位 89 cents
				if r.Amount != 89 || r.Currency != "USD" {
					t.Errorf("Amount/Currency = %d/%q, 期望 89/USD", r.Amount, r.Currency)
				}
				// purchase_time 1628171348 是 10 位 Unix 秒
				if !r.PaidAt.Equal(time.Unix(1628171348, 0)) {
					t.Errorf("PaidAt = %v", r.PaidAt)
				}
				if r.Raw["purchase_token"] != "10102867843382867" {
					t.Errorf(`Raw["purchase_token"] = %q`, r.Raw["purchase_token"])
				}
				if r.Raw["is_consumed"] != "false" {
					t.Errorf(`Raw["is_consumed"] = %q`, r.Raw["is_consumed"])
				}
			},
		},
		{
			name: "2021-08-25 前的数字形态 id（含超出 float64 安全范围的大整数）→ 按原文精确透传",
			receipt: platform.PaymentReceipt{
				Payload: makeSignedRequest(testAppSecret,
					`{"algorithm":"HMAC-SHA256","app_id":`+testAppID+`,"is_consumed":false,`+
						`"issued_at":1628530124,"payment_action_type":"charge","payment_id":2373285299469015,`+
						`"product_id":"sample_product","purchase_price":{"amount":"0.01","currency":"USD"},`+
						`"purchase_time":1628171348,"purchase_token":10102867843382867}`),
			},
			check: func(t *testing.T, r *platform.PaymentResult) {
				// 10102867843382867 经 float64 会失真为 ...868，必须按原文精确保留
				if r.Raw["purchase_token"] != "10102867843382867" {
					t.Errorf("大整数 purchase_token 失真: %q", r.Raw["purchase_token"])
				}
				if r.TransactionID != "2373285299469015" {
					t.Errorf("数字形态 payment_id 归一失败: %q", r.TransactionID)
				}
				if r.Amount != 1 {
					t.Errorf("Amount = %d, 期望 1", r.Amount)
				}
			},
		},
		{
			name: "In-App Test Payment mock 交易（111111111 开头 17 位）→ Sandbox=true",
			receipt: platform.PaymentReceipt{
				Payload: makeSignedRequest(testAppSecret,
					`{"algorithm":"HMAC-SHA256","app_id":"`+testAppID+`","is_consumed":"",`+
						`"issued_at":1755529556,"payment_action_type":"charge","payment_id":"11111111123456789",`+
						`"product_id":"hey","purchase_platform":"FB",`+
						`"purchase_price":{"amount":"0.89","currency":"USD"},`+
						`"purchase_time":1755529556226,"purchase_token":"11111111123456789"}`),
			},
			check: func(t *testing.T, r *platform.PaymentResult) {
				if !r.Sandbox {
					t.Error("mock 交易应判定 Sandbox=true")
				}
				// purchase_time 1755529556226 是 13 位 Unix 毫秒（官方 mock 样例形态）
				if r.PaidAt.Unix() != 1755529556 {
					t.Errorf("毫秒时间戳归一失败: PaidAt=%v", r.PaidAt)
				}
				// mock 样例 is_consumed 是字符串 ""——按原文透传
				if r.Raw["is_consumed"] != "" {
					t.Errorf(`Raw["is_consumed"] = %q`, r.Raw["is_consumed"])
				}
				if r.Raw["purchase_platform"] != "FB" {
					t.Errorf(`Raw["purchase_platform"] = %q`, r.Raw["purchase_platform"])
				}
			},
		},
		{
			name: "payment_action_type 缺省（旧客户端）→ 仍按有效购买",
			receipt: platform.PaymentReceipt{
				Payload: makeSignedRequest(testAppSecret,
					`{"algorithm":"HMAC-SHA256","app_id":"`+testAppID+`","issued_at":1628530124,`+
						`"payment_id":"2373285299469015","product_id":"p1","purchase_time":1628171348,`+
						`"purchase_token":"54321"}`),
			},
			check: func(t *testing.T, r *platform.PaymentResult) {
				if !r.Paid {
					t.Error("缺省 payment_action_type 应按有效购买（官方：旧客户端不下发该字段）")
				}
				// 无 purchase_price → Amount 0 / Currency 空（平台未提供）
				if r.Amount != 0 || r.Currency != "" {
					t.Errorf("无 purchase_price 时 Amount/Currency 应为零值: %d/%q", r.Amount, r.Currency)
				}
			},
		},
		{
			name: "业务期望全字段核对通过（TransactionID 用 purchase_token 也算匹配）",
			receipt: platform.PaymentReceipt{
				Platform:      PlatformName,
				TransactionID: "10102867843382867",
				ProductID:     "sample_product",
				Amount:        89,
				Currency:      "usd",
				Payload:       makeSignedRequest(testAppSecret, validPayload),
			},
			check: func(t *testing.T, r *platform.PaymentResult) {
				if !r.Paid {
					t.Error("核对全部通过应 Paid=true")
				}
			},
		},
		{
			name:    "Payload 为空",
			receipt: platform.PaymentReceipt{},
			wantErr: ErrSignedRequestMalformed,
		},
		{
			name:    "receipt.Platform 是别的平台 → 防串单拒绝",
			receipt: platform.PaymentReceipt{Platform: "tiktok", Payload: makeSignedRequest(testAppSecret, validPayload)},
			wantErr: ErrReceiptMismatch,
		},
		{
			name:    "缺 . 分隔",
			receipt: platform.PaymentReceipt{Payload: "not-a-signed-request"},
			wantErr: ErrSignedRequestMalformed,
		},
		{
			name:    "签名段非法 base64",
			receipt: platform.PaymentReceipt{Payload: "!!!!." + base64.RawURLEncoding.EncodeToString([]byte(validPayload))},
			wantErr: ErrSignedRequestMalformed,
		},
		{
			name:    "App Secret 不符 → 签名比对失败",
			receipt: platform.PaymentReceipt{Payload: makeSignedRequest("wrong-secret", validPayload)},
			wantErr: ErrSignedRequestSignatureMismatch,
		},
		{
			name: "载荷被篡改（签名对不上）",
			receipt: platform.PaymentReceipt{
				Payload: func() string {
					// 保留合法签名段 + 换成篡改后的载荷段
					sigPart, _, _ := strings.Cut(makeSignedRequest(testAppSecret, validPayload), ".")
					tampered := base64.RawURLEncoding.EncodeToString(
						[]byte(`{"algorithm":"HMAC-SHA256","app_id":"` + testAppID + `","product_id":"hacked"}`))
					return sigPart + "." + tampered
				}(),
			},
			wantErr: ErrSignedRequestSignatureMismatch,
		},
		{
			name: "签名有效但载荷不是 JSON",
			receipt: platform.PaymentReceipt{
				Payload: makeSignedRequest(testAppSecret, "this is not json"),
			},
			wantErr: ErrSignedRequestMalformed,
		},
		{
			name: "algorithm 声明异常",
			receipt: platform.PaymentReceipt{
				Payload: makeSignedRequest(testAppSecret,
					`{"algorithm":"HMAC-MD5","app_id":"`+testAppID+`","payment_id":"1","product_id":"p"}`),
			},
			wantPlainErr: true,
		},
		{
			name: "载荷 app_id 归属他人应用 → 串单拒绝",
			receipt: platform.PaymentReceipt{
				Payload: makeSignedRequest(testAppSecret,
					`{"algorithm":"HMAC-SHA256","app_id":"999000999","payment_id":"1","product_id":"p"}`),
			},
			wantErr: ErrReceiptMismatch,
		},
		{
			name: "payment_action_type 未知取值 → 拒绝判定已支付",
			receipt: platform.PaymentReceipt{
				Payload: makeSignedRequest(testAppSecret,
					`{"algorithm":"HMAC-SHA256","app_id":"`+testAppID+`","payment_action_type":"refund",`+
						`"payment_id":"1","product_id":"p"}`),
			},
			wantPlainErr: true,
		},
		{
			name: "product_id 与期望不符 → 货不对板拒绝",
			receipt: platform.PaymentReceipt{
				ProductID: "expected_product",
				Payload:   makeSignedRequest(testAppSecret, validPayload),
			},
			wantErr: ErrReceiptMismatch,
		},
		{
			name: "TransactionID 与 payment_id / purchase_token 均不符",
			receipt: platform.PaymentReceipt{
				TransactionID: "another-txn",
				Payload:       makeSignedRequest(testAppSecret, validPayload),
			},
			wantErr: ErrReceiptMismatch,
		},
		{
			name: "金额与期望不符",
			receipt: platform.PaymentReceipt{
				Amount:  100, // 平台是 89
				Payload: makeSignedRequest(testAppSecret, validPayload),
			},
			wantErr: ErrReceiptMismatch,
		},
		{
			name: "币种与期望不符",
			receipt: platform.PaymentReceipt{
				Amount:   89,
				Currency: "CNY",
				Payload:  makeSignedRequest(testAppSecret, validPayload),
			},
			wantErr: ErrReceiptMismatch,
		},
		{
			name: "业务期望核对金额但载荷无 purchase_price → 拒绝",
			receipt: platform.PaymentReceipt{
				Amount: 89,
				Payload: makeSignedRequest(testAppSecret,
					`{"algorithm":"HMAC-SHA256","app_id":"`+testAppID+`","payment_action_type":"charge",`+
						`"payment_id":"1","product_id":"p","purchase_token":"2"}`),
			},
			wantErr: ErrReceiptMismatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newPaymentFacebook(t)
			result, err := f.VerifyPayment(context.Background(), tc.receipt)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("期望 errors.Is(err, %v)，实际: %v", tc.wantErr, err)
				}
				return
			}
			if tc.wantPlainErr {
				if err == nil {
					t.Fatal("期望失败，实际成功")
				}
				return
			}
			if err != nil {
				t.Fatalf("期望成功，实际: %v", err)
			}
			if result.Platform != PlatformName {
				t.Errorf("Platform = %q", result.Platform)
			}
			if tc.check != nil {
				tc.check(t, result)
			}
		})
	}
}

// TestAmountToMinorUnits 金额换算（ISO 4217 小数位）。
func TestAmountToMinorUnits(t *testing.T) {
	tests := []struct {
		amount   string
		currency string
		want     int64
		wantErr  bool
	}{
		{"0.01", "USD", 1, false},
		{"0.89", "USD", 89, false},
		{"10.99", "USD", 1099, false},
		{"0.1", "USD", 10, false},
		{"5", "USD", 500, false},
		{"150", "JPY", 150, false},
		{"1.234", "KWD", 1234, false},
		{"1.5", "JPY", 0, true},   // JPY 无小数位
		{"1.234", "USD", 0, true}, // 超出 USD 两位小数
		{"-1", "USD", 0, true},
		{"abc", "USD", 0, true},
		{"", "USD", 0, true},
		{"1.2.3", "USD", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.amount+"_"+tc.currency, func(t *testing.T) {
			got, err := amountToMinorUnits(tc.amount, tc.currency)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望失败，实际得到 %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望成功，实际: %v", err)
			}
			if got != tc.want {
				t.Errorf("= %d, 期望 %d", got, tc.want)
			}
		})
	}
}

// TestIsMockPurchaseID mock 交易特征识别（官方：111111111 开头 17 位数字）。
func TestIsMockPurchaseID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"11111111123456789", true},
		{"11111111100000000", true},
		{"10102867843382867", false}, // 真交易样例
		{"1111111112345678", false},  // 16 位
		{"111111111234567890", false},
		{"1111111112345678x", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := isMockPurchaseID(tc.id); got != tc.want {
			t.Errorf("isMockPurchaseID(%q) = %v, 期望 %v", tc.id, got, tc.want)
		}
	}
}

// TestDecodeBase64Flexible 标准 base64 与 base64url（含/不含 padding）都能解。
func TestDecodeBase64Flexible(t *testing.T) {
	raw := []byte{0xfb, 0xef, 0xff, 0x01, 0x02}
	for name, enc := range map[string]string{
		"std":     base64.StdEncoding.EncodeToString(raw),
		"std_raw": base64.RawStdEncoding.EncodeToString(raw),
		"url":     base64.URLEncoding.EncodeToString(raw),
		"url_raw": base64.RawURLEncoding.EncodeToString(raw),
	} {
		got, err := decodeBase64Flexible(enc)
		if err != nil {
			t.Errorf("%s: 解码失败: %v", name, err)
			continue
		}
		if string(got) != string(raw) {
			t.Errorf("%s: 解码结果不符", name)
		}
	}
	if _, err := decodeBase64Flexible("!!!"); err == nil {
		t.Error("非法输入应报错")
	}
}
