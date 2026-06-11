//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description telegram：VerifyPayment 单测——httptest 模拟 getStarTransactions，成功/退款/分页/错误码/串单，表驱动
//2026/6/11
//***************************************************

package telegram

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// txJSON 构造一笔 StarTransaction 的 JSON 片段（map 形式便于按需增删字段）。
func txIncoming(id string, stars int64, date int64, userID int64, payload string) map[string]any {
	return map[string]any{
		"id":     id,
		"amount": stars,
		"date":   date,
		"source": map[string]any{
			"type":             "user",
			"transaction_type": "invoice_payment",
			"user":             map[string]any{"id": userID},
			"invoice_payload":  payload,
		},
	}
}

func txRefund(id string, stars int64, date int64, userID int64) map[string]any {
	return map[string]any{
		"id":     id,
		"amount": stars,
		"date":   date,
		"receiver": map[string]any{
			"type": "user",
			"user": map[string]any{"id": userID},
		},
	}
}

// starTxServer 起一个模拟 Bot API getStarTransactions 的 httptest server。
// pages 按 offset/limit 切片返回；status/envelope 可注入错误形态。
func starTxServer(t *testing.T, allTxs []map[string]any, status int, envelope func(txs []map[string]any) any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/getStarTransactions") {
			t.Errorf("意外的请求路径: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/bot"+testBotToken+"/") {
			t.Errorf("URL 未携带 bot token: %s", r.URL.Path)
		}
		var req getStarTransactionsReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("请求体解析失败: %v", err)
		}
		if req.Limit <= 0 || req.Limit > 100 {
			t.Errorf("limit 超出官方允许范围 1-100: %d", req.Limit)
		}
		start := req.Offset
		if start > len(allTxs) {
			start = len(allTxs)
		}
		end := start + req.Limit
		if end > len(allTxs) {
			end = len(allTxs)
		}
		w.WriteHeader(status)
		var body any
		if envelope != nil {
			body = envelope(allTxs[start:end])
		} else {
			body = map[string]any{"ok": true, "result": map[string]any{"transactions": allTxs[start:end]}}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
}

// newPaymentTelegram 构造指向 mock server 的被测实例。
func newPaymentTelegram(t *testing.T, baseURL string, extra func(*Config)) *Telegram {
	t.Helper()
	cfg := Config{BotToken: testBotToken, BotAPIBaseURL: baseURL}
	if extra != nil {
		extra(&cfg)
	}
	tg, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return tg
}

const (
	testChargeID = "stch_AbCdEf123456"
	testPayerID  = int64(123456789)
	testPaidUnix = int64(1749600000)
)

func validReceipt() platform.PaymentReceipt {
	return platform.PaymentReceipt{
		Platform:      PlatformName,
		OrderID:       "order-1001",
		TransactionID: testChargeID,
		OpenID:        "123456789",
		Amount:        50,
		Currency:      "XTR",
	}
}

func TestVerifyPayment_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		txs        []map[string]any
		status     int
		envelope   func(txs []map[string]any) any
		receipt    func() platform.PaymentReceipt
		cfg        func(*Config)
		wantErrSub string
		wantCode   string
		wantRetry  bool
		check      func(t *testing.T, res *platform.PaymentResult)
	}{
		{
			name:    "成功_找到入账交易",
			txs:     []map[string]any{txIncoming(testChargeID, 50, testPaidUnix, testPayerID, "order-1001")},
			status:  http.StatusOK,
			receipt: validReceipt,
			check: func(t *testing.T, res *platform.PaymentResult) {
				if !res.Paid {
					t.Error("Paid 应为 true")
				}
				if res.Amount != 50 {
					t.Errorf("Amount = %d, 期望 50（整数 Star）", res.Amount)
				}
				if res.Currency != "XTR" {
					t.Errorf("Currency = %q, 期望 XTR", res.Currency)
				}
				if res.TransactionID != testChargeID {
					t.Errorf("TransactionID = %q", res.TransactionID)
				}
				if res.OrderID != "order-1001" {
					t.Errorf("OrderID = %q", res.OrderID)
				}
				if !res.PaidAt.Equal(time.Unix(testPaidUnix, 0)) {
					t.Errorf("PaidAt = %v", res.PaidAt)
				}
				if res.Sandbox {
					t.Error("非测试环境 Sandbox 应为 false")
				}
				if res.Raw["invoice_payload"] != "order-1001" {
					t.Errorf("Raw[invoice_payload] = %q", res.Raw["invoice_payload"])
				}
				if res.Raw["refunded"] != "false" {
					t.Errorf("Raw[refunded] = %q", res.Raw["refunded"])
				}
			},
		},
		{
			name: "成功但已退款_Paid为false",
			txs: []map[string]any{
				txIncoming(testChargeID, 50, testPaidUnix, testPayerID, "order-1001"),
				txRefund(testChargeID, 50, testPaidUnix+100, testPayerID),
			},
			status:  http.StatusOK,
			receipt: validReceipt,
			check: func(t *testing.T, res *platform.PaymentResult) {
				if res.Paid {
					t.Error("已退款交易 Paid 应为 false")
				}
				if res.Raw["refunded"] != "true" {
					t.Errorf("Raw[refunded] = %q, 期望 true", res.Raw["refunded"])
				}
			},
		},
		{
			name: "成功_第二页命中（分页）",
			txs: func() []map[string]any {
				var txs []map[string]any
				for i := 0; i < 3; i++ { // 页大小 3：第一页 3 笔无关交易
					txs = append(txs, txIncoming("other_"+strings.Repeat("x", i+1), 1, testPaidUnix, 42, ""))
				}
				return append(txs, txIncoming(testChargeID, 50, testPaidUnix, testPayerID, "order-1001"))
			}(),
			status:  http.StatusOK,
			receipt: validReceipt,
			cfg:     func(c *Config) { c.PaymentScanPageSize = 3 },
			check: func(t *testing.T, res *platform.PaymentResult) {
				if !res.Paid {
					t.Error("分页第二页命中应 Paid=true")
				}
			},
		},
		{
			name:       "失败_未找到交易",
			txs:        []map[string]any{txIncoming("stch_other", 10, testPaidUnix, 42, "")},
			status:     http.StatusOK,
			receipt:    validReceipt,
			wantErrSub: "未在最近",
			wantCode:   "transaction_not_found",
		},
		{
			name: "失败_扫描达上限未找到",
			txs: func() []map[string]any {
				var txs []map[string]any
				for i := 0; i < 10; i++ { // 页大小 2 × 上限 2 页 = 只看前 4 笔
					txs = append(txs, txIncoming("other", 1, testPaidUnix, 42, ""))
				}
				return append(txs, txIncoming(testChargeID, 50, testPaidUnix, testPayerID, ""))
			}(),
			status:  http.StatusOK,
			receipt: validReceipt,
			cfg: func(c *Config) {
				c.PaymentScanPageSize = 2
				c.PaymentScanMaxPages = 2
			},
			wantErrSub: "未在最近 4 笔",
			wantCode:   "transaction_not_found",
		},
		{
			name:       "失败_付款人不匹配（串单）",
			txs:        []map[string]any{txIncoming(testChargeID, 50, testPaidUnix, 99999, "")},
			status:     http.StatusOK,
			receipt:    validReceipt,
			wantErrSub: "付款人不匹配",
		},
		{
			name: "失败_交易类型非invoice_payment",
			txs: []map[string]any{{
				"id": testChargeID, "amount": int64(50), "date": testPaidUnix,
				"source": map[string]any{
					"type":             "user",
					"transaction_type": "gift_purchase",
					"user":             map[string]any{"id": testPayerID},
				},
			}},
			status:     http.StatusOK,
			receipt:    validReceipt,
			wantErrSub: "invoice_payment",
		},
		{
			name:   "失败_平台业务错误ok_false",
			txs:    nil,
			status: http.StatusUnauthorized,
			envelope: func(_ []map[string]any) any {
				return map[string]any{"ok": false, "error_code": 401, "description": "Unauthorized"}
			},
			receipt:    validReceipt,
			wantErrSub: "Unauthorized",
			wantCode:   "401",
		},
		{
			name:   "失败_限频429可重试",
			txs:    nil,
			status: http.StatusTooManyRequests,
			envelope: func(_ []map[string]any) any {
				return map[string]any{"ok": false, "error_code": 429, "description": "Too Many Requests: retry after 5"}
			},
			receipt:   validReceipt,
			wantCode:  "429",
			wantRetry: true,
		},
		{
			name:   "失败_5xx非JSON应答可重试",
			txs:    nil,
			status: http.StatusBadGateway,
			envelope: func(_ []map[string]any) any {
				return "bad gateway" // 字符串 → 非预期结构，但 JSON 合法；用下方原始 handler 更准
			},
			receipt:    validReceipt,
			wantErrSub: "",
			wantRetry:  true,
		},
		{
			name:       "失败_TransactionID为空",
			txs:        nil,
			status:     http.StatusOK,
			receipt:    func() platform.PaymentReceipt { r := validReceipt(); r.TransactionID = ""; return r },
			wantErrSub: "TransactionID",
		},
		{
			name:       "失败_Platform串单",
			txs:        nil,
			status:     http.StatusOK,
			receipt:    func() platform.PaymentReceipt { r := validReceipt(); r.Platform = "wechat"; return r },
			wantErrSub: "串单",
		},
		{
			name:    "成功_receipt未带OpenID时跳过付款人核对",
			txs:     []map[string]any{txIncoming(testChargeID, 50, testPaidUnix, testPayerID, "")},
			status:  http.StatusOK,
			receipt: func() platform.PaymentReceipt { r := validReceipt(); r.OpenID = ""; return r },
			check: func(t *testing.T, res *platform.PaymentResult) {
				if res.Raw["payer_user_id"] != "123456789" {
					t.Errorf("payer_user_id = %q", res.Raw["payer_user_id"])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := starTxServer(t, tc.txs, tc.status, tc.envelope)
			defer srv.Close()
			tg := newPaymentTelegram(t, srv.URL, tc.cfg)
			res, err := tg.VerifyPayment(context.Background(), tc.receipt())
			if tc.wantErrSub == "" && tc.wantCode == "" && !tc.wantRetry {
				if err != nil {
					t.Fatalf("期望成功, 得到错误: %v", err)
				}
				if tc.check != nil {
					tc.check(t, res)
				}
				return
			}
			if err == nil {
				t.Fatalf("期望错误, 得到成功: %+v", res)
			}
			if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("错误信息 %q 不含 %q", err.Error(), tc.wantErrSub)
			}
			if tc.wantCode != "" {
				if got := errs.CodeOf(err); got != tc.wantCode {
					t.Errorf("错误码 = %q, 期望 %q", got, tc.wantCode)
				}
			}
			if got := errs.IsRetryable(err); got != tc.wantRetry {
				t.Errorf("Retryable = %v, 期望 %v", got, tc.wantRetry)
			}
		})
	}
}

// TestVerifyPayment_Sandbox 验证测试环境走 /test/ 路径且结果 Sandbox=true。
func TestVerifyPayment_Sandbox(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"result": map[string]any{"transactions": []any{txIncoming(testChargeID, 50, testPaidUnix, testPayerID, "")}},
		})
	}))
	defer srv.Close()

	tg := newPaymentTelegram(t, srv.URL, func(c *Config) { c.TestEnvironment = true })
	res, err := tg.VerifyPayment(context.Background(), validReceipt())
	if err != nil {
		t.Fatalf("期望成功: %v", err)
	}
	// 测试环境路径形态文档：
	// https://core.telegram.org/bots/webapps#using-bots-in-the-test-environment（2026-06-11 拉取）
	wantPath := "/bot" + testBotToken + "/test/getStarTransactions"
	if gotPath != wantPath {
		t.Errorf("请求路径 = %q, 期望 %q", gotPath, wantPath)
	}
	if !res.Sandbox {
		t.Error("测试环境 Sandbox 应为 true")
	}
}

// TestVerifyPayment_NetworkError 验证传输层失败标记可重试。
func TestVerifyPayment_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // 立刻关掉 → 连接拒绝
	tg := newPaymentTelegram(t, srv.URL, nil)
	_, err := tg.VerifyPayment(context.Background(), validReceipt())
	if err == nil {
		t.Fatal("期望网络错误")
	}
	if !errs.IsRetryable(err) {
		t.Errorf("网络错误应标记可重试: %v", err)
	}
}
