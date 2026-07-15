//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：Payment 单测——httptest mock 平台应答（成功/各错误码/字段缺失/串单防御），不打真实 TikTok
//2026/6/11
//***************************************************

package tiktok

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

const testUserToken = "act.user-token-pay"

// TestCreateTradeOrderSuccess 成功路径：断言请求构造（路径/方法/鉴权/请求体字段，
// 字段名以官方文档为准）与 trade_order_id 返回。
func TestCreateTradeOrderSuccess(t *testing.T) {
	var gotAuth, gotCT string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, 期望 POST", r.Method)
		}
		if r.URL.Path != "/v2/minis/trade_order/create/" {
			t.Errorf("path = %s, 期望 /v2/minis/trade_order/create/", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("解析请求体失败: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		// 官方示例应答（minis-payment-apis，2026-06-11 拉取）
		_, _ = w.Write([]byte(`{"data":{"trade_order_id":"TOID1732533244259"},"error":{"code":"ok","message":"","log_id":"20241125114034036EE8AEADBAF91D5E93"}}`))
	}))
	defer srv.Close()

	tk := newTestTikTok(t, srv.URL, nil)
	tradeOrderID, err := tk.CreateTradeOrder(context.Background(), testUserToken, 100, OrderInfo{
		OrderID:      "external_order_id_003",
		ProductName:  "Wake up dad! wedding time",
		ProductID:    "external_product_id",
		Quantity:     1,
		QuantityUnit: "episode",
	})
	if err != nil {
		t.Fatalf("CreateTradeOrder 失败: %v", err)
	}
	if tradeOrderID != "TOID1732533244259" {
		t.Errorf("tradeOrderID = %q, 期望 TOID1732533244259", tradeOrderID)
	}
	// 关键断言（历史踩坑点）：鉴权必须是「付款用户的 OAuth token」。
	if want := "Bearer " + testUserToken; gotAuth != want {
		t.Errorf("Authorization = %q, 期望 %q", gotAuth, want)
	}
	if !strings.HasPrefix(gotCT, "application/json") {
		t.Errorf("Content-Type = %q, 期望 application/json", gotCT)
	}
	// 请求体字段名/取值以官方文档为准。
	if gotBody["token_type"] != "BEANS" {
		t.Errorf("token_type = %v, 期望 BEANS（官方目前唯一取值）", gotBody["token_type"])
	}
	if got, _ := gotBody["token_amount"].(float64); got != 100 {
		t.Errorf("token_amount = %v, 期望 100", gotBody["token_amount"])
	}
	oi, _ := gotBody["order_info"].(map[string]any)
	if oi == nil {
		t.Fatal("请求体缺少 order_info")
	}
	wantOI := map[string]string{
		"order_id":      "external_order_id_003",
		"product_name":  "Wake up dad! wedding time",
		"product_id":    "external_product_id",
		"quantity_unit": "episode",
	}
	for k, want := range wantOI {
		if got := oi[k]; got != want {
			t.Errorf("order_info[%s] = %v, 期望 %q", k, got, want)
		}
	}
	if got, _ := oi["quantity"].(float64); got != 1 {
		t.Errorf("order_info[quantity] = %v, 期望 1", oi["quantity"])
	}
	// 零值字段应省略（omitempty）。
	if _, has := oi["order_url"]; has {
		t.Error("order_url 零值不应出现在请求体")
	}
}

// TestCreateTradeOrderParamValidation 参数校验：非法入参不发 HTTP 请求。
func TestCreateTradeOrderParamValidation(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		tokenAmount int64
		order       OrderInfo
	}{
		{"缺用户 token", "", 100, OrderInfo{OrderID: "o1"}},
		{"token_amount 为 0", testUserToken, 0, OrderInfo{OrderID: "o1"}},
		{"token_amount 为负", testUserToken, -1, OrderInfo{OrderID: "o1"}},
		{"缺业务订单号", testUserToken, 100, OrderInfo{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			defer srv.Close()
			tk := newTestTikTok(t, srv.URL, nil)
			if _, err := tk.CreateTradeOrder(context.Background(), tc.token, tc.tokenAmount, tc.order); err == nil {
				t.Fatal("期望参数校验错误，实际 nil")
			}
			if called {
				t.Error("非法入参不应发起 HTTP 请求")
			}
		})
	}
}

// TestCreateTradeOrderErrors 错误路径：官方错误码映射（minis-error-codes，
// 2026-06-11 拉取）与协议异常。
func TestCreateTradeOrderErrors(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		body          string
		wantCode      string
		wantRetryable bool
	}{
		{
			name:   "20021002 外部订单号重复（确定性失败）",
			status: http.StatusOK,
			body:   `{"data":{},"error":{"code":"20021002","message":"Outer order ID existed","log_id":"lg1"}}`,
			// 官方处置建议 "Your external order ID is a duplicate"——不可重试
			wantCode:      "20021002",
			wantRetryable: false,
		},
		{
			name:          "40001000 参数错误（确定性失败）",
			status:        http.StatusBadRequest,
			body:          `{"data":{},"error":{"code":"40001000","message":"Invalid Parameters","log_id":"lg2"}}`,
			wantCode:      "40001000",
			wantRetryable: false,
		},
		{
			name:   "50001000 平台内部错误（官方标注可重试）",
			status: http.StatusOK,
			body:   `{"data":{},"error":{"code":"50001000","message":"TikTok Internal Error","log_id":"lg3"}}`,
			// 官方处置建议 "Retry or do nothing"
			wantCode:      "50001000",
			wantRetryable: true,
		},
		{
			name:          "access_token_invalid（token 种类用错，确定性失败）",
			status:        http.StatusUnauthorized,
			body:          `{"data":{},"error":{"code":"access_token_invalid","message":"The access token is invalid","log_id":"lg4"}}`,
			wantCode:      "access_token_invalid",
			wantRetryable: false,
		},
		{
			name:          "5xx 非 JSON（暂时性）",
			status:        http.StatusBadGateway,
			body:          `<html>bad gateway</html>`,
			wantCode:      "",
			wantRetryable: true,
		},
		{
			name:          "200 但缺 trade_order_id（协议异常）",
			status:        http.StatusOK,
			body:          `{"data":{},"error":{"code":"ok","message":""}}`,
			wantCode:      "",
			wantRetryable: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			tk := newTestTikTok(t, srv.URL, nil)
			_, err := tk.CreateTradeOrder(context.Background(), testUserToken, 100, OrderInfo{OrderID: "o1"})
			if err == nil {
				t.Fatal("期望错误，实际 nil")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error，实际 %T: %v", err, err)
			}
			if pe.Platform != "tiktok" || pe.Op != "trade_order_create" {
				t.Errorf("Platform/Op = %s/%s", pe.Platform, pe.Op)
			}
			if pe.Code != tc.wantCode {
				t.Errorf("Code = %q, 期望 %q", pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetryable)
			}
		})
	}
}

// TestVerifyPaymentSuccess 成功路径：断言查单请求构造与 PaymentResult 映射
// （状态枚举以官方文档为准：仅 SUCCESS 视为已支付）。
func TestVerifyPaymentSuccess(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		wantPaid bool
	}{
		{"SUCCESS → Paid", "SUCCESS", true},
		{"PENDING → 未支付", "PENDING", false},
		{"未知状态保守按未支付（宁可漏发不可错发）", "UNKNOWN_FUTURE_STATUS", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotAuth string
			var gotBody map[string]string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v2/minis/trade_order/query/" {
					t.Errorf("path = %s, 期望 /v2/minis/trade_order/query/", r.URL.Path)
				}
				gotAuth = r.Header.Get("Authorization")
				if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
					t.Errorf("解析请求体失败: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":{"trade_order_id":"TOID1732533244259","trade_order_status":"` + tc.status + `"},"error":{"code":"ok","message":"","log_id":"lg"}}`))
			}))
			defer srv.Close()

			tk := newTestTikTok(t, srv.URL, nil)
			result, err := tk.VerifyPayment(context.Background(), platform.PaymentReceipt{
				Platform:      "tiktok",
				OrderID:       "biz-order-1",
				TransactionID: "TOID1732533244259",
				Raw:           map[string]string{ReceiptRawKeyAccessToken: testUserToken},
			})
			if err != nil {
				t.Fatalf("VerifyPayment 失败: %v", err)
			}
			// 关键断言（历史踩坑点）：查单鉴权必须是「付款用户的 OAuth token」。
			if want := "Bearer " + testUserToken; gotAuth != want {
				t.Errorf("Authorization = %q, 期望 %q", gotAuth, want)
			}
			if gotBody["trade_order_id"] != "TOID1732533244259" {
				t.Errorf("请求体 trade_order_id = %q", gotBody["trade_order_id"])
			}
			if result.Paid != tc.wantPaid {
				t.Errorf("Paid = %v, 期望 %v（状态 %s）", result.Paid, tc.wantPaid, tc.status)
			}
			if result.Platform != "tiktok" || result.OrderID != "biz-order-1" {
				t.Errorf("Platform/OrderID = %s/%s", result.Platform, result.OrderID)
			}
			if result.TransactionID != "TOID1732533244259" {
				t.Errorf("TransactionID = %q（应以平台应答为准）", result.TransactionID)
			}
			if result.Amount != 0 || result.Currency != "" {
				t.Errorf("Amount/Currency = %d/%q，官方查单接口不返回金额，应为零值", result.Amount, result.Currency)
			}
			if result.Sandbox || !result.PaidAt.IsZero() {
				t.Error("Sandbox/PaidAt 官方查单接口不返回，应为零值")
			}
			if result.Raw["trade_order_status"] != tc.status {
				t.Errorf("Raw[trade_order_status] = %q, 期望 %q", result.Raw["trade_order_status"], tc.status)
			}
		})
	}
}

// TestVerifyPaymentInputValidation 入参防御：串单 / 缺字段不发 HTTP 请求。
func TestVerifyPaymentInputValidation(t *testing.T) {
	tests := []struct {
		name    string
		receipt platform.PaymentReceipt
	}{
		{
			name: "Platform 串单（wechat 单据打到 tiktok 实现）",
			receipt: platform.PaymentReceipt{
				Platform: "wechat", TransactionID: "TOID1",
				Raw: map[string]string{ReceiptRawKeyAccessToken: testUserToken},
			},
		},
		{
			name: "缺 TransactionID",
			receipt: platform.PaymentReceipt{
				Platform: "tiktok",
				Raw:      map[string]string{ReceiptRawKeyAccessToken: testUserToken},
			},
		},
		{
			name:    "缺 Raw[access_token]（TikTok 查单按用户鉴权）",
			receipt: platform.PaymentReceipt{Platform: "tiktok", TransactionID: "TOID1"},
		},
		{
			name: "Raw 存在但 access_token 为空",
			receipt: platform.PaymentReceipt{
				Platform: "tiktok", TransactionID: "TOID1",
				Raw: map[string]string{ReceiptRawKeyAccessToken: ""},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			defer srv.Close()
			tk := newTestTikTok(t, srv.URL, nil)
			if _, err := tk.VerifyPayment(context.Background(), tc.receipt); err == nil {
				t.Fatal("期望入参校验错误，实际 nil")
			}
			if called {
				t.Error("非法入参不应发起 HTTP 请求")
			}
		})
	}

	t.Run("Platform 留空视为合法（合约：冗余校验位）", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"trade_order_id":"TOID1","trade_order_status":"SUCCESS"},"error":{"code":"ok"}}`))
		}))
		defer srv.Close()
		tk := newTestTikTok(t, srv.URL, nil)
		result, err := tk.VerifyPayment(context.Background(), platform.PaymentReceipt{
			TransactionID: "TOID1",
			Raw:           map[string]string{ReceiptRawKeyAccessToken: testUserToken},
		})
		if err != nil {
			t.Fatalf("VerifyPayment 失败: %v", err)
		}
		if !result.Paid {
			t.Error("期望 Paid = true")
		}
	})
}

// TestVerifyPaymentErrors 错误路径：查单业务错误码 / 协议异常 / 网络错误的分类。
func TestVerifyPaymentErrors(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		body          string
		wantCode      string
		wantRetryable bool
	}{
		{
			name:   "20011002 订单不存在（确定性失败）",
			status: http.StatusOK,
			body:   `{"data":{},"error":{"code":"20011002","message":"Order not existed","log_id":"lg1"}}`,
			// 官方处置建议 "Verify client key, trade order ID, and user ID"
			wantCode:      "20011002",
			wantRetryable: false,
		},
		{
			name:          "50001000 平台内部错误（可重试）",
			status:        http.StatusOK,
			body:          `{"data":{},"error":{"code":"50001000","message":"TikTok Internal Error","log_id":"lg2"}}`,
			wantCode:      "50001000",
			wantRetryable: true,
		},
		{
			name:          "429 限频（可重试）",
			status:        http.StatusTooManyRequests,
			body:          `{"data":{},"error":{"code":"rate_limit_exceeded","message":"too many requests"}}`,
			wantCode:      "rate_limit_exceeded",
			wantRetryable: true,
		},
		{
			name:          "200 但缺 trade_order_status（协议异常）",
			status:        http.StatusOK,
			body:          `{"data":{"trade_order_id":"TOID1"},"error":{"code":"ok"}}`,
			wantCode:      "",
			wantRetryable: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			tk := newTestTikTok(t, srv.URL, nil)
			_, err := tk.VerifyPayment(context.Background(), platform.PaymentReceipt{
				Platform:      "tiktok",
				TransactionID: "TOID1",
				Raw:           map[string]string{ReceiptRawKeyAccessToken: testUserToken},
			})
			if err == nil {
				t.Fatal("期望错误，实际 nil")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error，实际 %T: %v", err, err)
			}
			if pe.Op != "trade_order_query" {
				t.Errorf("Op = %s, 期望 trade_order_query", pe.Op)
			}
			if pe.Code != tc.wantCode {
				t.Errorf("Code = %q, 期望 %q", pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetryable)
			}
		})
	}

	t.Run("网络错误（可重试）", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // 立即关闭制造连接拒绝
		tk := newTestTikTok(t, srv.URL, nil)
		_, err := tk.VerifyPayment(context.Background(), platform.PaymentReceipt{
			TransactionID: "TOID1",
			Raw:           map[string]string{ReceiptRawKeyAccessToken: testUserToken},
		})
		if err == nil {
			t.Fatal("期望网络错误")
		}
		if !errs.IsRetryable(err) {
			t.Errorf("网络错误应可重试: %v", err)
		}
	})
}

// TestParseWebhookEvent webhook 事件 envelope 解析与支付事件 content 解码
// （payload 取官方示例，mini-games-monetization / webhooks-events，2026-06-11 拉取）。
func TestParseWebhookEvent(t *testing.T) {
	tk := MustNew(Config{ClientKey: "your_client_key", ClientSecret: "cs_test"})

	t.Run("redeem.success 官方示例", func(t *testing.T) {
		body := []byte(`{
			"client_key": "your_client_key",
			"event": "minis.trade_order.redeem.success",
			"create_time": 1615338610,
			"user_openid": "",
			"content": "{\"trade_order_id\":\"TOID667700996\",\"order_id\":\"order_id_as_in_your_system\"}"
		}`)
		ev, err := tk.ParseWebhookEvent(body)
		if err != nil {
			t.Fatalf("ParseWebhookEvent 失败: %v", err)
		}
		if ev.Event != EventTradeOrderRedeemSuccess {
			t.Errorf("Event = %q", ev.Event)
		}
		if ev.CreateTime != 1615338610 {
			t.Errorf("CreateTime = %d（官方单位 UTC epoch 秒）", ev.CreateTime)
		}
		c, err := ev.TradeOrderContent()
		if err != nil {
			t.Fatalf("TradeOrderContent 失败: %v", err)
		}
		if c.TradeOrderID != "TOID667700996" || c.OrderID != "order_id_as_in_your_system" {
			t.Errorf("content = %+v", c)
		}
		if c.IsSandbox || c.RefundAmount != 0 {
			t.Errorf("success 事件不携带 is_sandbox/refund_amount，应为零值: %+v", c)
		}
	})

	t.Run("refund_traceback 官方示例", func(t *testing.T) {
		body := []byte(`{
			"client_key": "your_client_key",
			"event": "minis.trade_order.redeem.refund_traceback",
			"create_time": 1744946518,
			"user_openid": "",
			"content": "{\"trade_order_id\":\"TOID2157c5ba03\",\"order_id\":\"order_id_as_in_your_system\",\"is_sandbox\":true,\"refund_amount\":80}"
		}`)
		ev, err := tk.ParseWebhookEvent(body)
		if err != nil {
			t.Fatalf("ParseWebhookEvent 失败: %v", err)
		}
		c, err := ev.TradeOrderContent()
		if err != nil {
			t.Fatalf("TradeOrderContent 失败: %v", err)
		}
		if !c.IsSandbox {
			t.Error("期望 IsSandbox = true")
		}
		if c.RefundAmount != 80 {
			t.Errorf("RefundAmount = %d, 期望 80", c.RefundAmount)
		}
	})

	t.Run("client_key 不符（防串单）", func(t *testing.T) {
		body := []byte(`{"client_key":"other_app","event":"minis.trade_order.redeem.success","content":"{}"}`)
		if _, err := tk.ParseWebhookEvent(body); err == nil {
			t.Fatal("期望 client_key 防御错误")
		}
	})

	t.Run("缺 event 字段", func(t *testing.T) {
		const canary = "canary-tiktok-webhook-token-do-not-log"
		body := []byte(`{"client_key":"your_client_key","access_token":"` + canary + `","content":"{}"}`)
		if _, err := tk.ParseWebhookEvent(body); err == nil {
			t.Fatal("期望缺 event 错误")
		} else if strings.Contains(err.Error(), canary) {
			t.Fatalf("缺 event 错误泄露 webhook canary: %v", err)
		} else if !strings.Contains(err.Error(), "body_bytes=") {
			t.Errorf("缺 event 错误缺少安全长度摘要: %v", err)
		}
	})

	t.Run("非法 JSON", func(t *testing.T) {
		if _, err := tk.ParseWebhookEvent([]byte(`not-json`)); err == nil {
			t.Fatal("期望 JSON 解析错误")
		}
	})

	t.Run("非交易事件调 TradeOrderContent 属误用", func(t *testing.T) {
		ev := &WebhookEvent{Event: "authorization.removed", Content: `{"reason":1}`}
		if _, err := ev.TradeOrderContent(); err == nil {
			t.Fatal("期望误用错误")
		}
	})

	t.Run("content 缺 trade_order_id", func(t *testing.T) {
		const canary = "canary-tiktok-content-token-do-not-log"
		ev := &WebhookEvent{Event: EventTradeOrderRedeemSuccess, Content: `{"order_id":"o1","access_token":"` + canary + `"}`}
		if _, err := ev.TradeOrderContent(); err == nil {
			t.Fatal("期望缺字段错误")
		} else if strings.Contains(err.Error(), canary) {
			t.Fatalf("content 错误泄露 canary: %v", err)
		} else if !strings.Contains(err.Error(), "body_bytes=") {
			t.Errorf("content 错误缺少安全长度摘要: %v", err)
		}
	})
}
