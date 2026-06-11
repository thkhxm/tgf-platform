//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description steam：VerifyPayment / FinalizeTxn 单测——httptest mock 平台应答（成功 / 状态映射 / 各错误形态），不打真实 Steam
//2026/6/11
//***************************************************

package steam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// queryTxnOKBody 按官方 QueryTxn/v3 示例数据（XML 例转 JSON 包封；amount/vat 数字
// 形态按官方 GetReport v5 JSON 示例）构造的成功应答。
const queryTxnOKBody = `{"response":{"result":"OK","params":{
	"orderid":"938474","transid":"374839","steamid":"76561197960287930",
	"status":"Succeeded","currency":"GBP","time":"2010-01-01T00:23:45Z",
	"country":"GB","usstate":"",
	"items":[
		{"itemid":12345,"qty":1,"amount":199,"vat":38,"itemstatus":"Succeeded"},
		{"itemid":12346,"qty":1,"amount":199,"vat":38,"itemstatus":"Succeeded"}
	]}}}`

// TestVerifyPaymentSuccess 成功路径：断言请求构造（方法 / 接口路径 / query 参数）
// 与结果映射（金额合计 = Σ(amount+vat)、PaidAt RFC3339、Raw 透传）。
func TestVerifyPaymentSuccess(t *testing.T) {
	var gotQuery url.Values
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, 期望 GET", r.Method)
		}
		gotPath = r.URL.Path
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(queryTxnOKBody))
	}))
	defer srv.Close()

	s := newTestSteam(t, srv.URL, nil)
	result, err := s.VerifyPayment(context.Background(), platform.PaymentReceipt{
		Platform:      "steam",
		OrderID:       "938474",
		TransactionID: "374839",
		OpenID:        "76561197960287930",
	})
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}

	if gotPath != "/ISteamMicroTxn/QueryTxn/v3/" {
		t.Errorf("path = %s, 期望 /ISteamMicroTxn/QueryTxn/v3/", gotPath)
	}
	wantFields := map[string]string{
		"key":     "key_test",
		"appid":   "440",
		"orderid": "938474",
		"transid": "374839",
	}
	for k, want := range wantFields {
		if got := gotQuery.Get(k); got != want {
			t.Errorf("query[%s] = %q, 期望 %q", k, got, want)
		}
	}

	if !result.Paid {
		t.Error("Paid = false, 期望 true（status=Succeeded）")
	}
	if result.Platform != "steam" || result.OrderID != "938474" || result.TransactionID != "374839" {
		t.Errorf("Platform/OrderID/TransactionID = %s/%s/%s", result.Platform, result.OrderID, result.TransactionID)
	}
	// 用户实付 = Σ(amount+vat) = (199+38)*2 = 474 cents
	if result.Amount != 474 {
		t.Errorf("Amount = %d, 期望 474（Σ(amount+vat)）", result.Amount)
	}
	if result.Currency != "GBP" {
		t.Errorf("Currency = %q, 期望 GBP", result.Currency)
	}
	if result.ProductID != "12345" {
		t.Errorf("ProductID = %q, 期望 12345（首个 itemid）", result.ProductID)
	}
	wantTime := time.Date(2010, 1, 1, 0, 23, 45, 0, time.UTC)
	if !result.PaidAt.Equal(wantTime) {
		t.Errorf("PaidAt = %v, 期望 %v", result.PaidAt, wantTime)
	}
	if result.Sandbox {
		t.Error("Sandbox = true, 期望 false（未开沙箱）")
	}
	if result.Raw["status"] != "Succeeded" || result.Raw["amount_ex_vat"] != "398" || result.Raw["vat"] != "76" {
		t.Errorf("Raw 透传异常: %v", result.Raw)
	}
	if result.Raw["items"] == "" {
		t.Error("Raw[items] 应包含明细 JSON")
	}
}

// TestVerifyPaymentSandboxPath 沙箱开关应切到 ISteamMicroTxnSandbox 接口，
// 且结果 Sandbox=true。
func TestVerifyPaymentSandboxPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(queryTxnOKBody))
	}))
	defer srv.Close()

	s := newTestSteam(t, srv.URL, func(c *Config) { c.Sandbox = true })
	result, err := s.VerifyPayment(context.Background(), platform.PaymentReceipt{OrderID: "938474"})
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if gotPath != "/ISteamMicroTxnSandbox/QueryTxn/v3/" {
		t.Errorf("path = %s, 期望 /ISteamMicroTxnSandbox/QueryTxn/v3/", gotPath)
	}
	if !result.Sandbox {
		t.Error("Sandbox = false, 期望 true")
	}
}

// TestVerifyPaymentStatusMapping 状态映射表驱动：只有 Succeeded 判 Paid=true，
// 其余全部 false（官方附录 A 全量枚举）。
func TestVerifyPaymentStatusMapping(t *testing.T) {
	tests := []struct {
		status   string
		wantPaid bool
	}{
		{StatusInit, false},
		{StatusApproved, false},
		{StatusSucceeded, true},
		{StatusFailed, false},
		{StatusRefunded, false},
		{StatusPartialRefund, false},
		{StatusChargedback, false},
		{StatusRefundedSuspectedFraud, false},
		{StatusRefundedFriendlyFraud, false},
	}
	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"result":"OK","params":{
					"orderid":"1","transid":"2","steamid":"3","status":"` + tc.status + `",
					"currency":"USD","time":"2026-06-11T00:00:00Z","items":[]}}}`))
			}))
			defer srv.Close()

			s := newTestSteam(t, srv.URL, nil)
			result, err := s.VerifyPayment(context.Background(), platform.PaymentReceipt{OrderID: "1"})
			if err != nil {
				t.Fatalf("VerifyPayment 失败: %v", err)
			}
			if result.Paid != tc.wantPaid {
				t.Errorf("Paid = %v, 期望 %v", result.Paid, tc.wantPaid)
			}
			if result.Raw["status"] != tc.status {
				t.Errorf("Raw[status] = %q, 期望 %q", result.Raw["status"], tc.status)
			}
		})
	}
}

// TestIsReversedStatus 逆转状态集合（官方实现指南列举的 claw-back 状态）。
func TestIsReversedStatus(t *testing.T) {
	reversed := []string{StatusRefunded, StatusPartialRefund, StatusChargedback,
		StatusRefundedSuspectedFraud, StatusRefundedFriendlyFraud}
	for _, st := range reversed {
		if !IsReversedStatus(st) {
			t.Errorf("IsReversedStatus(%s) = false, 期望 true", st)
		}
	}
	for _, st := range []string{StatusInit, StatusApproved, StatusSucceeded, StatusFailed, ""} {
		if IsReversedStatus(st) {
			t.Errorf("IsReversedStatus(%s) = true, 期望 false", st)
		}
	}
}

// TestVerifyPaymentErrors 错误路径表驱动。
func TestVerifyPaymentErrors(t *testing.T) {
	okReceipt := platform.PaymentReceipt{OrderID: "938474"}
	tests := []struct {
		name          string
		receipt       platform.PaymentReceipt
		handler       http.HandlerFunc // nil = 不应发出请求
		wantCode      string
		wantRetryable bool
		wantHTTP      int
	}{
		{
			name:    "platform 不匹配（防串单）",
			receipt: platform.PaymentReceipt{Platform: "tiktok", OrderID: "1"},
		},
		{
			name:    "orderid 与 transid 都为空",
			receipt: platform.PaymentReceipt{Platform: "steam"},
		},
		{
			name:    "result=Failure + error 块（官方附录 B 错误码透传）",
			receipt: okReceipt,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"result":"Failure",
					"error":{"errorcode":7,"errordesc":"User is not logged in"}}}`))
			},
			wantCode: "7",
			wantHTTP: 200,
		},
		{
			name: "steamid 与 receipt.OpenID 不一致（疑似串单）",
			receipt: platform.PaymentReceipt{
				OrderID: "938474",
				OpenID:  "76561197960280000",
			},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(queryTxnOKBody))
			},
			wantHTTP: 0,
		},
		{
			name:    "403 + HTML 错误页（key 无效，确定性失败）",
			receipt: okReceipt,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("<html>Forbidden</html>"))
			},
			wantCode:      "403",
			wantRetryable: false,
			wantHTTP:      403,
		},
		{
			name:    "503 服务暂不可用（可重试）",
			receipt: okReceipt,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantCode:      "503",
			wantRetryable: true,
			wantHTTP:      503,
		},
		{
			name:    "result=OK 但缺 status（协议异常，宁可失败不可误发货）",
			receipt: okReceipt,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"result":"OK","params":{"orderid":"938474"}}}`))
			},
			wantHTTP: 200,
		},
		{
			name:    "time 非 RFC3339（协议异常）",
			receipt: okReceipt,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"response":{"result":"OK","params":{
					"orderid":"938474","status":"Succeeded","time":"20100101","items":[]}}}`))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseURL := "http://127.0.0.1:0"
			if tc.handler != nil {
				srv := httptest.NewServer(tc.handler)
				defer srv.Close()
				baseURL = srv.URL
			}
			s := newTestSteam(t, baseURL, nil)
			_, err := s.VerifyPayment(context.Background(), tc.receipt)
			if err == nil {
				t.Fatal("期望失败，实际成功")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error, got %T: %v", err, err)
			}
			if pe.Platform != "steam" || pe.Op != opQueryTxn {
				t.Errorf("Platform/Op = %s/%s, 期望 steam/%s", pe.Platform, pe.Op, opQueryTxn)
			}
			if tc.wantCode != "" && pe.Code != tc.wantCode {
				t.Errorf("Code = %q, 期望 %q", pe.Code, tc.wantCode)
			}
			if pe.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, 期望 %v", pe.Retryable, tc.wantRetryable)
			}
			if tc.wantHTTP != 0 && pe.HTTPStatus != tc.wantHTTP {
				t.Errorf("HTTPStatus = %d, 期望 %d", pe.HTTPStatus, tc.wantHTTP)
			}
		})
	}
}

// TestVerifyPaymentTimeEmpty time 字段为空时 PaidAt 保持零值且不报错
// （status=Init 等未支付状态可能无交易时间）。
func TestVerifyPaymentTimeEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"result":"OK","params":{
			"orderid":"1","status":"Init","items":[]}}}`))
	}))
	defer srv.Close()

	s := newTestSteam(t, srv.URL, nil)
	result, err := s.VerifyPayment(context.Background(), platform.PaymentReceipt{OrderID: "1"})
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if !result.PaidAt.IsZero() {
		t.Errorf("PaidAt = %v, 期望零值", result.PaidAt)
	}
	if result.Paid {
		t.Error("Paid = true, 期望 false（status=Init）")
	}
}

// TestVerifyPaymentFlexNumberForms amount/vat/itemid 的字符串形态兼容
// （防协议历史歧义，见 json.go 注释）。
func TestVerifyPaymentFlexNumberForms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"result":"OK","params":{
			"orderid":"1","transid":"2","status":"Succeeded","currency":"USD",
			"time":"2026-06-11T00:00:00Z",
			"items":[{"itemid":"777","qty":"1","amount":"100","vat":"10","itemstatus":"Succeeded"}]}}}`))
	}))
	defer srv.Close()

	s := newTestSteam(t, srv.URL, nil)
	result, err := s.VerifyPayment(context.Background(), platform.PaymentReceipt{OrderID: "1"})
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if result.Amount != 110 {
		t.Errorf("Amount = %d, 期望 110", result.Amount)
	}
	if result.ProductID != "777" {
		t.Errorf("ProductID = %q, 期望 777", result.ProductID)
	}
}

// TestFinalizeTxn FinalizeTxn 成功与失败路径。
func TestFinalizeTxn(t *testing.T) {
	t.Run("成功：断言 POST 表单与结果映射", func(t *testing.T) {
		var gotForm url.Values
		var gotPath, gotCT string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, 期望 POST", r.Method)
			}
			gotPath = r.URL.Path
			gotCT = r.Header.Get("Content-Type")
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm: %v", err)
			}
			gotForm = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"response":{"result":"OK","params":{"orderid":"938473","transid":"374839"}}}`))
		}))
		defer srv.Close()

		s := newTestSteam(t, srv.URL, nil)
		result, err := s.FinalizeTxn(context.Background(), "938473")
		if err != nil {
			t.Fatalf("FinalizeTxn 失败: %v", err)
		}
		if gotPath != "/ISteamMicroTxn/FinalizeTxn/v2/" {
			t.Errorf("path = %s, 期望 /ISteamMicroTxn/FinalizeTxn/v2/", gotPath)
		}
		if gotCT != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %s, 期望 application/x-www-form-urlencoded", gotCT)
		}
		wantFields := map[string]string{"key": "key_test", "orderid": "938473", "appid": "440"}
		for k, want := range wantFields {
			if got := gotForm.Get(k); got != want {
				t.Errorf("form[%s] = %q, 期望 %q", k, got, want)
			}
		}
		if result.OrderID != "938473" || result.TransactionID != "374839" {
			t.Errorf("OrderID/TransactionID = %s/%s", result.OrderID, result.TransactionID)
		}
	})

	t.Run("orderID 为空", func(t *testing.T) {
		s := newTestSteam(t, "http://127.0.0.1:0", nil)
		if _, err := s.FinalizeTxn(context.Background(), ""); err == nil {
			t.Fatal("期望失败，实际成功")
		}
	})

	t.Run("Failure：错误码透传", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"response":{"result":"Failure",
				"error":{"errorcode":5,"errordesc":"User has not approved transaction"}}}`))
		}))
		defer srv.Close()

		s := newTestSteam(t, srv.URL, nil)
		_, err := s.FinalizeTxn(context.Background(), "938473")
		if err == nil {
			t.Fatal("期望失败，实际成功")
		}
		if got := errs.CodeOf(err); got != "5" {
			t.Errorf("Code = %q, 期望 5", got)
		}
	})

	t.Run("传输层失败不标记可重试（官方要求改查状态而非重发）", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		srv.Close()

		s := newTestSteam(t, srv.URL, nil)
		_, err := s.FinalizeTxn(context.Background(), "938473")
		if err == nil {
			t.Fatal("期望失败，实际成功")
		}
		if errs.IsRetryable(err) {
			t.Fatalf("FinalizeTxn 传输失败不应标记可重试: %v", err)
		}
	})

	t.Run("沙箱接口路径", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"response":{"result":"OK","params":{"orderid":"1","transid":"2"}}}`))
		}))
		defer srv.Close()

		s := newTestSteam(t, srv.URL, func(c *Config) { c.Sandbox = true })
		if _, err := s.FinalizeTxn(context.Background(), "1"); err != nil {
			t.Fatalf("FinalizeTxn 失败: %v", err)
		}
		if gotPath != "/ISteamMicroTxnSandbox/FinalizeTxn/v2/" {
			t.Errorf("path = %s, 期望 /ISteamMicroTxnSandbox/FinalizeTxn/v2/", gotPath)
		}
	})
}
