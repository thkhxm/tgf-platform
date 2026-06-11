//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：VerifyPayment 单测——httptest mock queryPayState 应答
//2026/6/11
//***************************************************

package douyin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// newPaymentServer 同一 server 同时挂 token 与 queryPayState 两个 endpoint。
func newPaymentServer(t *testing.T, payHandler http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var tokenCalls atomic.Int64
	mux := http.NewServeMux()
	mux.Handle("/mgplatform/api/apps/v2/token", tokenHandler(&tokenCalls, "tok-pay"))
	mux.Handle("/api/apps/game/payment/queryPayState", payHandler)
	return httptest.NewServer(mux), &tokenCalls
}

// TestVerifyPaymentStates status 映射：success → Paid / unsuccess → 未支付（非 error）。
func TestVerifyPaymentStates(t *testing.T) {
	tests := []struct {
		name       string
		respBody   string
		wantPaid   bool
		wantStatus string
	}{
		{"success 已支付", `{"status":"success"}`, true, "success"},
		{"unsuccess 未支付不发货", `{"status":"unsuccess"}`, false, "unsuccess"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotQuery url.Values
			srv, _ := newPaymentServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("method = %s, 期望 GET", r.Method)
				}
				gotQuery = r.URL.Query()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.respBody))
			})
			defer srv.Close()

			d := newTestDouyin(t, srv.URL, nil)
			result, err := d.VerifyPayment(context.Background(), platform.PaymentReceipt{
				Platform:      "douyin",
				OrderID:       "cp-order-1",
				TransactionID: "txn-keep",
				ProductID:     "prod-1",
			})
			if err != nil {
				t.Fatalf("VerifyPayment 失败: %v", err)
			}

			// 请求构造断言（access_token + orderno，见 payment.go queryPayStatePath 注释）。
			if got := gotQuery.Get("access_token"); got != "tok-pay" {
				t.Errorf("query access_token = %q, 期望 tok-pay", got)
			}
			if got := gotQuery.Get("orderno"); got != "cp-order-1" {
				t.Errorf("query orderno = %q, 期望 cp-order-1", got)
			}

			if result.Paid != tc.wantPaid {
				t.Errorf("Paid = %v, 期望 %v", result.Paid, tc.wantPaid)
			}
			if result.Platform != "douyin" || result.OrderID != "cp-order-1" {
				t.Errorf("Platform/OrderID = %s/%s, 期望 douyin/cp-order-1", result.Platform, result.OrderID)
			}
			if result.TransactionID != "txn-keep" {
				t.Errorf("TransactionID = %q, 期望原样回传 txn-keep", result.TransactionID)
			}
			// queryPayState 不返回金额——恒 0，金额核对走回调 amount_cent。
			if result.Amount != 0 || result.Currency != "" {
				t.Errorf("Amount/Currency = %d/%q, 期望 0/空（该接口不返回金额）", result.Amount, result.Currency)
			}
			if result.Raw["status"] != tc.wantStatus {
				t.Errorf("Raw[status] = %q, 期望 %q", result.Raw["status"], tc.wantStatus)
			}
		})
	}
}

// TestVerifyPaymentErrors 错误路径：参数校验 / 协议异常 / 防御性错误解析。
func TestVerifyPaymentErrors(t *testing.T) {
	t.Run("Platform 不符拒绝（防串单）", func(t *testing.T) {
		d := newTestDouyin(t, "http://127.0.0.1:1", nil)
		_, err := d.VerifyPayment(context.Background(), platform.PaymentReceipt{
			Platform: "wechat", OrderID: "o1",
		})
		if err == nil {
			t.Fatal("期望失败")
		}
	})

	t.Run("OrderID 为空拒绝", func(t *testing.T) {
		d := newTestDouyin(t, "http://127.0.0.1:1", nil)
		_, err := d.VerifyPayment(context.Background(), platform.PaymentReceipt{Platform: "douyin"})
		if err == nil {
			t.Fatal("期望失败")
		}
	})

	tests := []struct {
		name          string
		respBody      string
		respStatus    int
		wantCode      string
		wantRetryable bool
	}{
		{"未知 status 拒绝（宁可失败不误发货）", `{"status":"paid"}`, 200, "", false},
		{"防御解析 err_no", `{"err_no":40017,"err_tips":"bad token"}`, 200, "40017", false},
		{"防御解析 errcode", `{"errcode":401,"errmsg":"token expired"}`, 200, "401", false},
		{"应答缺 status", `{}`, 200, "", false},
		{"HTTP 500 可重试", `oops`, 500, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newPaymentServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.respStatus)
				_, _ = w.Write([]byte(tc.respBody))
			})
			defer srv.Close()

			d := newTestDouyin(t, srv.URL, nil)
			_, err := d.VerifyPayment(context.Background(), platform.PaymentReceipt{
				Platform: "douyin", OrderID: "cp-order-x",
			})
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

	t.Run("token 获取失败直接透出", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/mgplatform/api/apps/v2/token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"err_no":40017,"err_tips":"bad secret"}`))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		d := newTestDouyin(t, srv.URL, nil)
		_, err := d.VerifyPayment(context.Background(), platform.PaymentReceipt{
			Platform: "douyin", OrderID: "o1",
		})
		pe, ok := errs.AsPlatformError(err)
		if !ok || pe.Op != "get_access_token" || pe.Code != "40017" {
			t.Fatalf("期望透出 get_access_token/40017 错误, 实际: %v", err)
		}
	})
}

// TestVerifyPaymentTokenReuse 连续两次校验只取一次 token（缓存复用）。
func TestVerifyPaymentTokenReuse(t *testing.T) {
	srv, tokenCalls := newPaymentServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})
	defer srv.Close()

	d := newTestDouyin(t, srv.URL, nil)
	for i := 0; i < 2; i++ {
		if _, err := d.VerifyPayment(context.Background(), platform.PaymentReceipt{
			Platform: "douyin", OrderID: "o1",
		}); err != nil {
			t.Fatalf("第 %d 次 VerifyPayment 失败: %v", i+1, err)
		}
	}
	if got := tokenCalls.Load(); got != 1 {
		t.Fatalf("token 被取 %d 次, 期望 1 次（缓存复用）", got)
	}
}
