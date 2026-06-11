//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：VerifyPayment 单测——双签名校验 / 请求构造 / 状态映射 / 串单防御 / 配置缺失
//2026/6/11
//***************************************************

package wechat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

const (
	testSessionKey = "9hAb/NEYUlkaMBEsmFgzig=="
	testAppKey     = "appkey_prod_test"
	testSandboxKey = "appkey_sandbox_test"
)

// paymentMutate 配齐支付所需配置。
func paymentMutate(c *Config) {
	c.OfferID = "offer-123"
	c.AppKey = testAppKey
	c.SandboxAppKey = testSandboxKey
	c.BizID = BizIDGoods
	c.SessionKeyFunc = func(ctx context.Context, openID string) (string, error) {
		return testSessionKey, nil
	}
}

// newPaymentServer 起一个校验双签名后返回 respBody 的米大师 mock。
func newPaymentServer(t *testing.T, respBody string, capture func(query map[string]string, body map[string]any)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	stableTokenHandler(mux)
	mux.HandleFunc("/wxa/game/queryorderinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, 期望 POST", r.Method)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("读请求体失败: %v", err)
		}
		q := r.URL.Query()

		// 服务端按官方算法复算双签名（密钥与本测试共享）：
		// signature = hmac_sha256(session_key, post_body)
		if want := sign.HMACSHA256Hex([]byte(testSessionKey), raw); q.Get("signature") != want {
			t.Errorf("signature = %q, 期望 %q（hmac_sha256(session_key, post_body)）", q.Get("signature"), want)
		}
		// pay_sig = hmac_sha256(app_key, uri + "&" + post_body)，uri 不带 query
		if want := sign.HMACSHA256Hex([]byte(testAppKey), []byte("/wxa/game/queryorderinfo&"+string(raw))); q.Get("pay_sig") != want {
			t.Errorf("pay_sig = %q, 期望 %q（hmac_sha256(app_key, uri&body)）", q.Get("pay_sig"), want)
		}
		if q.Get("sig_method") != "hmac_sha256" {
			t.Errorf("sig_method = %q, 期望 hmac_sha256（官方固定值）", q.Get("sig_method"))
		}
		if q.Get("access_token") != "AT_TEST" {
			t.Errorf("access_token = %q, 期望 AT_TEST", q.Get("access_token"))
		}

		if capture != nil {
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			qm := map[string]string{}
			for k := range q {
				qm[k] = q.Get(k)
			}
			capture(qm, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	return httptest.NewServer(mux)
}

// TestVerifyPaymentPaid 已支付订单：双签名 / 请求体字段 / 结果映射全断言。
func TestVerifyPaymentPaid(t *testing.T) {
	// 官方返回示例字段（api_pay_v2.queryorder.html，2026-06-11 拉取）。
	resp := `{"errcode":0,"errmsg":"ok","out_trade_no":"order-1","pay_finish_time":1669364790,
		"product_id":"id_100001","deliver_state":2,"pay_state":2,
		"mch_order_no":"1217752501201407033233368018","transaction_id":"4200001234202611116666666666"}`
	var gotBody map[string]any
	srv := newPaymentServer(t, resp, func(q map[string]string, body map[string]any) { gotBody = body })
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, paymentMutate)
	fixedNow := time.Unix(1_770_000_000, 0)
	wc.now = func() time.Time { return fixedNow }

	result, err := wc.VerifyPayment(context.Background(), platform.PaymentReceipt{
		Platform: PlatformName,
		OrderID:  "order-1",
		OpenID:   "openid-1",
	})
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}

	// 请求体断言（官方七字段）
	want := map[string]any{
		"openid":       "openid-1",
		"offer_id":     "offer-123",
		"ts":           float64(fixedNow.Unix()),
		"zone_id":      "1", // DefaultZoneID
		"env":          float64(EnvProduction),
		"out_trade_no": "order-1",
		"biz_id":       float64(BizIDGoods),
	}
	for k, v := range want {
		if gotBody[k] != v {
			t.Errorf("body.%s = %v, 期望 %v", k, gotBody[k], v)
		}
	}

	// 结果映射断言
	if !result.Paid {
		t.Error("pay_state=2 应映射 Paid=true")
	}
	if result.Sandbox {
		t.Error("env=0 应映射 Sandbox=false")
	}
	if result.ProductID != "id_100001" {
		t.Errorf("ProductID = %q", result.ProductID)
	}
	if result.TransactionID != "4200001234202611116666666666" {
		t.Errorf("TransactionID = %q（应优先 transaction_id）", result.TransactionID)
	}
	if !result.PaidAt.Equal(time.Unix(1669364790, 0)) {
		t.Errorf("PaidAt = %v, 期望 Unix(1669364790)", result.PaidAt)
	}
	if result.Amount != 0 || result.Currency != "" {
		t.Errorf("Amount/Currency = %d/%q——官方接口不返回金额，必须保持 0/空，不许编造",
			result.Amount, result.Currency)
	}
	if result.OrderID != "order-1" {
		t.Errorf("OrderID = %q", result.OrderID)
	}
	if result.Raw["deliver_state"] != "2" || result.Raw["pay_state"] != "2" {
		t.Errorf("Raw 透传缺失: %v", result.Raw)
	}
}

// TestVerifyPaymentUnpaid 未支付订单：Paid=false，业务严禁发货。
func TestVerifyPaymentUnpaid(t *testing.T) {
	resp := `{"errcode":0,"errmsg":"ok","out_trade_no":"order-2","pay_state":1,"deliver_state":1}`
	srv := newPaymentServer(t, resp, nil)
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, paymentMutate)
	result, err := wc.VerifyPayment(context.Background(), platform.PaymentReceipt{
		OrderID: "order-2",
		OpenID:  "openid-1",
	})
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if result.Paid {
		t.Error("pay_state=1（未支付）应映射 Paid=false")
	}
	if !result.PaidAt.IsZero() {
		t.Errorf("未支付订单 PaidAt 应为零值，实际 %v", result.PaidAt)
	}
}

// TestVerifyPaymentSandbox 沙箱环境：用 SandboxAppKey 签 pay_sig、Sandbox=true。
func TestVerifyPaymentSandbox(t *testing.T) {
	mux := http.NewServeMux()
	stableTokenHandler(mux)
	mux.HandleFunc("/wxa/game/queryorderinfo", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		// 沙箱环境 pay_sig 必须用 SandboxAppKey（环境错配是历史踩坑高发区）。
		if want := sign.HMACSHA256Hex([]byte(testSandboxKey), []byte("/wxa/game/queryorderinfo&"+string(raw))); r.URL.Query().Get("pay_sig") != want {
			t.Errorf("沙箱 pay_sig 未用 SandboxAppKey 计算")
		}
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if body["env"] != float64(EnvSandbox) {
			t.Errorf("body.env = %v, 期望 1（沙箱）", body["env"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok","out_trade_no":"order-3","pay_state":2}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wc := newTestWeChat(t, srv.URL, func(c *Config) {
		paymentMutate(c)
		c.Env = EnvSandbox
	})
	result, err := wc.VerifyPayment(context.Background(), platform.PaymentReceipt{
		OrderID: "order-3",
		OpenID:  "openid-1",
	})
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if !result.Sandbox {
		t.Error("env=1 应映射 Sandbox=true")
	}
}

// TestVerifyPaymentSessionKeyPriority receipt.Raw[session_key] 优先于钩子。
func TestVerifyPaymentSessionKeyPriority(t *testing.T) {
	const rawKey = "raw_session_key_override"
	mux := http.NewServeMux()
	stableTokenHandler(mux)
	mux.HandleFunc("/wxa/game/queryorderinfo", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if want := sign.HMACSHA256Hex([]byte(rawKey), raw); r.URL.Query().Get("signature") != want {
			t.Errorf("signature 未用 receipt.Raw[session_key] 计算")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok","out_trade_no":"order-4","pay_state":2}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hookCalled := false
	wc := newTestWeChat(t, srv.URL, func(c *Config) {
		paymentMutate(c)
		c.SessionKeyFunc = func(ctx context.Context, openID string) (string, error) {
			hookCalled = true
			return testSessionKey, nil
		}
	})
	_, err := wc.VerifyPayment(context.Background(), platform.PaymentReceipt{
		OrderID: "order-4",
		OpenID:  "openid-1",
		Raw:     map[string]string{"session_key": rawKey},
	})
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if hookCalled {
		t.Error("Raw[session_key] 已提供时不应回调 SessionKeyFunc")
	}
}

// TestVerifyPaymentErrors 错误与防御路径。
func TestVerifyPaymentErrors(t *testing.T) {
	t.Run("应答 out_trade_no 不一致（防串单）", func(t *testing.T) {
		srv := newPaymentServer(t, `{"errcode":0,"errmsg":"ok","out_trade_no":"OTHER","pay_state":2}`, nil)
		defer srv.Close()
		wc := newTestWeChat(t, srv.URL, paymentMutate)
		_, err := wc.VerifyPayment(context.Background(), platform.PaymentReceipt{OrderID: "order-x", OpenID: "o1"})
		if err == nil || !strings.Contains(err.Error(), "串单") {
			t.Errorf("期望串单防御错误，实际: %v", err)
		}
	})

	t.Run("平台 errcode 非 0", func(t *testing.T) {
		srv := newPaymentServer(t, `{"errcode":90009,"errmsg":"order not exist"}`, nil)
		defer srv.Close()
		wc := newTestWeChat(t, srv.URL, paymentMutate)
		_, err := wc.VerifyPayment(context.Background(), platform.PaymentReceipt{OrderID: "order-x", OpenID: "o1"})
		if err == nil {
			t.Fatal("期望错误")
		}
		pe, ok := errs.AsPlatformError(err)
		if !ok || pe.Code != "90009" || pe.Op != "query_order" {
			t.Errorf("Op/Code = %v, 期望 query_order/90009", err)
		}
		if pe.Retryable {
			t.Error("未知业务错误码不应标记可重试")
		}
	})

	t.Run("receipt.Platform 串平台", func(t *testing.T) {
		wc := newTestWeChat(t, "http://127.0.0.1:0", paymentMutate)
		_, err := wc.VerifyPayment(context.Background(), platform.PaymentReceipt{
			Platform: "tiktok", OrderID: "o", OpenID: "u",
		})
		if err == nil {
			t.Error("Platform=tiktok 应被防串单校验拒绝")
		}
	})

	// 必填项缺失矩阵（全部不应发起 HTTP 请求）。
	missing := []struct {
		name    string
		mutate  func(*Config)
		receipt platform.PaymentReceipt
	}{
		{"缺 OpenID", paymentMutate, platform.PaymentReceipt{OrderID: "o"}},
		{"缺 OrderID", paymentMutate, platform.PaymentReceipt{OpenID: "u"}},
		{"缺 OfferID", func(c *Config) { paymentMutate(c); c.OfferID = "" },
			platform.PaymentReceipt{OrderID: "o", OpenID: "u"}},
		{"缺 AppKey", func(c *Config) { paymentMutate(c); c.AppKey = "" },
			platform.PaymentReceipt{OrderID: "o", OpenID: "u"}},
		{"缺 BizID", func(c *Config) { paymentMutate(c); c.BizID = 0 },
			platform.PaymentReceipt{OrderID: "o", OpenID: "u"}},
		{"缺 session_key 来源", func(c *Config) { paymentMutate(c); c.SessionKeyFunc = nil },
			platform.PaymentReceipt{OrderID: "o", OpenID: "u"}},
		{"Raw[biz_id] 非法", paymentMutate,
			platform.PaymentReceipt{OrderID: "o", OpenID: "u", Raw: map[string]string{"biz_id": "abc"}}},
	}
	for _, tc := range missing {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			defer srv.Close()
			wc := newTestWeChat(t, srv.URL, tc.mutate)
			if _, err := wc.VerifyPayment(context.Background(), tc.receipt); err == nil {
				t.Fatal("期望配置/参数校验错误")
			}
			if called {
				t.Error("校验失败不应发起 HTTP 请求")
			}
		})
	}

	t.Run("Raw[biz_id] 覆盖配置", func(t *testing.T) {
		mux := http.NewServeMux()
		stableTokenHandler(mux)
		mux.HandleFunc("/wxa/game/queryorderinfo", func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			if body["biz_id"] != float64(BizIDCoin) {
				t.Errorf("body.biz_id = %v, 期望 1（Raw 覆盖）", body["biz_id"])
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok","out_trade_no":"o5","pay_state":2}`))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()
		wc := newTestWeChat(t, srv.URL, paymentMutate) // 配置是 BizIDGoods
		_, err := wc.VerifyPayment(context.Background(), platform.PaymentReceipt{
			OrderID: "o5", OpenID: "u", Raw: map[string]string{"biz_id": "1"},
		})
		if err != nil {
			t.Fatalf("VerifyPayment 失败: %v", err)
		}
	})
}
