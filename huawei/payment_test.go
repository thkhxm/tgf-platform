//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：VerifyPayment 单测——Order/Subscription 两路径 / 应答验签 / 应用级 AT 缓存与 401 刷新 / 错误分类
//2026/6/11
//***************************************************

package huawei

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

const (
	testProductID      = "com.example.hmsgame.diamond60"
	testPurchaseToken  = "00000189-purchase-token-001"
	testAppAT          = "DAEDAppAccessToken001"
	testSubscriptionID = "1759054187541.D14FB8B9.3845"
	testBizOrderID     = "biz-order-20260611-001"
	testPlatformOrder  = "ORDER20260611000001"
)

// iapServer 是 IAP 支付链路 mock：/oauth2/v3/token 发应用级 AT，
// Order / Subscription 验证接口做公共协议断言后按注入 handler 应答。
type iapServer struct {
	srv          *httptest.Server
	tokenHits    atomic.Int64
	orderHits    atomic.Int64
	subHits      atomic.Int64
	tokenHandler http.HandlerFunc // nil → 默认逻辑（断言 client_credentials 协议 + 发 testAppAT）
	orderHandler http.HandlerFunc
	subHandler   http.HandlerFunc
}

func newIAPServer(t *testing.T) *iapServer {
	t.Helper()
	s := &iapServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/v3/token", func(w http.ResponseWriter, r *http.Request) {
		s.tokenHits.Add(1)
		if s.tokenHandler != nil {
			s.tokenHandler(w, r)
			return
		}
		// 默认逻辑：按官方客户端模式（client_credentials）协议断言后发放测试 AT
		//（协议见 payment.go appAccessToken 注释的文档引用）。
		if err := r.ParseForm(); err != nil {
			t.Errorf("解析 token 表单失败: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q, 期望 client_credentials", got)
		}
		if got := r.PostForm.Get("client_id"); got != testClientID {
			t.Errorf("client_id = %q, 期望 %q", got, testClientID)
		}
		if got := r.PostForm.Get("client_secret"); got != testClientSecret {
			t.Errorf("client_secret = %q, 期望 %q", got, testClientSecret)
		}
		jsonHandler(200, map[string]any{
			"access_token": testAppAT,
			"expires_in":   3600,
			"token_type":   "Bearer",
		})(w, r)
	})
	// assertIAP 两个验证接口共用的协议断言：POST + APPAT 鉴权头 + JSON 体。
	assertIAP := func(r *http.Request) map[string]string {
		if r.Method != http.MethodPost {
			t.Errorf("验证购买 Token 应为 POST，实际 %s", r.Method)
		}
		// 鉴权头格式独立钉死（不用 buildIAPAuthorization 自证）：
		// Basic Base64("APPAT:"+应用级AT)。
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("APPAT:"+testAppAT))
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Errorf("Authorization = %q, 期望 %q", got, wantAuth)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q, 期望 application/json", ct)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("读取请求体失败: %v", err)
		}
		var body map[string]string
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("请求体不是 JSON: %v", err)
		}
		return body
	}
	mux.HandleFunc(orderVerifyPath, func(w http.ResponseWriter, r *http.Request) {
		s.orderHits.Add(1)
		body := assertIAP(r)
		if body["purchaseToken"] != testPurchaseToken {
			t.Errorf("purchaseToken = %q, 期望 %q", body["purchaseToken"], testPurchaseToken)
		}
		if body["productId"] != testProductID {
			t.Errorf("productId = %q, 期望 %q", body["productId"], testProductID)
		}
		if s.orderHandler == nil {
			t.Error("用例未注入 orderHandler，却收到 Order 验证请求")
			http.Error(w, "no handler", http.StatusInternalServerError)
			return
		}
		s.orderHandler(w, r)
	})
	mux.HandleFunc(subscriptionVerifyPath, func(w http.ResponseWriter, r *http.Request) {
		s.subHits.Add(1)
		body := assertIAP(r)
		if body["subscriptionId"] != testSubscriptionID {
			t.Errorf("subscriptionId = %q, 期望 %q", body["subscriptionId"], testSubscriptionID)
		}
		if body["purchaseToken"] != testPurchaseToken {
			t.Errorf("purchaseToken = %q, 期望 %q", body["purchaseToken"], testPurchaseToken)
		}
		if s.subHandler == nil {
			t.Error("用例未注入 subHandler，却收到 Subscription 验证请求")
			http.Error(w, "no handler", http.StatusInternalServerError)
			return
		}
		s.subHandler(w, r)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// newPayHuawei 构造接到 mock IAP 服务的支付态实例。
func newPayHuawei(t *testing.T, s *iapServer, mutate func(*Config)) *Huawei {
	t.Helper()
	cfg := Config{
		ClientID:            testClientID,
		ClientSecret:        testClientSecret,
		IAPPublicKey:        testIAPPublicKeyB64(t),
		OAuthBaseURL:        s.srv.URL,
		OrderSiteURL:        s.srv.URL,
		SubscriptionSiteURL: s.srv.URL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return h
}

// basePayReceipt 基准合法支付凭据（Order 路径）。
func basePayReceipt(mutate func(*platform.PaymentReceipt)) platform.PaymentReceipt {
	r := platform.PaymentReceipt{
		Platform:      PlatformName,
		OrderID:       testBizOrderID,
		TransactionID: testPurchaseToken,
		ProductID:     testProductID,
	}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

// orderPurchaseData 构造 InAppPurchaseData（字段形态见 payment.go inAppPurchaseData
// 注释的官方文档引用；price 是实际价格 ×100）。
func orderPurchaseData(mutate func(map[string]any)) map[string]any {
	data := map[string]any{
		"applicationId":    104358151,
		"autoRenewing":     false,
		"orderId":          testPlatformOrder,
		"kind":             0,
		"packageName":      "com.example.hmsgame",
		"productId":        testProductID,
		"productName":      "60钻石",
		"purchaseTime":     1718080000000,
		"purchaseState":    0,
		"developerPayload": "payload-001",
		"purchaseToken":    testPurchaseToken,
		"consumptionState": 0,
		"currency":         "CNY",
		"price":            600,
		"country":          "CN",
		"payOrderId":       "WX20260611220001",
		"payType":          "17",
	}
	if mutate != nil {
		mutate(data)
	}
	return data
}

// iapOKBody 构造验签通过的成功应答。dataField 区分 Order（purchaseTokenData）与
// Subscription（inappPurchaseData）的字段名差异；algorithm 空 = 应答省略
// signatureAlgorithm（默认 SHA256WithRSA）。
func iapOKBody(t *testing.T, dataField string, data map[string]any, algorithm string) map[string]any {
	t.Helper()
	dj, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("序列化购买数据失败: %v", err)
	}
	body := map[string]any{
		"responseCode":  "0",
		dataField:       string(dj),
		"dataSignature": signIAPData(t, string(dj), algorithm),
	}
	if algorithm != "" {
		body["signatureAlgorithm"] = algorithm
	}
	return body
}

func TestVerifyPayment(t *testing.T) {
	cases := []struct {
		name      string
		handler   http.HandlerFunc // orderHandler；nil 表示请求不应到达服务端
		mutateCfg func(*Config)
		receipt   platform.PaymentReceipt
		check     func(t *testing.T, result *platform.PaymentResult, err error)
	}{
		{
			name: "成功_已购买生产单",
			handler: func(w http.ResponseWriter, r *http.Request) {
				jsonHandler(200, iapOKBody(t, "purchaseTokenData", orderPurchaseData(nil), ""))(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if !result.Paid {
					t.Error("purchaseState=0 应判定 Paid=true")
				}
				if result.Sandbox {
					t.Error("无 purchaseType 字段（正式购买）应判定 Sandbox=false")
				}
				if result.Platform != PlatformName {
					t.Errorf("Platform = %q, 期望 %q", result.Platform, PlatformName)
				}
				if result.OrderID != testBizOrderID {
					t.Errorf("OrderID = %q, 期望回传业务订单号 %q", result.OrderID, testBizOrderID)
				}
				if result.TransactionID != testPlatformOrder {
					t.Errorf("TransactionID = %q, 期望平台 orderId %q", result.TransactionID, testPlatformOrder)
				}
				if result.ProductID != testProductID {
					t.Errorf("ProductID = %q, 期望 %q", result.ProductID, testProductID)
				}
				if result.Amount != 600 || result.Currency != "CNY" {
					t.Errorf("Amount/Currency = %d/%q, 期望 600/CNY", result.Amount, result.Currency)
				}
				if want := time.UnixMilli(1718080000000).UTC(); !result.PaidAt.Equal(want) {
					t.Errorf("PaidAt = %v, 期望 %v", result.PaidAt, want)
				}
				for k, want := range map[string]string{
					"purchaseState":    "0",
					"kind":             "0",
					"purchaseToken":    testPurchaseToken,
					"payOrderId":       "WX20260611220001",
					"payType":          "17",
					"country":          "CN",
					"productName":      "60钻石",
					"packageName":      "com.example.hmsgame",
					"applicationId":    "104358151",
					"developerPayload": "payload-001",
					"consumptionState": "0",
				} {
					if got := result.Raw[k]; got != want {
						t.Errorf("Raw[%q] = %q, 期望 %q", k, got, want)
					}
				}
				if !strings.Contains(result.Raw["inAppPurchaseData"], testPlatformOrder) {
					t.Error("Raw[inAppPurchaseData] 应透传购买数据原文")
				}
			},
		},
		{
			name: "成功_purchaseType为0判沙盒",
			handler: func(w http.ResponseWriter, r *http.Request) {
				jsonHandler(200, iapOKBody(t, "purchaseTokenData", orderPurchaseData(func(d map[string]any) {
					d["purchaseType"] = 0
				}), ""))(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if !result.Paid || !result.Sandbox {
					t.Errorf("purchaseType=0（沙盒）应 Paid=true 且 Sandbox=true，实际 %v/%v",
						result.Paid, result.Sandbox)
				}
			},
		},
		{
			name: "成功_price字符串形态兼容",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// 官方应答示例里 price 是字符串 "100"（文档自相矛盾，两种形态都见于官方正文）。
				jsonHandler(200, iapOKBody(t, "purchaseTokenData", orderPurchaseData(func(d map[string]any) {
					d["price"] = "600"
					d["purchaseTime"] = "1718080000000"
				}), ""))(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if result.Amount != 600 {
					t.Errorf("字符串形态 price 应解析为 600，实际 %d", result.Amount)
				}
				if want := time.UnixMilli(1718080000000).UTC(); !result.PaidAt.Equal(want) {
					t.Errorf("字符串形态 purchaseTime 应解析，PaidAt = %v, 期望 %v", result.PaidAt, want)
				}
			},
		},
		{
			name: "成功_已退款不算支付",
			handler: func(w http.ResponseWriter, r *http.Request) {
				jsonHandler(200, iapOKBody(t, "purchaseTokenData", orderPurchaseData(func(d map[string]any) {
					d["purchaseState"] = 2
				}), ""))(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if result.Paid {
					t.Error("purchaseState=2（已退款）应判定 Paid=false")
				}
			},
		},
		{
			name: "成功_PSS算法验签",
			handler: func(w http.ResponseWriter, r *http.Request) {
				jsonHandler(200, iapOKBody(t, "purchaseTokenData", orderPurchaseData(nil),
					"SHA256WithRSA/PSS"))(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("PSS 算法应验签通过，实际失败: %v", err)
				}
			},
		},
		{
			name: "失败_购买数据篡改保留原签名",
			handler: func(w http.ResponseWriter, r *http.Request) {
				body := iapOKBody(t, "purchaseTokenData", orderPurchaseData(nil), "")
				tampered, _ := json.Marshal(orderPurchaseData(func(d map[string]any) {
					d["price"] = 1 // 改单价、保留原签名
				}))
				body["purchaseTokenData"] = string(tampered)
				jsonHandler(200, body)(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil || !strings.Contains(err.Error(), "验签失败") {
					t.Errorf("篡改后的购买数据应验签失败，实际: %v", err)
				}
			},
		},
		{
			name: "失败_缺dataSignature",
			handler: func(w http.ResponseWriter, r *http.Request) {
				body := iapOKBody(t, "purchaseTokenData", orderPurchaseData(nil), "")
				delete(body, "dataSignature")
				jsonHandler(200, body)(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil || !strings.Contains(err.Error(), "dataSignature") {
					t.Errorf("缺签名字段应失败，实际: %v", err)
				}
			},
		},
		{
			name: "失败_未知签名算法",
			handler: func(w http.ResponseWriter, r *http.Request) {
				body := iapOKBody(t, "purchaseTokenData", orderPurchaseData(nil), "")
				body["signatureAlgorithm"] = "SHA1WithRSA"
				jsonHandler(200, body)(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil || !strings.Contains(err.Error(), "未知签名算法") {
					t.Errorf("官方未定义的算法应拒绝，实际: %v", err)
				}
			},
		},
		{
			name: "失败_业务错误码8未拥有商品",
			handler: jsonHandler(200, map[string]any{
				"responseCode":    "8",
				"responseMessage": "the user does not own the product",
			}),
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("responseCode=8 应失败")
				}
				if code := errs.CodeOf(err); code != "8" {
					t.Errorf("CodeOf = %q, 期望透传业务错误码 8", code)
				}
				if errs.IsRetryable(err) {
					t.Error("业务确定性失败不应可重试")
				}
			},
		},
		{
			name: "失败_缺购买数据字段",
			handler: jsonHandler(200, map[string]any{
				"responseCode": "0",
			}),
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil || !strings.Contains(err.Error(), "缺少购买数据") {
					t.Errorf("缺购买数据字段应失败，实际: %v", err)
				}
			},
		},
		{
			name: "失败_productId货不对板",
			handler: func(w http.ResponseWriter, r *http.Request) {
				jsonHandler(200, iapOKBody(t, "purchaseTokenData", orderPurchaseData(func(d map[string]any) {
					d["productId"] = "com.example.hmsgame.other"
				}), ""))(w, r)
			},
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil || !strings.Contains(err.Error(), "货不对板") {
					t.Errorf("应答 productId 与请求不符应失败，实际: %v", err)
				}
			},
		},
		{
			name:    "失败_HTTP500可重试",
			handler: jsonHandler(500, map[string]any{}),
			receipt: basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("HTTP 500 应失败")
				}
				if !errs.IsRetryable(err) {
					t.Error("5xx 应标记可重试")
				}
			},
		},
		{
			name:    "失败_串单平台不符",
			receipt: basePayReceipt(func(r *platform.PaymentReceipt) { r.Platform = "apple" }),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("receipt.Platform=apple 应被防串单拦截")
				}
			},
		},
		{
			name:    "失败_缺TransactionID",
			receipt: basePayReceipt(func(r *platform.PaymentReceipt) { r.TransactionID = "" }),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("缺 purchaseToken 应失败")
				}
			},
		},
		{
			name:    "失败_缺ProductID",
			receipt: basePayReceipt(func(r *platform.PaymentReceipt) { r.ProductID = "" }),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("缺 ProductID 应失败")
				}
			},
		},
		{
			name:      "失败_未配置IAP公钥",
			mutateCfg: func(c *Config) { c.IAPPublicKey = "" },
			receipt:   basePayReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil || !strings.Contains(err.Error(), "IAPPublicKey") {
					t.Errorf("未配置 IAP 公钥应失败（官方验签硬要求），实际: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newIAPServer(t)
			s.orderHandler = tc.handler
			h := newPayHuawei(t, s, tc.mutateCfg)
			result, err := h.VerifyPayment(context.Background(), tc.receipt)
			tc.check(t, result, err)
			if tc.handler == nil && s.orderHits.Load() != 0 {
				t.Errorf("前置校验失败的用例不应打到服务端，实际命中 %d 次", s.orderHits.Load())
			}
		})
	}
}

// TestVerifyPaymentSubscription 校验订阅路径：receipt.Raw["subscriptionId"] 非空时
// 走 Subscription 服务接口（字段名 inappPurchaseData），并透传订阅专属字段。
func TestVerifyPaymentSubscription(t *testing.T) {
	s := newIAPServer(t)
	s.subHandler = func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(200, iapOKBody(t, "inappPurchaseData", orderPurchaseData(func(d map[string]any) {
			d["kind"] = 2
			d["subscriptionId"] = testSubscriptionID
			d["subIsvalid"] = true
			d["autoRenewing"] = true
			d["expirationDate"] = 1726080000000
		}), ""))(w, r)
	}
	h := newPayHuawei(t, s, nil)

	receipt := basePayReceipt(func(r *platform.PaymentReceipt) {
		r.Raw = map[string]string{"subscriptionId": testSubscriptionID}
	})
	result, err := h.VerifyPayment(context.Background(), receipt)
	if err != nil {
		t.Fatalf("订阅校验失败: %v", err)
	}
	if s.subHits.Load() != 1 || s.orderHits.Load() != 0 {
		t.Errorf("应走 Subscription 接口（sub=1 order=0），实际 sub=%d order=%d",
			s.subHits.Load(), s.orderHits.Load())
	}
	if !result.Paid {
		t.Error("purchaseState=0 应判定 Paid=true")
	}
	for k, want := range map[string]string{
		"subscriptionId": testSubscriptionID,
		"subIsvalid":     "true",
		"autoRenewing":   "true",
		"expirationDate": "1726080000000",
		"kind":           "2",
	} {
		if got := result.Raw[k]; got != want {
			t.Errorf("Raw[%q] = %q, 期望 %q", k, got, want)
		}
	}
}

// TestVerifyPaymentAppATCache 校验应用级 AT 缓存：有效期内多次支付校验只申请一次
// （官方最佳实践：频繁申请会触发服务拒绝）。
func TestVerifyPaymentAppATCache(t *testing.T) {
	s := newIAPServer(t)
	s.orderHandler = func(w http.ResponseWriter, r *http.Request) {
		jsonHandler(200, iapOKBody(t, "purchaseTokenData", orderPurchaseData(nil), ""))(w, r)
	}
	h := newPayHuawei(t, s, nil)

	for i := 0; i < 3; i++ {
		if _, err := h.VerifyPayment(context.Background(), basePayReceipt(nil)); err != nil {
			t.Fatalf("第 %d 次 VerifyPayment 失败: %v", i+1, err)
		}
	}
	if n := s.tokenHits.Load(); n != 1 {
		t.Errorf("AT 有效期内应只申请 1 次，实际 %d 次", n)
	}
}

// TestVerifyPaymentAppAT401Refresh 校验官方最佳实践：IAP 接口返回 401 时强制刷新
// AT 重试一次。
func TestVerifyPaymentAppAT401Refresh(t *testing.T) {
	s := newIAPServer(t)
	var orderCalls atomic.Int64
	s.orderHandler = func(w http.ResponseWriter, r *http.Request) {
		if orderCalls.Add(1) == 1 {
			// 首次返回 401（模拟 AT 失效），刷新后第二次放行。
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		jsonHandler(200, iapOKBody(t, "purchaseTokenData", orderPurchaseData(nil), ""))(w, r)
	}
	h := newPayHuawei(t, s, nil)

	result, err := h.VerifyPayment(context.Background(), basePayReceipt(nil))
	if err != nil {
		t.Fatalf("401 后刷新重试应成功，实际失败: %v", err)
	}
	if !result.Paid {
		t.Error("重试成功后应正常映射结果")
	}
	if n := s.tokenHits.Load(); n != 2 {
		t.Errorf("401 应触发一次强制刷新，期望申请 AT 2 次，实际 %d 次", n)
	}
	if n := s.orderHits.Load(); n != 2 {
		t.Errorf("Order 接口应被调 2 次（401 + 重试），实际 %d 次", n)
	}
}

// TestVerifyPaymentAppATError 校验应用级 AT 申请失败的错误透传（op 重标为
// obtain_app_at、主.子错误码保留）。
func TestVerifyPaymentAppATError(t *testing.T) {
	s := newIAPServer(t)
	s.tokenHandler = jsonHandler(400, map[string]any{
		"error":             1101,
		"sub_error":         12304,
		"error_description": "invalid client_secret",
	})
	h := newPayHuawei(t, s, nil)

	_, err := h.VerifyPayment(context.Background(), basePayReceipt(nil))
	if err == nil {
		t.Fatal("AT 申请失败时 VerifyPayment 应失败")
	}
	if code := errs.CodeOf(err); code != "1101.12304" {
		t.Errorf("CodeOf = %q, 期望透传 1101.12304", code)
	}
	pe, ok := errs.AsPlatformError(err)
	if !ok || pe.Op != opAppAT {
		t.Errorf("错误 Op 应为 %q，实际: %+v", opAppAT, pe)
	}
	if n := s.orderHits.Load(); n != 0 {
		t.Errorf("AT 申请失败时不应调 Order 接口，实际命中 %d 次", n)
	}
}

// TestFlexInt64 校验数字/字符串双形态 int64 解析（官方文档两种形态都出现过）。
func TestFlexInt64(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    int64
		wantErr bool
	}{
		{name: "数字形态", raw: `600`, want: 600},
		{name: "字符串形态", raw: `"600"`, want: 600},
		{name: "空字符串归零", raw: `""`, want: 0},
		{name: "null归零", raw: `null`, want: 0},
		{name: "非数字报错", raw: `"abc"`, wantErr: true},
		{name: "小数报错", raw: `1.5`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var f flexInt64
			err := json.Unmarshal([]byte(tc.raw), &f)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("应解析失败，实际得到 %d", int64(f))
				}
				return
			}
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if int64(f) != tc.want {
				t.Errorf("解析 %s = %d, 期望 %d", tc.raw, int64(f), tc.want)
			}
		})
	}
}
