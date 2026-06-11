//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：VerifyPayment 单测——JWT-bearer 断言 / token 缓存 / ProductPurchase 映射 / 错误分类
//2026/6/11
//***************************************************

package google

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

const (
	testSAEmail       = "play-verify@proj.iam.gserviceaccount.com"
	testPackageName   = "com.example.app"
	testProductSKU    = "com.example.app.sku1"
	testPurchaseToken = "token-abc-123"
	testAccessToken   = "ya29.test-access-token"
)

// pemOfKey 把 RSA 私钥编码为 PKCS#8 PEM（service account JSON 的 private_key 形态）。
func pemOfKey(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("私钥 PKCS#8 编码失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// payServer 是支付链路 mock：/token 校验 JWT-bearer 断言后发 access token，
// androidpublisher GET 按注入的 handler 应答。
type payServer struct {
	srv       *httptest.Server
	tokenHits atomic.Int64
	// tokenHandler 为 nil 时执行默认逻辑（断言校验 + 发 testAccessToken）。
	tokenHandler   func(w http.ResponseWriter, r *http.Request)
	productHandler func(w http.ResponseWriter, r *http.Request)
}

func newPayServer(t *testing.T, priv *rsa.PrivateKey) *payServer {
	t.Helper()
	ps := &payServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ps.tokenHits.Add(1)
		if ps.tokenHandler != nil {
			ps.tokenHandler(w, r)
			return
		}
		// 默认逻辑：按官方协议校验 JWT-bearer 断言
		// （https://developers.google.com/identity/protocols/oauth2/service-account ，
		// 2026-06-11 拉取）。
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if got := r.PostForm.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q, 期望 jwt-bearer urn", got)
		}
		assertion := r.PostForm.Get("assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Errorf("assertion 不是三段式 JWT: %q", assertion)
			http.Error(w, "bad assertion", http.StatusBadRequest)
			return
		}
		// 验签：断言必须由 service account 私钥 RS256 签名。
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || sign.RSASHA256Verify(&priv.PublicKey, []byte(parts[0]+"."+parts[1]), sig) != nil {
			t.Errorf("assertion 签名校验失败")
		}
		var claims struct {
			Iss   string `json:"iss"`
			Scope string `json:"scope"`
			Aud   string `json:"aud"`
			Exp   int64  `json:"exp"`
			Iat   int64  `json:"iat"`
		}
		cj, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if err := json.Unmarshal(cj, &claims); err != nil {
			t.Errorf("assertion claims 解析失败: %v", err)
		}
		if claims.Iss != testSAEmail {
			t.Errorf("assertion iss = %q, 期望 %q", claims.Iss, testSAEmail)
		}
		if claims.Scope != "https://www.googleapis.com/auth/androidpublisher" {
			t.Errorf("assertion scope = %q, 期望 androidpublisher scope", claims.Scope)
		}
		if !strings.HasSuffix(claims.Aud, "/token") {
			t.Errorf("assertion aud = %q, 期望 token 端点", claims.Aud)
		}
		if claims.Exp <= claims.Iat || claims.Exp > claims.Iat+3600 {
			t.Errorf("assertion exp/iat 非法（exp 至多 iat+1h）: exp=%d iat=%d", claims.Exp, claims.Iat)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": testAccessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        claims.Scope,
		})
	})
	wantPath := "/androidpublisher/v3/applications/" + testPackageName +
		"/purchases/products/" + testProductSKU + "/tokens/" + testPurchaseToken
	mux.HandleFunc("/androidpublisher/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("purchases.products.get 应为 GET，实际 %s", r.Method)
		}
		if r.URL.Path != wantPath {
			t.Errorf("请求路径 = %q, 期望 %q", r.URL.Path, wantPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testAccessToken {
			t.Errorf("Authorization = %q, 期望 Bearer %s", got, testAccessToken)
		}
		if ps.productHandler == nil {
			t.Fatal("用例未注入 productHandler")
		}
		ps.productHandler(w, r)
	})
	ps.srv = httptest.NewServer(mux)
	t.Cleanup(ps.srv.Close)
	return ps
}

// newPayGoogle 构造接到 mock 服务的支付态实例。
func newPayGoogle(t *testing.T, priv *rsa.PrivateKey, ps *payServer) *Google {
	t.Helper()
	g, err := New(Config{
		PackageName:                 testPackageName,
		ServiceAccountEmail:         testSAEmail,
		ServiceAccountPrivateKeyPEM: pemOfKey(t, priv),
		ServiceAccountPrivateKeyID:  "sa-key-id-1",
		OAuthTokenURL:               ps.srv.URL + "/token",
		AndroidPublisherBaseURL:     ps.srv.URL,
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return g
}

// baseReceipt 基准合法凭据。
func baseReceipt(mutate func(*platform.PaymentReceipt)) platform.PaymentReceipt {
	r := platform.PaymentReceipt{
		Platform:      PlatformName,
		OrderID:       "biz-order-1",
		TransactionID: testPurchaseToken,
		ProductID:     testProductSKU,
	}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

// jsonHandler 返回固定 JSON 应答的 handler。
func jsonHandler(status int, body map[string]any) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// purchasedBody 官方示例形态的 Purchased 应答
// （https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products/get ，
// 2026-06-11 拉取的 sample response，token/SKU 替换为测试常量）。
func purchasedBody(mutate func(map[string]any)) map[string]any {
	body := map[string]any{
		"kind":                 "androidpublisher#productPurchase",
		"purchaseTimeMillis":   "1678886400000",
		"purchaseState":        0,
		"consumptionState":     0,
		"developerPayload":     "sample developer payload",
		"orderId":              "GPA.1234-5678-9012-34567",
		"acknowledgementState": 0,
		"productId":            testProductSKU,
		"purchaseToken":        testPurchaseToken,
		"quantity":             1,
		"refundableQuantity":   1,
		"regionCode":           "US",
	}
	if mutate != nil {
		mutate(body)
	}
	return body
}

func TestVerifyPayment(t *testing.T) {
	priv := testRSAKey(t)

	cases := []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request)
		receipt platform.PaymentReceipt
		check   func(t *testing.T, result *platform.PaymentResult, err error)
	}{
		{
			name:    "成功_Purchased生产购买",
			handler: jsonHandler(200, purchasedBody(nil)),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if !result.Paid {
					t.Error("purchaseState=0 应判定 Paid=true")
				}
				if result.Sandbox {
					t.Error("无 purchaseType 字段（标准购买流）应判定 Sandbox=false")
				}
				if want := time.UnixMilli(1678886400000).UTC(); !result.PaidAt.Equal(want) {
					t.Errorf("PaidAt = %v, 期望 %v", result.PaidAt, want)
				}
				if result.TransactionID != testPurchaseToken {
					t.Errorf("TransactionID = %q, 期望 %q", result.TransactionID, testPurchaseToken)
				}
				if result.ProductID != testProductSKU {
					t.Errorf("ProductID = %q, 期望 %q", result.ProductID, testProductSKU)
				}
				if result.OrderID != "biz-order-1" {
					t.Errorf("OrderID = %q, 期望回传业务订单号", result.OrderID)
				}
				if result.Amount != 0 || result.Currency != "" {
					t.Errorf("该接口不返回金额，Amount/Currency 应为 0/空，实际 %d/%q",
						result.Amount, result.Currency)
				}
				if result.Raw["orderId"] != "GPA.1234-5678-9012-34567" {
					t.Errorf("Raw[orderId] = %q, 期望透传平台订单号", result.Raw["orderId"])
				}
				if result.Raw["acknowledgementState"] != "0" {
					t.Errorf("Raw[acknowledgementState] = %q, 期望 \"0\"", result.Raw["acknowledgementState"])
				}
			},
		},
		{
			name: "成功_Test购买判沙箱",
			handler: jsonHandler(200, purchasedBody(func(b map[string]any) {
				b["purchaseType"] = 0
			})),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if !result.Paid || !result.Sandbox {
					t.Errorf("purchaseType=0（Test）应 Paid=true 且 Sandbox=true，实际 %v/%v",
						result.Paid, result.Sandbox)
				}
			},
		},
		{
			name: "成功_Canceled不发货",
			handler: jsonHandler(200, purchasedBody(func(b map[string]any) {
				b["purchaseState"] = 1
			})),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if result.Paid {
					t.Error("purchaseState=1（Canceled）应判定 Paid=false")
				}
			},
		},
		{
			name: "成功_Pending不发货",
			handler: jsonHandler(200, purchasedBody(func(b map[string]any) {
				b["purchaseState"] = 2
			})),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if result.Paid {
					t.Error("purchaseState=2（Pending）应判定 Paid=false")
				}
			},
		},
		{
			name: "失败_缺purchaseState拒绝判定",
			handler: jsonHandler(200, purchasedBody(func(b map[string]any) {
				delete(b, "purchaseState")
			})),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatalf("缺 purchaseState 应失败（0 值陷阱），实际成功: %+v", result)
				}
			},
		},
		{
			name: "失败_productId货不对板",
			handler: jsonHandler(200, purchasedBody(func(b map[string]any) {
				b["productId"] = "com.example.app.other"
			})),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("应答 productId 与请求不符应失败")
				}
			},
		},
		{
			name: "失败_purchaseToken不符",
			handler: jsonHandler(200, purchasedBody(func(b map[string]any) {
				b["purchaseToken"] = "another-token"
			})),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("应答 purchaseToken 与请求不符应失败")
				}
			},
		},
		{
			name: "失败_401标准错误体",
			handler: jsonHandler(401, map[string]any{
				"error": map[string]any{
					"code":    401,
					"message": "The current user has insufficient permissions",
					"status":  "UNAUTHENTICATED",
				},
			}),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("401 应失败")
				}
				if code := errs.CodeOf(err); code != "UNAUTHENTICATED" {
					t.Errorf("CodeOf = %q, 期望透传 status 枚举 UNAUTHENTICATED", code)
				}
				if errs.IsRetryable(err) {
					t.Error("401 是确定性失败，不应标记可重试")
				}
			},
		},
		{
			name: "失败_429限频可重试",
			handler: jsonHandler(429, map[string]any{
				"error": map[string]any{
					"code":    429,
					"message": "Quota exceeded",
					"status":  "RESOURCE_EXHAUSTED",
				},
			}),
			receipt: baseReceipt(nil),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("429 应失败")
				}
				if !errs.IsRetryable(err) {
					t.Error("429 应标记可重试")
				}
			},
		},
		{
			name:    "失败_串单平台不符",
			receipt: baseReceipt(func(r *platform.PaymentReceipt) { r.Platform = "apple" }),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("receipt.Platform=apple 应被防串单拦截")
				}
			},
		},
		{
			name:    "失败_缺TransactionID",
			receipt: baseReceipt(func(r *platform.PaymentReceipt) { r.TransactionID = "" }),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("缺 purchaseToken 应失败")
				}
			},
		},
		{
			name:    "失败_缺ProductID",
			receipt: baseReceipt(func(r *platform.PaymentReceipt) { r.ProductID = "" }),
			check: func(t *testing.T, result *platform.PaymentResult, err error) {
				if err == nil {
					t.Fatal("缺 ProductID 应失败")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPayServer(t, priv)
			ps.productHandler = tc.handler
			g := newPayGoogle(t, priv, ps)
			result, err := g.VerifyPayment(context.Background(), tc.receipt)
			tc.check(t, result, err)
		})
	}
}

// TestVerifyPaymentTokenCache 校验 access token 缓存：两次校验只换发一次 token。
func TestVerifyPaymentTokenCache(t *testing.T) {
	priv := testRSAKey(t)
	ps := newPayServer(t, priv)
	ps.productHandler = jsonHandler(200, purchasedBody(nil))
	g := newPayGoogle(t, priv, ps)

	for i := 0; i < 2; i++ {
		if _, err := g.VerifyPayment(context.Background(), baseReceipt(nil)); err != nil {
			t.Fatalf("第 %d 次 VerifyPayment 失败: %v", i+1, err)
		}
	}
	if n := ps.tokenHits.Load(); n != 1 {
		t.Errorf("expires_in 窗口内应只换发 1 次 token，实际 %d 次", n)
	}
}

// TestVerifyPaymentTokenEndpointError 校验 token 端点 OAuth 错误透传。
func TestVerifyPaymentTokenEndpointError(t *testing.T) {
	priv := testRSAKey(t)
	ps := newPayServer(t, priv)
	ps.tokenHandler = jsonHandler(400, map[string]any{
		"error":             "invalid_grant",
		"error_description": "Invalid JWT Signature.",
	})
	g := newPayGoogle(t, priv, ps)

	_, err := g.VerifyPayment(context.Background(), baseReceipt(nil))
	if err == nil {
		t.Fatal("token 端点报错时 VerifyPayment 应失败")
	}
	if code := errs.CodeOf(err); code != "invalid_grant" {
		t.Errorf("CodeOf = %q, 期望透传 OAuth 错误码 invalid_grant", code)
	}
}

// TestVerifyPaymentNotConfigured 未配置支付能力时报明确错误。
func TestVerifyPaymentNotConfigured(t *testing.T) {
	g, err := New(Config{ClientIDs: []string{testClientID}})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if _, err := g.VerifyPayment(context.Background(), baseReceipt(nil)); err == nil {
		t.Fatal("未配置支付能力时 VerifyPayment 应失败")
	}
}
