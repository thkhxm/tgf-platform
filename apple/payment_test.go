//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：PaymentProvider 单测——App Store Server API mock + JWS 链验签各路径
//2026/6/11
//***************************************************

package apple

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

const (
	testBundleID  = "com.test.app"
	testProductID = "com.test.gold100"
	testIssuerID  = "57246542-96fe-1a63e053-0824d011072a"
	testKeyID     = "2X9R4HXF34"
)

// basePayload 构造一笔合法的已支付交易载荷（按需覆盖）。
func basePayload(override map[string]any) map[string]any {
	now := time.Now()
	p := map[string]any{
		"transactionId":         "1000000123456789",
		"originalTransactionId": "1000000123456789",
		"bundleId":              testBundleID,
		"productId":             testProductID,
		"purchaseDate":          now.Add(-time.Minute).UnixMilli(),
		"originalPurchaseDate":  now.Add(-time.Minute).UnixMilli(),
		"signedDate":            now.UnixMilli(),
		"quantity":              1,
		"type":                  "Consumable",
		"inAppOwnershipType":    "PURCHASED",
		"environment":           envProduction,
		"storefront":            "USA",
		"transactionReason":     "PURCHASE",
		"currency":              "USD",
		"price":                 1990,
	}
	for k, v := range override {
		if v == nil {
			delete(p, k)
			continue
		}
		p[k] = v
	}
	return p
}

// apiServer 起一个 Get Transaction Info mock，返回链上签好的 signedTransactionInfo。
// respond 为 nil 时按 txPayload 签名应答；否则自定义应答。
func newAPIServer(t *testing.T, chain *testChain, txPayload map[string]any, capture *http.Request) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			*capture = *r.Clone(context.Background())
		}
		if !strings.HasPrefix(r.URL.Path, "/inApps/v1/transactions/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorCode":4040010,"errorMessage":"path mismatch"}`))
			return
		}
		body, _ := json.Marshal(map[string]string{
			"signedTransactionInfo": chain.signJWS(t, txPayload),
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// notFoundServer 起一个恒返回 4040010 的 mock（模拟交易不在该环境）。
func newNotFoundServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorCode":4040010,"errorMessage":"Transaction id not found."}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newPaymentApple 构造指向 mock API 的支付用实例。
func newPaymentApple(t *testing.T, chain *testChain, prodURL, sandboxURL string) (*Apple, *ecdsa.PrivateKey) {
	t.Helper()
	apiKey := genECKey(t)
	a, err := New(Config{
		IssuerID:          testIssuerID,
		KeyID:             testKeyID,
		PrivateKeyP8:      p8PEM(t, apiKey),
		BundleID:          testBundleID,
		APIBaseURL:        prodURL,
		SandboxAPIBaseURL: sandboxURL,
		RootCAs:           chain.pool,
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return a, apiKey
}

func baseReceipt() platform.PaymentReceipt {
	return platform.PaymentReceipt{
		Platform:      PlatformName,
		OrderID:       "order-1",
		TransactionID: "1000000123456789",
		ProductID:     testProductID,
	}
}

func TestVerifyPayment_SuccessProduction(t *testing.T) {
	chain := newTestChain(t, true)
	var captured http.Request
	prod := newAPIServer(t, chain, basePayload(nil), &captured)
	a, apiKey := newPaymentApple(t, chain, prod.URL, newNotFoundServer(t).URL)

	result, err := a.VerifyPayment(context.Background(), baseReceipt())
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if !result.Paid {
		t.Error("Paid = false，期望 true")
	}
	if result.Sandbox {
		t.Error("Sandbox = true，期望 false（Production）")
	}
	if result.Amount != 199 {
		t.Errorf("Amount = %d，期望 199（price 1990 USD → 199 cents）", result.Amount)
	}
	if result.Currency != "USD" {
		t.Errorf("Currency = %q，期望 USD", result.Currency)
	}
	if result.TransactionID != "1000000123456789" {
		t.Errorf("TransactionID = %q", result.TransactionID)
	}
	if result.OrderID != "order-1" {
		t.Errorf("OrderID = %q，期望回传 order-1", result.OrderID)
	}
	if result.ProductID != testProductID {
		t.Errorf("ProductID = %q", result.ProductID)
	}
	if result.PaidAt.IsZero() {
		t.Error("PaidAt 为零值，期望 purchaseDate")
	}
	if result.Raw["price"] != "1990" {
		t.Errorf("Raw[price] = %q，期望原始毫单位 1990 留底", result.Raw["price"])
	}

	// 请求形态核对：路径 + Authorization Bearer ES256 JWT（claims 按官方文档）。
	if want := "/inApps/v1/transactions/1000000123456789"; captured.URL.Path != want {
		t.Errorf("请求路径 = %q，期望 %q", captured.URL.Path, want)
	}
	auth := captured.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("Authorization = %q，期望 Bearer 形态", auth)
	}
	jwt := strings.TrimPrefix(auth, "Bearer ")
	hSeg, pSeg, sSeg, err := splitCompact(jwt)
	if err != nil {
		t.Fatalf("API JWT 非法: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := decodeSegmentJSON(hSeg, &header); err != nil {
		t.Fatalf("API JWT header 解析失败: %v", err)
	}
	if header.Alg != "ES256" || header.Kid != testKeyID || header.Typ != "JWT" {
		t.Errorf("API JWT header = %+v，期望 alg=ES256 kid=%s typ=JWT", header, testKeyID)
	}
	var claims struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Bid string `json:"bid"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := decodeSegmentJSON(pSeg, &claims); err != nil {
		t.Fatalf("API JWT claims 解析失败: %v", err)
	}
	if claims.Iss != testIssuerID || claims.Aud != apiAudience || claims.Bid != testBundleID {
		t.Errorf("API JWT claims = %+v，期望 iss=%s aud=%s bid=%s", claims, testIssuerID, apiAudience, testBundleID)
	}
	if claims.Exp <= claims.Iat || claims.Exp-claims.Iat > 3600 {
		t.Errorf("API JWT exp-iat = %d 秒，应在 (0, 3600] 内（官方上限 60 分钟）", claims.Exp-claims.Iat)
	}
	sigRaw, err := b64uDecode(sSeg)
	if err != nil {
		t.Fatalf("API JWT 签名段非法: %v", err)
	}
	if !es256Verify(&apiKey.PublicKey, []byte(hSeg+"."+pSeg), sigRaw) {
		t.Error("API JWT 签名用配置私钥的公钥验不过")
	}
}

func TestVerifyPayment_SandboxFallback(t *testing.T) {
	chain := newTestChain(t, true)
	prod := newNotFoundServer(t)
	sandbox := newAPIServer(t, chain, basePayload(map[string]any{"environment": envSandbox}), nil)
	a, _ := newPaymentApple(t, chain, prod.URL, sandbox.URL)

	result, err := a.VerifyPayment(context.Background(), baseReceipt())
	if err != nil {
		t.Fatalf("沙箱 fallback 失败: %v", err)
	}
	if !result.Sandbox {
		t.Error("Sandbox = false，期望 true")
	}
	if !result.Paid {
		t.Error("Paid = false，期望 true")
	}
}

func TestVerifyPayment_NotFoundBothEnvs(t *testing.T) {
	chain := newTestChain(t, true)
	a, _ := newPaymentApple(t, chain, newNotFoundServer(t).URL, newNotFoundServer(t).URL)

	_, err := a.VerifyPayment(context.Background(), baseReceipt())
	if err == nil {
		t.Fatal("两环境都 404 应失败")
	}
	if errs.CodeOf(err) != errCodeTransactionIDNotFound {
		t.Errorf("错误码 = %q，期望 %q", errs.CodeOf(err), errCodeTransactionIDNotFound)
	}
}

func TestVerifyPayment_Revoked(t *testing.T) {
	chain := newTestChain(t, true)
	prod := newAPIServer(t, chain, basePayload(map[string]any{
		"revocationDate":   time.Now().UnixMilli(),
		"revocationReason": 0,
	}), nil)
	a, _ := newPaymentApple(t, chain, prod.URL, newNotFoundServer(t).URL)

	result, err := a.VerifyPayment(context.Background(), baseReceipt())
	if err != nil {
		t.Fatalf("已退款交易查询本身应成功: %v", err)
	}
	if result.Paid {
		t.Error("Paid = true，期望 false（已退款/撤销严禁发货）")
	}
	if result.Raw["revocationDate"] == "" {
		t.Error("Raw[revocationDate] 应留底")
	}
}

func TestVerifyPayment_JPYAmount(t *testing.T) {
	chain := newTestChain(t, true)
	prod := newAPIServer(t, chain, basePayload(map[string]any{
		"price": 300000, "currency": "JPY",
	}), nil)
	a, _ := newPaymentApple(t, chain, prod.URL, newNotFoundServer(t).URL)

	result, err := a.VerifyPayment(context.Background(), baseReceipt())
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if result.Amount != 300 {
		t.Errorf("Amount = %d，期望 300（JPY 0 位小数，官方示例 JPY 300 → price 300000）", result.Amount)
	}
}

func TestVerifyPayment_PriceAbsent(t *testing.T) {
	// price 仅在平台记录时出现（文档），缺失时 Amount=0 且 Raw 无 price。
	chain := newTestChain(t, true)
	prod := newAPIServer(t, chain, basePayload(map[string]any{"price": nil, "currency": nil}), nil)
	a, _ := newPaymentApple(t, chain, prod.URL, newNotFoundServer(t).URL)

	result, err := a.VerifyPayment(context.Background(), baseReceipt())
	if err != nil {
		t.Fatalf("VerifyPayment 失败: %v", err)
	}
	if result.Amount != 0 || result.Currency != "" {
		t.Errorf("Amount/Currency = %d/%q，期望 0/空", result.Amount, result.Currency)
	}
	if _, ok := result.Raw["price"]; ok {
		t.Error("price 缺失时 Raw 不应有 price 键")
	}
}

func TestVerifyPayment_Mismatches(t *testing.T) {
	chain := newTestChain(t, true)

	tests := []struct {
		name    string
		payload map[string]any
		receipt func() platform.PaymentReceipt
		wantErr string
	}{
		{
			name:    "bundleId 不符（串单）",
			payload: map[string]any{"bundleId": "com.evil.app"},
			receipt: baseReceipt,
			wantErr: "疑似串单",
		},
		{
			name:    "productId 不符（货不对板）",
			payload: map[string]any{"productId": "com.test.other"},
			receipt: baseReceipt,
			wantErr: "货不对板",
		},
		{
			name:    "应答交易号与请求不匹配",
			payload: map[string]any{"transactionId": "999", "originalTransactionId": "999"},
			receipt: baseReceipt,
			wantErr: "不匹配",
		},
		{
			name:    "应答环境与请求环境不一致",
			payload: map[string]any{"environment": envSandbox},
			receipt: baseReceipt,
			wantErr: "不一致",
		},
		{
			name:    "Platform 字段串平台",
			payload: nil,
			receipt: func() platform.PaymentReceipt {
				r := baseReceipt()
				r.Platform = "tiktok"
				return r
			},
			wantErr: "与本实现（apple）不符",
		},
		{
			name:    "交易号与 Payload 都缺失",
			payload: nil,
			receipt: func() platform.PaymentReceipt {
				r := baseReceipt()
				r.TransactionID = ""
				return r
			},
			wantErr: "至少传一个",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prod := newAPIServer(t, chain, basePayload(tc.payload), nil)
			a, _ := newPaymentApple(t, chain, prod.URL, newNotFoundServer(t).URL)
			_, err := a.VerifyPayment(context.Background(), tc.receipt())
			if err == nil {
				t.Fatalf("期望错误（含 %q），实际成功", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误 %q 不含期望片段 %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestVerifyPayment_PayloadJWS(t *testing.T) {
	// StoreKit 2 形态：客户端只上送 signedTransaction（JWS），服务端验签提取
	// 交易号后仍以服务端查询应答为准。
	chain := newTestChain(t, true)
	prod := newAPIServer(t, chain, basePayload(nil), nil)
	a, _ := newPaymentApple(t, chain, prod.URL, newNotFoundServer(t).URL)

	receipt := baseReceipt()
	receipt.TransactionID = ""
	receipt.Payload = chain.signJWS(t, basePayload(nil))
	result, err := a.VerifyPayment(context.Background(), receipt)
	if err != nil {
		t.Fatalf("Payload JWS 流程失败: %v", err)
	}
	if !result.Paid || result.TransactionID != "1000000123456789" {
		t.Errorf("结果异常: %+v", result)
	}

	// Payload 与 TransactionID 不一致 → 串单拒绝。
	receipt = baseReceipt()
	receipt.TransactionID = "111"
	receipt.Payload = chain.signJWS(t, basePayload(nil))
	if _, err := a.VerifyPayment(context.Background(), receipt); err == nil ||
		!strings.Contains(err.Error(), "不一致") {
		t.Fatalf("期望串单拒绝，实际: %v", err)
	}

	// Payload 被篡改（换 payload 段）→ 验签失败。
	receipt = baseReceipt()
	receipt.TransactionID = ""
	jws := chain.signJWS(t, basePayload(nil))
	parts := strings.Split(jws, ".")
	parts[1] = b64uEncode([]byte(`{"transactionId":"hacked"}`))
	receipt.Payload = strings.Join(parts, ".")
	if _, err := a.VerifyPayment(context.Background(), receipt); err == nil ||
		!strings.Contains(err.Error(), "验签失败") {
		t.Fatalf("期望验签失败，实际: %v", err)
	}
}

func TestVerifyPayment_JWSChainSecurity(t *testing.T) {
	goodChain := newTestChain(t, true)
	evilChain := newTestChain(t, true)   // 另一条根不在信任池里的链
	noOIDChain := newTestChain(t, false) // 缺 Apple 专属扩展 OID 的链

	tests := []struct {
		name    string
		jws     func() string
		wantErr string
	}{
		{
			name:    "证书链根不可信",
			jws:     func() string { return evilChain.signJWS(t, basePayload(nil)) },
			wantErr: "证书链校验失败",
		},
		{
			name:    "缺 Apple 专属扩展 OID",
			jws:     func() string { return noOIDChain.signJWS(t, basePayload(nil)) },
			wantErr: "OID",
		},
		{
			name: "签名被篡改",
			jws: func() string {
				jws := goodChain.signJWS(t, basePayload(nil))
				parts := strings.Split(jws, ".")
				sig, _ := b64uDecode(parts[2])
				sig[0] ^= 0xFF
				parts[2] = b64uEncode(sig)
				return strings.Join(parts, ".")
			},
			wantErr: "签名校验失败",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// mock server 直接回这条问题 JWS
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := json.Marshal(map[string]string{"signedTransactionInfo": tc.jws()})
				_, _ = w.Write(body)
			}))
			t.Cleanup(srv.Close)
			a, _ := newPaymentApple(t, goodChain, srv.URL, newNotFoundServer(t).URL)
			_, err := a.VerifyPayment(context.Background(), baseReceipt())
			if err == nil {
				t.Fatalf("期望错误（含 %q），实际成功", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误 %q 不含期望片段 %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestVerifyPayment_HTTPErrors(t *testing.T) {
	chain := newTestChain(t, true)

	tests := []struct {
		name          string
		status        int
		body          string
		wantRetryable bool
		wantCode      string
	}{
		{
			name:          "401 鉴权失败不可重试",
			status:        http.StatusUnauthorized,
			body:          `{"errorCode":4010000,"errorMessage":"invalid JWT"}`,
			wantRetryable: false,
			wantCode:      "4010000",
		},
		{
			name:          "429 限频可重试",
			status:        http.StatusTooManyRequests,
			body:          `{"errorCode":4290000,"errorMessage":"Rate limit exceeded."}`,
			wantRetryable: true,
			wantCode:      "4290000",
		},
		{
			name:          "500 服务端错误可重试",
			status:        http.StatusInternalServerError,
			body:          `{"errorCode":5000000,"errorMessage":"general internal error"}`,
			wantRetryable: true,
			wantCode:      "5000000",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			a, _ := newPaymentApple(t, chain, srv.URL, newNotFoundServer(t).URL)
			_, err := a.VerifyPayment(context.Background(), baseReceipt())
			if err == nil {
				t.Fatal("期望失败")
			}
			if errs.IsRetryable(err) != tc.wantRetryable {
				t.Errorf("IsRetryable = %v，期望 %v（err=%v）", errs.IsRetryable(err), tc.wantRetryable, err)
			}
			if errs.CodeOf(err) != tc.wantCode {
				t.Errorf("CodeOf = %q，期望 %q", errs.CodeOf(err), tc.wantCode)
			}
		})
	}
}

func TestVerifyPayment_NoPaymentCreds(t *testing.T) {
	a, err := New(Config{ClientID: testClientID})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if _, err := a.VerifyPayment(context.Background(), baseReceipt()); err == nil ||
		!strings.Contains(err.Error(), "支付能力不可用") {
		t.Fatalf("期望提示支付能力不可用，实际: %v", err)
	}
}
