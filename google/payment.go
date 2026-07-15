//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：PaymentProvider——service account JWT-bearer 换 token + Play Developer API purchases.products.get
//2026/6/11
//***************************************************

package google

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const (
	opServiceAccountToken = "service_account_token"
	opProductsGet         = "purchases_products_get"
)

// purchaseState 枚举。
// 文档：https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products
// （2026-06-11 拉取）：「The purchase state of the order. Possible values are:
// 0. Purchased 1. Canceled 2. Pending」。
const (
	purchaseStatePurchased = 0
	purchaseStateCanceled  = 1
	purchaseStatePending   = 2
)

// purchaseType 枚举（仅非标准内购流程才有此字段）。
// 文档同上：「This field is only set if this purchase was not made using the
// standard in-app billing flow. Possible values are: 0. Test 1. Promo 2. Rewarded」。
const purchaseTypeTest = 0

// saTokenSource 是 service account 的 OAuth2 access token 源：
// JWT-bearer 流换 token + 进程内缓存（提前 60s 过期触发换新）。并发安全。
//
// 流程（文档：https://developers.google.com/identity/protocols/oauth2/service-account ，
// 2026-06-11 拉取）：
//  1. 构造 JWT：header {"alg":"RS256","typ":"JWT"}（可带 kid）；claims
//     {iss: service account 邮箱, scope: 空格分隔的权限列表,
//     aud: "https://oauth2.googleapis.com/token", exp: 签发后至多 1 小时, iat}；
//  2. 用 service account 私钥做 SHA256withRSA（RSASSA-PKCS1-v1_5）签名，
//     三段各自 base64url 编码后以 "." 拼接；
//  3. POST https://oauth2.googleapis.com/token ，
//     Content-Type: application/x-www-form-urlencoded，参数
//     grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer & assertion=<JWT>；
//  4. 成功应答 {access_token, scope, token_type:"Bearer", expires_in(秒)}，
//     官方明确「Access tokens can be reused during the duration window
//     specified by the expires_in value」——故本类型缓存复用。
type saTokenSource struct {
	email    string
	keyID    string
	priv     *rsa.PrivateKey
	scope    string
	tokenURL string
	hc       *httpx.Client
	now      func() time.Time

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// saTokenLifetime JWT 断言有效期：官方上限「maximum of 1 hour after the
// issued time」，取满 1 小时（access token 的实际寿命由应答 expires_in 决定）。
const saTokenLifetime = time.Hour

// saTokenEarlyRefresh 提前换新余量，避免拿着临过期 token 出门。
const saTokenEarlyRefresh = time.Minute

// oauthTokenResp 是 token 端点应答。成功字段见 saTokenSource 注释；失败为
// OAuth2 风格 {"error":"invalid_grant","error_description":"..."}（官方
// troubleshooting 节列出 unauthorized_client / invalid_scope / invalid_grant
// 等错误名，文档同上）。
type oauthTokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// accessToken 取（缓存的）service account access token。
func (s *saTokenSource) accessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.token != "" && now.Before(s.expiry) {
		return s.token, nil
	}

	assertion, err := s.buildAssertion(now)
	if err != nil {
		return "", errs.Wrap(PlatformName, opServiceAccountToken, err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	resp, err := s.hc.PostForm(ctx, s.tokenURL, form, nil)
	if err != nil {
		return "", errs.Wrap(PlatformName, opServiceAccountToken, err).WithRetryable(true)
	}
	var body oauthTokenResp
	if err := resp.JSON(&body); err != nil {
		return "", errs.Wrap(PlatformName, opServiceAccountToken, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.Error != "" {
		return "", errs.New(PlatformName, opServiceAccountToken, body.Error, body.ErrorDescription).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return "", errs.New(PlatformName, opServiceAccountToken, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.AccessToken == "" || body.ExpiresIn <= 0 {
		return "", errs.New(PlatformName, opServiceAccountToken, "",
			"应答缺少 access_token / expires_in 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}

	s.token = body.AccessToken
	s.expiry = now.Add(time.Duration(body.ExpiresIn)*time.Second - saTokenEarlyRefresh)
	return s.token, nil
}

// buildAssertion 构造并签名 JWT-bearer 断言（协议见 saTokenSource 注释）。
func (s *saTokenSource) buildAssertion(now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss":   s.email,
		"scope": s.scope,
		"aud":   s.tokenURL,
		"exp":   now.Add(saTokenLifetime).Unix(),
		"iat":   now.Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig, err := sign.RSASHA256Sign(s.priv, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// productPurchase 是 purchases.products.get 的应答资源 ProductPurchase。
// 字段表：https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products
// （2026-06-11 拉取）。注意：
//   - purchaseTimeMillis 是 string（int64 format），毫秒（ms since epoch）；
//   - purchaseState / purchaseType / acknowledgementState 用 *int——0 是有效
//     枚举值（Purchased / Test / yet to be acknowledged），必须与「字段缺失」
//     区分开，缺 purchaseState 的应答绝不能误判为已支付；
//   - purchaseToken / productId 官方注明「May not be present」。
type productPurchase struct {
	Kind                        string `json:"kind"`
	PurchaseTimeMillis          string `json:"purchaseTimeMillis"`
	PurchaseState               *int   `json:"purchaseState"`
	ConsumptionState            *int   `json:"consumptionState"`
	DeveloperPayload            string `json:"developerPayload"`
	OrderID                     string `json:"orderId"`
	PurchaseType                *int   `json:"purchaseType"`
	AcknowledgementState        *int   `json:"acknowledgementState"`
	PurchaseToken               string `json:"purchaseToken"`
	ProductID                   string `json:"productId"`
	Quantity                    int    `json:"quantity"`
	ObfuscatedExternalAccountID string `json:"obfuscatedExternalAccountId"`
	ObfuscatedExternalProfileID string `json:"obfuscatedExternalProfileId"`
	RegionCode                  string `json:"regionCode"`
	RefundableQuantity          int    `json:"refundableQuantity"`
}

// googleAPIError 是 Google API 标准错误应答（非 2xx 时）。
// 文档：https://cloud.google.com/apis/design/errors（2026-06-11 拉取）：
// {"error":{"code":<HTTP 状态码>,"message":"...","status":"<google.rpc.Code 枚举名>"}}。
type googleAPIError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// VerifyPayment 实现 platform.PaymentProvider（一次性商品；订阅不在范围，见 doc.go）。
//
// 调 Play Developer API 校验内购状态：
//
// 文档：https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products/get
// （2026-06-11 拉取）：
//   - GET https://androidpublisher.googleapis.com/androidpublisher/v3/applications/
//     {packageName}/purchases/products/{productId}/tokens/{token}
//   - 鉴权：Authorization: Bearer <service account 换的 access token>，
//     scope = https://www.googleapis.com/auth/androidpublisher
//   - 请求体必须为空；成功应答为 ProductPurchase 资源
//
// 凭据映射（合约 types.go 已约定）：receipt.TransactionID = purchaseToken
// （客户端 BillingClient 购买成功后拿到的 token）；receipt.ProductID = 商品 SKU
// （endpoint 路径参数）；packageName 取 Config.PackageName。
//
// 结果映射：
//   - Paid    ← purchaseState == 0（Purchased）；1（Canceled）/ 2（Pending）
//     一律 false——Pending 不是终态，业务严禁对 Pending 发货；
//   - Sandbox ← purchaseType 存在且 == 0（Test，license testing 账号的购买；
//     该字段仅非标准购买流程才出现，缺失即正常生产购买）；
//   - PaidAt  ← purchaseTimeMillis（毫秒，字符串承载的 int64）；
//   - TransactionID ← 应答 purchaseToken（缺失时回填请求的 receipt.TransactionID）；
//   - Amount=0 / Currency=""——该接口**不返回金额/币种**（官方字段表确认无此
//     字段），不与 receipt.Amount 核对、也绝不回填请求值冒充平台确认值；货不对板
//     防护依赖 ProductID 一致性（价格由 Play Console 商品配置锁定），实付金额
//     核对需另接 orders.get（NEEDS-DOC，见 doc.go）。
//
// 发货纪律：Paid==true 只代表「Google 确认这笔购买处于 Purchased 状态」。
// 业务发货必须以 receipt.OrderID 幂等，且发货后按官方要求 acknowledge
// （acknowledgementState==0 的购买 3 天内不确认会被 Google 自动退款——
// acknowledge 接口本包未封装，业务可据 Raw["acknowledgementState"] 判断）。
func (g *Google) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	if g.tokens == nil {
		return nil, errs.New(PlatformName, opProductsGet, "",
			"未配置支付能力：Config.ServiceAccountEmail / ServiceAccountPrivateKeyPEM / PackageName")
	}
	// 防串单：冗余校验位与自身平台名一致才处理。
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opProductsGet, "",
			"receipt.Platform 与平台不符（疑似串单）: "+truncate(receipt.Platform, 32))
	}
	if receipt.TransactionID == "" {
		return nil, errs.New(PlatformName, opProductsGet, "",
			"receipt.TransactionID（purchaseToken）为空")
	}
	if receipt.ProductID == "" {
		return nil, errs.New(PlatformName, opProductsGet, "",
			"receipt.ProductID（商品 SKU，endpoint 路径参数）为空")
	}

	token, err := g.tokens.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := httpx.JoinURL(g.cfg.AndroidPublisherBaseURL,
		"/androidpublisher/v3/applications/"+url.PathEscape(g.cfg.PackageName)+
			"/purchases/products/"+url.PathEscape(receipt.ProductID)+
			"/tokens/"+url.PathEscape(receipt.TransactionID))
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	resp, err := g.hc.Get(ctx, endpoint, nil, header)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opProductsGet, err).WithRetryable(true)
	}
	if !resp.OK() {
		// Google API 标准错误体；解析不出时退化为 HTTP 状态码。
		var apiErr googleAPIError
		if jsonErr := resp.JSON(&apiErr); jsonErr == nil && apiErr.Error.Message != "" {
			code := apiErr.Error.Status
			if code == "" {
				code = strconv.Itoa(apiErr.Error.Code)
			}
			return nil, errs.New(PlatformName, opProductsGet, code, apiErr.Error.Message).
				WithHTTPStatus(resp.StatusCode).
				WithRetryable(retryableStatus(resp.StatusCode))
		}
		return nil, errs.New(PlatformName, opProductsGet, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	var pp productPurchase
	if err := resp.JSON(&pp); err != nil {
		return nil, errs.Wrap(PlatformName, opProductsGet, err).WithHTTPStatus(resp.StatusCode)
	}
	// 200 却没有 purchaseState——按官方协议不该发生；缺它无法判定支付状态，
	// 宁可失败绝不猜测（0 值陷阱：缺失误读为 0 就是误判已支付）。
	if pp.PurchaseState == nil {
		return nil, errs.New(PlatformName, opProductsGet, "",
			"应答缺少 purchaseState 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}
	// 货不对板：应答 productId 存在时必须与请求一致（路径已钉死 productId，
	// 不一致即协议异常，宁可失败不可错发）。
	if pp.ProductID != "" && pp.ProductID != receipt.ProductID {
		return nil, errs.New(PlatformName, opProductsGet, "",
			"应答 productId 与请求不符（疑似货不对板）: "+truncate(pp.ProductID, 64)+" != "+receipt.ProductID)
	}
	// 同理：应答 purchaseToken 存在时必须与请求一致。
	if pp.PurchaseToken != "" && pp.PurchaseToken != receipt.TransactionID {
		return nil, errs.New(PlatformName, opProductsGet, "",
			"应答 purchaseToken 与请求不符（疑似串单）")
	}

	var paidAt time.Time
	if pp.PurchaseTimeMillis != "" {
		ms, err := strconv.ParseInt(pp.PurchaseTimeMillis, 10, 64)
		if err != nil {
			return nil, errs.New(PlatformName, opProductsGet, "",
				"purchaseTimeMillis 非法: "+truncate(pp.PurchaseTimeMillis, 32))
		}
		paidAt = time.UnixMilli(ms).UTC()
	}

	transactionID := pp.PurchaseToken
	if transactionID == "" {
		transactionID = receipt.TransactionID
	}
	productID := pp.ProductID
	if productID == "" {
		productID = receipt.ProductID
	}

	raw := map[string]string{
		"purchaseState": strconv.Itoa(*pp.PurchaseState),
	}
	setIfNotEmpty(raw, "kind", pp.Kind)
	setIfNotEmpty(raw, "purchaseTimeMillis", pp.PurchaseTimeMillis)
	setIfNotEmpty(raw, "developerPayload", pp.DeveloperPayload)
	setIfNotEmpty(raw, "orderId", pp.OrderID)
	setIfNotEmpty(raw, "regionCode", pp.RegionCode)
	setIfNotEmpty(raw, "obfuscatedExternalAccountId", pp.ObfuscatedExternalAccountID)
	setIfNotEmpty(raw, "obfuscatedExternalProfileId", pp.ObfuscatedExternalProfileID)
	if pp.ConsumptionState != nil {
		raw["consumptionState"] = strconv.Itoa(*pp.ConsumptionState)
	}
	if pp.PurchaseType != nil {
		raw["purchaseType"] = strconv.Itoa(*pp.PurchaseType)
	}
	if pp.AcknowledgementState != nil {
		raw["acknowledgementState"] = strconv.Itoa(*pp.AcknowledgementState)
	}
	if pp.Quantity != 0 {
		raw["quantity"] = strconv.Itoa(pp.Quantity)
	}
	if pp.RefundableQuantity != 0 {
		raw["refundableQuantity"] = strconv.Itoa(pp.RefundableQuantity)
	}

	return &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       receipt.OrderID,
		TransactionID: transactionID,
		ProductID:     productID,
		Amount:        0,  // 该接口不返回金额（见方法注释），绝不冒充平台确认值
		Currency:      "", // 同上
		Paid:          *pp.PurchaseState == purchaseStatePurchased,
		Sandbox:       pp.PurchaseType != nil && *pp.PurchaseType == purchaseTypeTest,
		PaidAt:        paidAt,
		Raw:           raw,
	}, nil
}
