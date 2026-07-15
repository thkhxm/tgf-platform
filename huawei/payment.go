//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：PaymentProvider——IAP 验证购买 Token（Order/Subscription）+ 应用级 AT 缓存 + 应答验签
//2026/6/11
//***************************************************

package huawei

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const (
	opVerifyPayment = "verify_purchase_token"
	opAppAT         = "obtain_app_at"
)

// IAP 验证购买 Token 接口路径。
const (
	// orderVerifyPath Order 服务验证购买 Token（消耗型/非消耗型商品）。
	//
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/api-order-verify-purchase-token-0000001050746113
	// （2026-06-11 拉取）
	//   - POST {rootUrl}/applications/purchases/tokens/verify
	//   - Header：Content-Type: application/json; charset=UTF-8 +
	//     Authorization: Basic Base64("APPAT:"+应用级AT)（鉴权格式见 buildIAPAuthorization）
	//   - Body：{"purchaseToken":"...","productId":"..."}
	//   - 应答：{responseCode("0"=成功，错误码见 server-error-code 文档) /
	//     responseMessage / purchaseTokenData(JSON 字符串，原样参与签名) /
	//     dataSignature / signatureAlgorithm}
	//   - 约束：只能校验用户对特定商品的"最新一笔" token（历史 token 返回错误码 12）；
	//     响应体要求用应用 RSA IAP 公钥验签。
	orderVerifyPath = "/applications/purchases/tokens/verify"

	// subscriptionVerifyPath Subscription 服务验证购买 Token（订阅型商品）。
	//
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/api-subscription-verify-purchase-token-0000001050706080
	// （2026-06-11 拉取）
	//   - POST {rootUrl}/sub/applications/v2/purchases/get
	//   - Header 同 Order 接口；Body：{"subscriptionId":"...","purchaseToken":"..."}
	//   - 应答：{responseCode / responseMessage / inappPurchaseData(注意字段名与
	//     Order 接口的 purchaseTokenData 不同) / dataSignature / signatureAlgorithm}
	subscriptionVerifyPath = "/sub/applications/v2/purchases/get"
)

// receiptRawKeySubscriptionID 订阅校验路径的开关：receipt.Raw 里带此 key
// （值为订阅 ID，InAppPurchaseData.subscriptionId）即走 Subscription 服务接口。
const receiptRawKeySubscriptionID = "subscriptionId"

// appATCache 是应用级 Access Token 缓存。
// 官方最佳实践（文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/obtain-application-level-at-0000001051066052 ，
// 2026-06-11 拉取）："不要在每次调用服务端接口之前都重新申请应用 AT，频繁的申请
// 可能触发服务拒绝……建议在访问服务端接口并且返回的 http 结果码为 401 时，才重新
// 申请应用 AT。"本实现：有效期内复用（提前 appATExpireMargin 过期）+ 401 时强制
// 刷新重试一次，双保险。
type appATCache struct {
	mu       sync.Mutex
	token    string
	expireAt time.Time
}

// iapVerifyResp 是两个验证接口的应答合一（purchaseTokenData / inappPurchaseData
// 字段名不同，各自声明；其余字段同构）。
type iapVerifyResp struct {
	ResponseCode    string `json:"responseCode"`
	ResponseMessage string `json:"responseMessage"`
	// PurchaseTokenData Order 接口的购买数据 JSON 字符串（原样参与签名）。
	PurchaseTokenData string `json:"purchaseTokenData"`
	// InappPurchaseData Subscription 接口的购买数据 JSON 字符串。
	InappPurchaseData  string `json:"inappPurchaseData"`
	DataSignature      string `json:"dataSignature"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
}

// flexInt64 兼容数字与字符串两种 JSON 形态的 int64。
// 官方字段表声明 price / purchaseTime 等为 Long，但 Order 接口的官方应答示例里
// price 是字符串 "100"（文档自相矛盾，两种形态都见于官方正文）——防御性兼容。
type flexInt64 int64

func (f *flexInt64) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("无法解析为整数: %s", httpx.SafeBodySummary(data))
	}
	*f = flexInt64(v)
	return nil
}

// inAppPurchaseData 是购买详情 InAppPurchaseData（只列映射需要的字段，全量原文
// 经 PaymentResult.Raw["inAppPurchaseData"] 透传）。
//
// 字段语义文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/json-inapppurchasedata-0000001050986125
// （2026-06-11 拉取），关键字段：
//   - purchaseState：-1 初始化 / 0 已购买 / 1 已取消 / 2 已退款 / 3 待处理；
//   - price：商品实际价格 ×100 后的值（如 501 = 实际价格 5.01）——对 CNY/USD 等
//     2 位小数货币即合约 Amount 要求的"最小货币单位"；0 位小数货币（JPY 等）华为
//     口径仍为 ×100，业务核对金额时注意（单位纪律，绝不凭记忆换算）；
//   - currency：ISO 4217；
//   - purchaseTime：UTC 毫秒时间戳；
//   - purchaseType：0=沙盒环境（正式购买不返回该参数）——指针区分"缺失"与 0；
//   - kind：0 消耗型 / 1 非消耗型 / 2 订阅型。
type inAppPurchaseData struct {
	OrderID        string    `json:"orderId"`
	ProductID      string    `json:"productId"`
	ProductName    string    `json:"productName"`
	PurchaseState  int       `json:"purchaseState"`
	PurchaseTime   flexInt64 `json:"purchaseTime"`
	PurchaseToken  string    `json:"purchaseToken"`
	PurchaseType   *int      `json:"purchaseType"`
	Kind           int       `json:"kind"`
	Price          flexInt64 `json:"price"`
	Currency       string    `json:"currency"`
	Country        string    `json:"country"`
	PayOrderID     string    `json:"payOrderId"`
	PayType        string    `json:"payType"`
	PackageName    string    `json:"packageName"`
	ApplicationID  flexInt64 `json:"applicationId"`
	ConsumptionSta *int      `json:"consumptionState"`
	DeveloperPay   string    `json:"developerPayload"`
	// 订阅场景字段（Order 路径无值）。
	SubscriptionID string    `json:"subscriptionId"`
	SubIsValid     *bool     `json:"subIsvalid"`
	ExpirationDate flexInt64 `json:"expirationDate"`
	AutoRenewing   bool      `json:"autoRenewing"`
}

// VerifyPayment 实现 platform.PaymentProvider。
//
// receipt 字段映射（与合约对 Google Play 的映射同构——华为同样以 purchaseToken
// 为验证凭据）：
//
//   - TransactionID ← InAppPurchaseData.purchaseToken（必填，验证凭据）；
//   - ProductID     ← 商品 ID（必填，接口请求字段，且用于核对货不对板）；
//   - Raw["subscriptionId"] 非空 → 走 Subscription 服务接口（订阅型商品），
//     否则走 Order 服务接口（消耗型/非消耗型）。
//
// 结果映射（以华为服务端应答为准，绝不信任客户端上报）：
//
//   - Paid     ← purchaseState == 0（已购买）；
//   - Sandbox  ← purchaseType 存在且 == 0（沙盒环境；正式购买不返回该字段）；
//   - Amount   ← price（华为口径"实际价格×100"，见 inAppPurchaseData 注释的单位说明）；
//   - TransactionID ← orderId（平台侧交易号）；PaidAt ← purchaseTime（UTC 毫秒）。
//
// 流程硬要求（官方）：应答先用 IAP 公钥对 purchaseTokenData 验签（Config.IAPPublicKey
// 必须已配置），再核对 productId 一致后映射；金额/币种的最终核对由业务按合约
// 约定执行（结果里已是平台确认值）。发货成功后还须按官方流程做消耗确认
// （consumeOwnedPurchase 或 Order 服务确认购买接口）——that 属业务侧流程，不在
// 本方法范围。
func (h *Huawei) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"receipt.Platform 不匹配（防串单）: "+truncate(receipt.Platform, 32))
	}
	if receipt.TransactionID == "" {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"receipt.TransactionID 为空（应填 InAppPurchaseData.purchaseToken）")
	}
	if receipt.ProductID == "" {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"receipt.ProductID 为空（验证接口必填字段）")
	}
	if h.iapPublicKey == nil {
		// 官方使用约束："响应体要求使用应用 RSA IAP 公钥进行验证"——未配置公钥
		// 无法满足验签硬要求，宁可失败不可降级跳过（IAP 公钥在 AppGallery Connect
		// 「查询支付服务信息」获取）。
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"Config.IAPPublicKey 未配置，无法按官方要求对应答验签")
	}

	subscriptionID := receipt.Raw[receiptRawKeySubscriptionID]
	var (
		endpoint string
		reqBody  map[string]string
	)
	if subscriptionID != "" {
		endpoint = httpx.JoinURL(h.cfg.SubscriptionSiteURL, subscriptionVerifyPath)
		reqBody = map[string]string{
			"subscriptionId": subscriptionID,
			"purchaseToken":  receipt.TransactionID,
		}
	} else {
		endpoint = httpx.JoinURL(h.cfg.OrderSiteURL, orderVerifyPath)
		reqBody = map[string]string{
			"purchaseToken": receipt.TransactionID,
			"productId":     receipt.ProductID,
		}
	}

	resp, err := h.postIAPWithAuth(ctx, endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	var body iapVerifyResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opVerifyPayment, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 业务返回码："0" 成功；其他失败（错误码表：
	// https://developer.huawei.com/consumer/cn/doc/HMSCore-References/server-error-code-0000001050166248 ，
	// 2026-06-11 拉取：5=IAP 未开通、6=致命错误、8=未拥有商品、9=已消耗/已确认、
	// 11=账号已销户、12=订单记录不存在/非最新一笔）。
	if body.ResponseCode != "0" {
		return nil, errs.New(PlatformName, opVerifyPayment, body.ResponseCode,
			"IAP 验证失败: "+body.ResponseMessage).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opVerifyPayment, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	// 两个接口的购买数据字段名不同（见 iapVerifyResp 注释）。
	dataStr := body.PurchaseTokenData
	if subscriptionID != "" {
		dataStr = body.InappPurchaseData
	}
	if dataStr == "" {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"应答缺少购买数据字段: "+resp.SafeSummary())
	}

	// 官方硬要求：用 IAP 公钥对购买数据 JSON 字符串验签（"该字段原样参与签名"——
	// 必须用原始字符串字节，绝不可反序列化再序列化）。
	if err := h.verifyIAPSignature([]byte(dataStr), body.DataSignature, body.SignatureAlgorithm); err != nil {
		return nil, err
	}

	var data inAppPurchaseData
	if err := httpx.DecodeJSON([]byte(dataStr), &data); err != nil {
		return nil, errs.Wrap(PlatformName, opVerifyPayment, err)
	}
	// 防货不对板：平台确认的商品 ID 必须与请求一致（官方要求验证 productId 一致后发货）。
	if data.ProductID != "" && data.ProductID != receipt.ProductID {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"productId 不一致（疑似货不对板）: 平台="+truncate(data.ProductID, 64)+" 请求="+truncate(receipt.ProductID, 64))
	}

	result := &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       receipt.OrderID,
		TransactionID: data.OrderID,
		ProductID:     data.ProductID,
		Amount:        int64(data.Price),
		Currency:      data.Currency,
		// purchaseState：0=已购买（其余 -1 初始化 / 1 已取消 / 2 已退款 / 3 待处理
		// 一律不算已支付）。false 时业务严禁发货（合约纪律）。
		Paid: data.PurchaseState == 0,
		// purchaseType=0 表示沙盒环境；正式购买不返回该字段。
		Sandbox: data.PurchaseType != nil && *data.PurchaseType == 0,
		Raw: map[string]string{
			"purchaseState":     strconv.Itoa(data.PurchaseState),
			"kind":              strconv.Itoa(data.Kind),
			"purchaseToken":     data.PurchaseToken,
			"payOrderId":        data.PayOrderID,
			"payType":           data.PayType,
			"country":           data.Country,
			"productName":       data.ProductName,
			"packageName":       data.PackageName,
			"applicationId":     strconv.FormatInt(int64(data.ApplicationID), 10),
			"developerPayload":  data.DeveloperPay,
			"inAppPurchaseData": dataStr,
		},
	}
	if data.PurchaseTime > 0 {
		result.PaidAt = time.UnixMilli(int64(data.PurchaseTime)).UTC()
	}
	if data.ConsumptionSta != nil {
		result.Raw["consumptionState"] = strconv.Itoa(*data.ConsumptionSta)
	}
	// 订阅场景补充字段：subIsvalid 是订阅"当前是否有效"的官方判定（已收费未过期
	// 未退款/宽限期内），业务做订阅权益判定应看它与 expirationDate，而非只看 Paid。
	if subscriptionID != "" {
		result.Raw["subscriptionId"] = data.SubscriptionID
		result.Raw["autoRenewing"] = strconv.FormatBool(data.AutoRenewing)
		if data.SubIsValid != nil {
			result.Raw["subIsvalid"] = strconv.FormatBool(*data.SubIsValid)
		}
		if data.ExpirationDate > 0 {
			result.Raw["expirationDate"] = strconv.FormatInt(int64(data.ExpirationDate), 10)
		}
	}
	return result, nil
}

// postIAPWithAuth 携带应用级 AT 调 IAP 服务端接口；HTTP 401 时按官方最佳实践
// 强制刷新 AT 重试一次。
func (h *Huawei) postIAPWithAuth(ctx context.Context, endpoint string, body map[string]string) (*httpx.Response, error) {
	for attempt := 0; ; attempt++ {
		at, err := h.appAccessToken(ctx, attempt > 0)
		if err != nil {
			return nil, err
		}
		header := http.Header{}
		header.Set("Authorization", buildIAPAuthorization(at))
		resp, err := h.hc.PostJSON(ctx, endpoint, body, header)
		if err != nil {
			return nil, errs.Wrap(PlatformName, opVerifyPayment, err).WithRetryable(true)
		}
		// 401=需要鉴权（AT 过期/无效）→ 强制刷新 AT 重试一次（仅一次，防死循环）。
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		return resp, nil
	}
}

// buildIAPAuthorization 构造 IAP 服务端接口的鉴权头。
// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/api-common-statement-0000001050986127
// （2026-06-11 拉取）："应用级 AT：Authorization: Basic Base64(APPAT:atvalue)"——
// 即字面量前缀 "APPAT:" 拼接 AT 后整体 base64（官方示例：Base64("APPAT:thisIsAppAtValue")
// = QVBQQVQ6dGhpc0lzQXBwQXRWYWx1ZQ==）。注意不是 HTTP Basic 的"用户名:密码"语义，
// 凭据种类/格式用错是历史踩坑高发区。
func buildIAPAuthorization(appAT string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("APPAT:"+appAT))
}

// appAccessToken 返回应用级 Access Token（缓存有效则复用；force 强制刷新）。
// 申请协议（client_credentials）见 huawei.go oauthTokenPath 注释与
// https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/open-platform-oauth-0000001053629189
// （2026-06-11 拉取，"客户端模式"小节；应答 {access_token, expires_in(秒), token_type}；
// 流控阈值 1000 次/5 分钟，故必须缓存复用）。
func (h *Huawei) appAccessToken(ctx context.Context, force bool) (string, error) {
	h.appAT.mu.Lock()
	defer h.appAT.mu.Unlock()
	if !force && h.appAT.token != "" && h.now().Before(h.appAT.expireAt) {
		return h.appAT.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {h.cfg.ClientID},
		"client_secret": {h.cfg.ClientSecret},
	}
	tok, err := h.postOAuthToken(ctx, form)
	if err != nil {
		// 透传底层错误，但把 Op 改成本操作名便于定位（保留原错误在 cause 链）。
		if pe, ok := errs.AsPlatformError(err); ok {
			return "", errs.New(PlatformName, opAppAT, pe.Code, pe.Message).
				WithHTTPStatus(pe.HTTPStatus).
				WithRetryable(pe.Retryable).
				WithCause(err)
		}
		return "", err
	}
	if tok.AccessToken == "" {
		return "", errs.New(PlatformName, opAppAT, "", "应答缺少 access_token 字段")
	}
	h.appAT.token = tok.AccessToken
	expiresIn := time.Duration(tok.ExpiresIn) * time.Second
	if expiresIn > appATExpireMargin {
		expiresIn -= appATExpireMargin
	}
	h.appAT.expireAt = h.now().Add(expiresIn)
	return h.appAT.token, nil
}

// verifyIAPSignature 用 IAP 公钥校验签名。
// 算法语义（文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/verifying-signature-returned-result-0000001050033088
// 与 api-common-statement，均 2026-06-11 拉取）：
//   - signatureAlgorithm 为空 → 默认 "SHA256WithRSA"（PKCS#1 v1.5）；
//   - "SHA256WithRSA/PSS" → RSA-PSS（请求头 HW-IAP-APPINFO 指定后启用）；
//   - 官方仅定义上述两种，其余取值拒绝（不猜测语义）。
//
// 签名为标准 base64；大小写按官方原文匹配，但防御性忽略大小写差异
// （官方页面同时出现 SHA256WithRSA 与 SHA256withRSA 两种写法）。
func (h *Huawei) verifyIAPSignature(content []byte, sigB64, algorithm string) error {
	if sigB64 == "" {
		return errs.New(PlatformName, opVerifyPayment, "", "应答缺少 dataSignature 字段，无法验签")
	}
	switch {
	case algorithm == "" || strings.EqualFold(algorithm, "SHA256WithRSA"):
		if err := sign.RSASHA256VerifyBase64(h.iapPublicKey, content, sigB64); err != nil {
			return errs.New(PlatformName, opVerifyPayment, "", "应答验签失败（SHA256WithRSA）").WithCause(err)
		}
	case strings.EqualFold(algorithm, "SHA256WithRSA/PSS"):
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return errs.New(PlatformName, opVerifyPayment, "", "dataSignature 不是合法 base64").WithCause(err)
		}
		digest := sha256.Sum256(content)
		if err := rsa.VerifyPSS(h.iapPublicKey, crypto.SHA256, digest[:], sig, nil); err != nil {
			return errs.New(PlatformName, opVerifyPayment, "", "应答验签失败（SHA256WithRSA/PSS）").WithCause(err)
		}
	default:
		return errs.New(PlatformName, opVerifyPayment, "",
			"未知签名算法 "+truncate(algorithm, 64)+"（官方仅 SHA256WithRSA / SHA256WithRSA/PSS）")
	}
	return nil
}
