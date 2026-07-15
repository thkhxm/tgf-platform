//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：PaymentProvider——App Store Server API Get Transaction Info + JWS 交易验签
//2026/6/11
//***************************************************

package apple

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opGetTransactionInfo = "get_transaction_info"

// App Store Server API 协议常量。
const (
	// transactionInfoPath Get Transaction Info 端点路径。
	//
	// 文档：https://developer.apple.com/documentation/appstoreserverapi/get-transaction-info
	// （2026-06-11 拉取）：
	//   - GET https://api.storekit.apple.com/inApps/v1/transactions/{transactionId}
	//   - GET https://api.storekit-sandbox.apple.com/inApps/v1/transactions/{transactionId}
	//   - transactionId 可以是交易号，也可以是 original transaction id；
	//   - 200 → TransactionInfoResponse{signedTransactionInfo: JWSTransaction}；
	//   - 401 → 鉴权 JWT 非法；404 → TransactionIdNotFoundError；
	//     429 → RateLimitExceededError；5xx → GeneralInternalError（可重试）。
	transactionInfoPath = "/inApps/v1/transactions/"

	// apiAudience API 鉴权 JWT 的 aud 声明固定值。
	// 文档：https://developer.apple.com/documentation/appstoreserverapi/generating-json-web-tokens-for-api-requests
	// （2026-06-11 拉取）。
	apiAudience = "appstoreconnect-v1"

	// errCodeTransactionIDNotFound TransactionIdNotFoundError 的业务错误码。
	// 文档：https://developer.apple.com/documentation/appstoreserverapi/transactionidnotfounderror
	// （2026-06-11 拉取，errorCode=4040010）。官方主页（2026-06-11 拉取）给出
	// 环境探测流程：先打生产 URL，收到 4040010 再打沙箱 URL；沙箱也 4040010
	// 则两个环境都没有这笔交易。
	errCodeTransactionIDNotFound = "4040010"

	// envSandbox / envProduction environment 字段取值。
	// 文档：https://developer.apple.com/documentation/appstoreserverapi/environment
	// （2026-06-11 拉取，枚举值 "Sandbox" / "Production"）。
	envSandbox    = "Sandbox"
	envProduction = "Production"
)

// apiErrorResp 是 App Store Server API 的错误应答体
// （文档：https://developer.apple.com/documentation/appstoreserverapi/transactionidnotfounderror ，
// 2026-06-11 拉取：errorCode int64 + errorMessage string）。
type apiErrorResp struct {
	ErrorCode    int64  `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

// transactionInfoResp 是 Get Transaction Info 的成功应答。
// 文档：https://developer.apple.com/documentation/appstoreserverapi/transactioninforesponse
// （2026-06-11 拉取）：signedTransactionInfo 是 Apple 签名的 JWS。
type transactionInfoResp struct {
	SignedTransactionInfo string `json:"signedTransactionInfo"`
}

// transactionPayload 是 JWSTransaction 验签后的解码载荷（取映射所需字段）。
//
// 文档：https://developer.apple.com/documentation/appstoreserverapi/jwstransactiondecodedpayload
// （2026-06-11 拉取），关键字段语义：
//   - price：整数，配置价 ×1000（货币毫单位，"One unit of the currency equals
//     1000 milliunits"；官方示例 $1.99→1990、JPY 300→300000、KRW 3300→3300000，
//     https://developer.apple.com/documentation/appstoreserverapi/price ，2026-06-11 拉取）；
//   - currency：ISO 4217 三字码，仅 price 存在时出现；
//   - purchaseDate / signedDate / revocationDate：UNIX 毫秒；
//   - environment："Sandbox" / "Production"；
//   - revocationDate 存在 = 该交易已退款或被家庭共享撤销。
type transactionPayload struct {
	TransactionID         string `json:"transactionId"`
	OriginalTransactionID string `json:"originalTransactionId"`
	WebOrderLineItemID    string `json:"webOrderLineItemId"`
	BundleID              string `json:"bundleId"`
	ProductID             string `json:"productId"`
	SubscriptionGroupID   string `json:"subscriptionGroupIdentifier"`
	AppTransactionID      string `json:"appTransactionId"`
	PurchaseDate          int64  `json:"purchaseDate"`
	OriginalPurchaseDate  int64  `json:"originalPurchaseDate"`
	ExpiresDate           int64  `json:"expiresDate"`
	SignedDate            int64  `json:"signedDate"`
	Quantity              int64  `json:"quantity"`
	Type                  string `json:"type"`
	AppAccountToken       string `json:"appAccountToken"`
	InAppOwnershipType    string `json:"inAppOwnershipType"`
	RevocationDate        *int64 `json:"revocationDate"`
	RevocationReason      *int64 `json:"revocationReason"`
	Environment           string `json:"environment"`
	Storefront            string `json:"storefront"`
	StorefrontID          string `json:"storefrontId"`
	TransactionReason     string `json:"transactionReason"`
	Currency              string `json:"currency"`
	Price                 *int64 `json:"price"`
}

// VerifyPayment 实现 platform.PaymentProvider。
//
// 以 App Store Server API 的应答为准判定支付状态（合约硬要求：绝不信任客户端
// 上报）。流程：
//
//  1. 确定交易号：优先 receipt.TransactionID；为空时从 receipt.Payload
//     （StoreKit 2 客户端上送的 signedTransaction JWS）经 x5c 链验签后提取——
//     两者都有且不一致按串单拒绝；
//  2. 调 Get Transaction Info（环境探测按官方流程：先生产，404+4040010 再沙箱，
//     见 errCodeTransactionIDNotFound 注释）；
//  3. 对应答的 signedTransactionInfo 做 x5c 链验签（锚定 Apple Root CA - G3，
//     见 jws.go），解码后核对：交易号匹配请求、bundleId 等于 Config.BundleID
//     （防串单）、productId 等于 receipt.ProductID（传入时核对，防货不对板）；
//  4. 映射标准化结果：Paid = 无 revocationDate（已退款/撤销的交易 Paid=false）。
//
// 金额说明：PaymentResult.Amount 按合约语义换算为最小货币单位（cents/分）——
// price 是货币毫单位（×1000），按 ISO 4217 小数位换算（见 minorUnits）。
// App Store 各地区售价由 Apple 汇率体系决定，业务侧不要拿本地配置价与 Amount
// 强相等核对，应以 ProductID 核对商品 + 以 Amount/Currency 记账。
// 原始 price/currency 一并透传在 Raw。
//
// 订阅说明：本方法校验的是"这笔交易真实存在且未退款"。auto-renewable 订阅的
// 当前权益状态（是否仍在有效期）业务应结合 expiresDate（Raw 透传）或订阅状态
// 接口判断，Paid=true 不等于订阅当前有效。
func (a *Apple) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	if a.apiKey == nil {
		return nil, errs.New(PlatformName, opGetTransactionInfo, "",
			"未配置 App Store Server API 凭据（IssuerID/KeyID/PrivateKeyP8/BundleID）——支付能力不可用")
	}
	// 防串单冗余校验位：显式传了其它平台名直接拒绝。
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opGetTransactionInfo, "",
			"PaymentReceipt.Platform="+receipt.Platform+" 与本实现（apple）不符（疑似串单）")
	}

	// —— 确定交易号 ——
	txID := receipt.TransactionID
	if receipt.Payload != "" {
		// Payload 是 StoreKit 2 的 signedTransaction（JWS）——先验签再取字段，
		// 未验签的客户端数据一个字节都不信。
		raw, err := a.verifyAppleJWS(receipt.Payload)
		if err != nil {
			return nil, errs.New(PlatformName, opGetTransactionInfo, "",
				"PaymentReceipt.Payload（signedTransaction JWS）验签失败: "+err.Error())
		}
		var fromPayload transactionPayload
		if err := httpx.DecodeJSON(raw, &fromPayload); err != nil {
			return nil, errs.Wrap(PlatformName, opGetTransactionInfo, err)
		}
		if fromPayload.TransactionID == "" {
			return nil, errs.New(PlatformName, opGetTransactionInfo, "", "Payload JWS 缺少 transactionId 字段")
		}
		if txID == "" {
			txID = fromPayload.TransactionID
		} else if txID != fromPayload.TransactionID {
			return nil, errs.New(PlatformName, opGetTransactionInfo, "",
				"TransactionID="+txID+" 与 Payload JWS 内 transactionId="+fromPayload.TransactionID+" 不一致（疑似串单）")
		}
	}
	if txID == "" {
		return nil, errs.New(PlatformName, opGetTransactionInfo, "",
			"缺少交易号：TransactionID 与 Payload（signedTransaction JWS）至少传一个")
	}

	// —— 调 Get Transaction Info（先生产，4040010 再沙箱，官方环境探测流程） ——
	signedInfo, sandbox, err := a.fetchTransactionInfo(ctx, txID)
	if err != nil {
		return nil, err
	}

	// —— 应答 JWS 验签 + 解码 ——
	raw, err := a.verifyAppleJWS(signedInfo)
	if err != nil {
		return nil, errs.New(PlatformName, opGetTransactionInfo, "",
			"signedTransactionInfo 验签失败: "+err.Error())
	}
	var tx transactionPayload
	if err := httpx.DecodeJSON(raw, &tx); err != nil {
		return nil, errs.Wrap(PlatformName, opGetTransactionInfo, err)
	}

	// —— 核对（防串单 / 货不对板） ——
	if tx.TransactionID != txID && tx.OriginalTransactionID != txID {
		return nil, errs.New(PlatformName, opGetTransactionInfo, "",
			"应答交易号 "+tx.TransactionID+" 与请求交易号 "+txID+" 不匹配（协议异常）")
	}
	if tx.BundleID != a.cfg.BundleID {
		return nil, errs.New(PlatformName, opGetTransactionInfo, "",
			"应答 bundleId="+tx.BundleID+" 与配置 BundleID="+a.cfg.BundleID+" 不符（疑似串单）")
	}
	if receipt.ProductID != "" && tx.ProductID != receipt.ProductID {
		return nil, errs.New(PlatformName, opGetTransactionInfo, "",
			"应答 productId="+tx.ProductID+" 与期望 ProductID="+receipt.ProductID+" 不符（货不对板）")
	}
	// 环境一致性：应答 environment 与实际命中的域名应当一致（官方语义），
	// 不一致按协议异常拒绝，宁可失败不可错判沙箱单。
	wantEnv := envProduction
	if sandbox {
		wantEnv = envSandbox
	}
	if tx.Environment != wantEnv {
		return nil, errs.New(PlatformName, opGetTransactionInfo, "",
			"应答 environment="+tx.Environment+" 与请求环境 "+wantEnv+" 不一致（协议异常）")
	}

	// —— 映射标准化结果 ——
	result := &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       receipt.OrderID,
		TransactionID: tx.TransactionID,
		ProductID:     tx.ProductID,
		Currency:      tx.Currency,
		// Paid：交易真实存在且未被退款/撤销。revocationDate 存在 = 已退款或被
		// 家庭共享撤销（文档见 transactionPayload 注释），此时严禁发货。
		Paid:    tx.RevocationDate == nil,
		Sandbox: tx.Environment == envSandbox,
		Raw:     transactionRaw(&tx),
	}
	if tx.Price != nil {
		result.Amount = minorUnits(*tx.Price, tx.Currency)
	}
	if tx.PurchaseDate > 0 {
		result.PaidAt = time.UnixMilli(tx.PurchaseDate)
	}
	return result, nil
}

// fetchTransactionInfo 调 Get Transaction Info，按官方环境探测流程先生产后沙箱；
// 返回 signedTransactionInfo 与是否命中沙箱环境。
func (a *Apple) fetchTransactionInfo(ctx context.Context, txID string) (signedInfo string, sandbox bool, err error) {
	signedInfo, notFound, err := a.fetchTransactionInfoFrom(ctx, a.cfg.APIBaseURL, txID)
	if err == nil {
		return signedInfo, false, nil
	}
	if !notFound {
		return "", false, err
	}
	// 生产环境 4040010 → 按官方流程改打沙箱。
	signedInfo, notFound, err = a.fetchTransactionInfoFrom(ctx, a.cfg.SandboxAPIBaseURL, txID)
	if err == nil {
		return signedInfo, true, nil
	}
	if notFound {
		return "", false, errs.New(PlatformName, opGetTransactionInfo, errCodeTransactionIDNotFound,
			"交易号 "+txID+" 在生产与沙箱环境都不存在").WithHTTPStatus(http.StatusNotFound)
	}
	return "", false, err
}

// fetchTransactionInfoFrom 对指定环境域名调一次 Get Transaction Info。
// notFound 标记应答是否为 4040010（TransactionIdNotFoundError，触发环境切换）。
func (a *Apple) fetchTransactionInfoFrom(ctx context.Context, baseURL, txID string) (signedInfo string, notFound bool, err error) {
	token, err := a.apiJWT()
	if err != nil {
		return "", false, errs.Wrap(PlatformName, opGetTransactionInfo, err)
	}
	header := http.Header{}
	// 鉴权形态：Authorization: Bearer <ES256 JWT>
	// 文档：https://developer.apple.com/documentation/appstoreserverapi/generating-json-web-tokens-for-api-requests
	// （2026-06-11 拉取）。
	header.Set("Authorization", "Bearer "+token)

	resp, err := a.hc.Get(ctx, httpx.JoinURL(baseURL, transactionInfoPath+txID), nil, header)
	if err != nil {
		return "", false, errs.Wrap(PlatformName, opGetTransactionInfo, err).WithRetryable(true)
	}
	if !resp.OK() {
		var apiErr apiErrorResp
		_ = resp.JSON(&apiErr) // 错误体解析失败按无业务码处理
		if apiErr.ErrorCode == 4040010 {
			return "", true, errs.New(PlatformName, opGetTransactionInfo, errCodeTransactionIDNotFound,
				apiErr.ErrorMessage).WithHTTPStatus(resp.StatusCode)
		}
		code := ""
		if apiErr.ErrorCode != 0 {
			code = strconv.FormatInt(apiErr.ErrorCode, 10)
		}
		msg := apiErr.ErrorMessage
		if msg == "" {
			msg = "HTTP 状态异常: " + resp.SafeSummary()
		}
		return "", false, errs.New(PlatformName, opGetTransactionInfo, code, msg).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	var body transactionInfoResp
	if err := resp.JSON(&body); err != nil {
		return "", false, errs.Wrap(PlatformName, opGetTransactionInfo, err).WithHTTPStatus(resp.StatusCode)
	}
	if body.SignedTransactionInfo == "" {
		return "", false, errs.New(PlatformName, opGetTransactionInfo, "",
			"应答缺少 signedTransactionInfo 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}
	return body.SignedTransactionInfo, false, nil
}

// apiJWT 签发一个 App Store Server API 鉴权 JWT。
//
// 文档：https://developer.apple.com/documentation/appstoreserverapi/generating-json-web-tokens-for-api-requests
// （2026-06-11 拉取）：
//   - header：alg=ES256（必须）、kid=私钥 Key ID、typ=JWT；
//   - payload：iss=Issuer ID、iat=签发时刻（UNIX 秒）、exp=过期时刻（UNIX 秒，
//     距 iat 不得超过 60 分钟）、aud="appstoreconnect-v1"、bid=App 的 bundle ID；
//   - 用 .p8 私钥 ES256 签名；每次请求新签（官方允许复用到过期，这里取更稳妥的短时效）。
func (a *Apple) apiJWT() (string, error) {
	now := a.now()
	header := map[string]string{
		"alg": "ES256",
		"kid": a.cfg.KeyID,
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss": a.cfg.IssuerID,
		"iat": now.Unix(),
		"exp": now.Add(a.cfg.APITokenTTL).Unix(),
		"aud": apiAudience,
		"bid": a.cfg.BundleID,
	}
	return signES256JWT(a.apiKey, header, claims)
}

// transactionRaw 把交易载荷的全部字段透传成 Raw（有什么透传什么，不丢信息）。
func transactionRaw(tx *transactionPayload) map[string]string {
	raw := map[string]string{
		"transactionId":               tx.TransactionID,
		"originalTransactionId":       tx.OriginalTransactionID,
		"webOrderLineItemId":          tx.WebOrderLineItemID,
		"bundleId":                    tx.BundleID,
		"productId":                   tx.ProductID,
		"subscriptionGroupIdentifier": tx.SubscriptionGroupID,
		"appTransactionId":            tx.AppTransactionID,
		"purchaseDate":                strconv.FormatInt(tx.PurchaseDate, 10),
		"originalPurchaseDate":        strconv.FormatInt(tx.OriginalPurchaseDate, 10),
		"expiresDate":                 strconv.FormatInt(tx.ExpiresDate, 10),
		"signedDate":                  strconv.FormatInt(tx.SignedDate, 10),
		"quantity":                    strconv.FormatInt(tx.Quantity, 10),
		"type":                        tx.Type,
		"appAccountToken":             tx.AppAccountToken,
		"inAppOwnershipType":          tx.InAppOwnershipType,
		"environment":                 tx.Environment,
		"storefront":                  tx.Storefront,
		"storefrontId":                tx.StorefrontID,
		"transactionReason":           tx.TransactionReason,
		"currency":                    tx.Currency,
	}
	if tx.Price != nil {
		raw["price"] = strconv.FormatInt(*tx.Price, 10)
	}
	if tx.RevocationDate != nil {
		raw["revocationDate"] = strconv.FormatInt(*tx.RevocationDate, 10)
	}
	if tx.RevocationReason != nil {
		raw["revocationReason"] = strconv.FormatInt(*tx.RevocationReason, 10)
	}
	return raw
}

// currencyExponent ISO 4217 货币小数位（minor units）的非默认值表。
// 来源：ISO 4217 维护机构 SIX 的官方清单 list-one.xml
// （https://www.six-group.com/dam/download/financial-information/data-center/iso-currrency/lists/list-one.xml ，
// 2026-06-11 拉取）；未列出的货币按默认 2 位处理。
var currencyExponent = map[string]int{
	// 0 位小数
	"BIF": 0, "CLP": 0, "DJF": 0, "GNF": 0, "ISK": 0, "JPY": 0, "KMF": 0,
	"KRW": 0, "PYG": 0, "RWF": 0, "UGX": 0, "UYI": 0, "VND": 0, "VUV": 0,
	"XAF": 0, "XOF": 0, "XPF": 0,
	// 3 位小数
	"BHD": 3, "IQD": 3, "JOD": 3, "KWD": 3, "LYD": 3, "OMR": 3, "TND": 3,
	// 4 位小数
	"CLF": 4, "UYW": 4,
}

// minorUnits 把 price（货币毫单位，配置价 ×1000，见 transactionPayload 注释）
// 换算为最小货币单位（合约 Amount 语义：cents/分）。
//
// 换算式：minor = price × 10^exponent / 1000。官方示例核对：
// $1.99 → price 1990，USD 小数位 2 → 1990×100/1000 = 199 cents ✓；
// JPY 300 → price 300000，小数位 0 → 300000/1000 = 300 yen ✓；
// KRW 3300 → price 3300000，小数位 0 → 3300 won ✓。
// 整除不尽时截断（毫单位精度低于 0.1 个最小单位的尾差），原始 price 在
// Raw["price"] 留底供业务对账。
func minorUnits(price int64, currency string) int64 {
	exp := 2
	if e, ok := currencyExponent[currency]; ok {
		exp = e
	}
	switch exp {
	case 0:
		return price / 1000
	case 1:
		return price / 100
	case 2:
		return price / 10
	case 3:
		return price
	default: // 4
		return price * 10
	}
}

// truncate 截断非敏感诊断字段到 n 字节，防错误信息过长。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}
