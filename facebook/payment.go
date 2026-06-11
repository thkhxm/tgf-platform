//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description facebook：PaymentProvider——Instant Games signedRequest 本地 HMAC 验签 + 字段核对
//2026/6/11
//***************************************************

package facebook

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// 支付校验失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, facebook.ErrXxx) 区分失败原因。
var (
	// ErrSignedRequestMalformed signedRequest 结构非法（缺 "." 分隔 / base64 解码失败 /
	// JSON 解析失败）。
	ErrSignedRequestMalformed = errors.New("facebook: signedRequest 结构非法")
	// ErrSignedRequestSignatureMismatch 签名比对失败（App Secret 不符或载荷被篡改）。
	ErrSignedRequestSignatureMismatch = errors.New("facebook: signedRequest 签名比对失败")
	// ErrReceiptMismatch 平台确认的字段与业务提交的期望值不符（货不对板/串单）。
	ErrReceiptMismatch = errors.New("facebook: 支付凭据与业务期望不符")
)

// 操作名（errs.Error.Op）。
const opVerifyPayment = "verify_signed_request"

// signedRequest 验签协议
//
// 文档：https://developers.facebook.com/docs/games/monetize/in-app-purchases
// （2026-06-11 拉取；任务原给的 /docs/games/build/instant-games/payments-purchases
// 路径已 404，文档站改版后 Instant Games IAP 的权威页即此 Monetize 页，
// "Verifying a Purchase" 一节）：
//
//  1. purchaseAsync 返回的 signedRequest 由 "." 分隔的两段组成：
//     第一段是支付信息的 Base64 编码 SHA256 签名，第二段是支付信息本身的
//     Base64 编码；
//  2. 官方校验样例（JS/Java 一致）：签名段先做 url-safe 字符还原（'-'→'+'、
//     '_'→'/'）再 base64 解码；期望签名 = HMAC-SHA256(key=APP_SECRET,
//     data=第二段【原始字符串】)——注意是对第二段字符串本身做 HMAC，不是对
//     解码后的字节；
//  3. App Secret 绝不可进客户端，signedRequest 只允许在服务端校验（官方原文：
//     "Never embed your app secret into your game"）。
//
// 载荷字段（同页官方样例，2021-08-25 起 id 类字段统一为字符串；此前为数字——
// 官方还特别警告 purchase_token 超出 JS Number.MAX_SAFE_INTEGER，故本实现用
// json.RawMessage 接住数字/字符串两种形态，绝不经 float64 转手）：
//
//	algorithm: "HMAC-SHA256"
//	app_id: "772899436149321"
//	is_consumed: false                          （mock 样例中出现过字符串 ""）
//	issued_at: 1628530124                       （Unix 秒）
//	payment_action_type: "charge"
//	payment_id: "2373285299469015"
//	product_id: "sample_product"
//	purchase_price: {"amount":"0.01","currency":"USD"}（amount 为主单位十进制串）
//	purchase_time: 1628171348                   （单位见 unixFlexible 注释）
//	purchase_token: "10102867843382867"
//	developer_payload / purchase_platform       （mock 样例额外出现）
type signedPaymentPayload struct {
	Algorithm         string          `json:"algorithm"`
	AppID             json.RawMessage `json:"app_id"`
	DeveloperPayload  string          `json:"developer_payload"`
	IsConsumed        json.RawMessage `json:"is_consumed"`
	IssuedAt          int64           `json:"issued_at"`
	PaymentActionType string          `json:"payment_action_type"`
	PaymentID         json.RawMessage `json:"payment_id"`
	ProductID         string          `json:"product_id"`
	PurchasePlatform  string          `json:"purchase_platform"`
	PurchasePrice     *struct {
		Amount   string `json:"amount"`
		Currency string `json:"currency"`
	} `json:"purchase_price"`
	PurchaseTime  json.Number     `json:"purchase_time"`
	PurchaseToken json.RawMessage `json:"purchase_token"`
}

// VerifyPayment 实现 platform.PaymentProvider。
//
// receipt.Payload = Instant Games purchaseAsync 返回的 signedRequest 原串。
// 验签是纯本地 HMAC 计算（协议见 signedPaymentPayload 注释），不访问平台网络，
// ctx 仅为满足合约签名保留。
//
// 核对纪律（合约要求"以平台应答为准判定 Paid + 核对货不对板"）：
//   - 载荷 app_id 必须等于 Config.AppID（防他人应用的凭据串单）；
//   - receipt.ProductID 非空时必须与载荷 product_id 一致；
//   - receipt.TransactionID 非空时必须与载荷 payment_id 或 purchase_token 一致；
//   - receipt.Amount > 0 时，载荷必须携带 purchase_price 且换算到最小货币单位后
//     与之相等（换算规则见 amountToMinorUnits）；receipt.Currency 非空时币种也须一致。
//
// Sandbox 判定：In-App Test Payment 的 mock 交易，官方明确 paymentID 与
// purchaseToken 均为 "111111111" 开头的 17 位数字（文档同上，"In-App Test
// Payment System" 一节）——命中即置 Sandbox=true，生产发货前应按业务策略拦截。
//
// 注意：payment_action_type 在 web 与 Facebook for Android v323+ 才出现
// （官方原文），缺失时按正常购买处理；出现且不是 "charge" 的值官方未给出枚举
// （NEEDS-DOC），本实现宁可报错也不猜测其含义。
func (f *Facebook) VerifyPayment(_ context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	// 冗余校验位：防止业务把别的平台的单据投错实现（合约 PaymentReceipt.Platform 注释）。
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"receipt.Platform="+receipt.Platform+" 与本实现不符（防串单拒绝）").
			WithCause(ErrReceiptMismatch)
	}
	if receipt.Payload == "" {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"receipt.Payload 为空（应为 purchaseAsync 返回的 signedRequest 原串）").
			WithCause(ErrSignedRequestMalformed)
	}

	sigPart, payloadPart, found := strings.Cut(receipt.Payload, ".")
	if !found || sigPart == "" || payloadPart == "" {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"signedRequest 缺少 \".\" 分隔的两段结构").
			WithCause(ErrSignedRequestMalformed)
	}
	sigBytes, err := decodeBase64Flexible(sigPart)
	if err != nil {
		return nil, errs.New(PlatformName, opVerifyPayment, "", "签名段 base64 解码失败: "+err.Error()).
			WithCause(ErrSignedRequestMalformed)
	}
	// 期望签名 = HMAC-SHA256(key=AppSecret, data=第二段原始字符串)——常量时间比较。
	if !sign.VerifyHMACSHA256([]byte(f.cfg.AppSecret), []byte(payloadPart), sigBytes) {
		return nil, errs.New(PlatformName, opVerifyPayment, "", "签名比对失败").
			WithCause(ErrSignedRequestSignatureMismatch)
	}

	payloadBytes, err := decodeBase64Flexible(payloadPart)
	if err != nil {
		return nil, errs.New(PlatformName, opVerifyPayment, "", "载荷段 base64 解码失败: "+err.Error()).
			WithCause(ErrSignedRequestMalformed)
	}
	var payload signedPaymentPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"载荷 JSON 解析失败: "+err.Error()+"（原文片段: "+truncate(string(payloadBytes), 256)+"）").
			WithCause(ErrSignedRequestMalformed)
	}

	// algorithm 必须是官方声明的 HMAC-SHA256（载荷自述算法与实际校验算法一致性兜底）。
	if !strings.EqualFold(payload.Algorithm, "HMAC-SHA256") {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"不支持的签名算法声明: "+payload.Algorithm)
	}
	// 防串单：载荷 app_id 必须是本应用（2021-08-25 前为数字、之后为字符串，统一归一后比对）。
	appID := rawJSONToString(payload.AppID)
	if appID != f.cfg.AppID {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"载荷 app_id="+appID+" 与本应用 "+f.cfg.AppID+" 不符（疑似串单）").
			WithCause(ErrReceiptMismatch)
	}
	// payment_action_type：仅 "charge"（购买扣款）与缺省（旧客户端不下发该字段）
	// 视为有效购买；其余取值官方未枚举（NEEDS-DOC），拒绝判定为已支付。
	if payload.PaymentActionType != "" && !strings.EqualFold(payload.PaymentActionType, "charge") {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"payment_action_type="+payload.PaymentActionType+" 不是已知的购买类型（官方未给出完整枚举，拒绝按已支付处理）")
	}

	paymentID := rawJSONToString(payload.PaymentID)
	purchaseToken := rawJSONToString(payload.PurchaseToken)

	// 货不对板核对（业务提交了期望值才核对；核对不过一律拒绝）。
	if receipt.ProductID != "" && receipt.ProductID != payload.ProductID {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"product_id 不符: 平台="+payload.ProductID+" 期望="+receipt.ProductID).
			WithCause(ErrReceiptMismatch)
	}
	if receipt.TransactionID != "" && receipt.TransactionID != paymentID && receipt.TransactionID != purchaseToken {
		return nil, errs.New(PlatformName, opVerifyPayment, "",
			"TransactionID="+receipt.TransactionID+" 与载荷 payment_id="+paymentID+" / purchase_token="+purchaseToken+" 均不符").
			WithCause(ErrReceiptMismatch)
	}

	// 金额换算与核对：purchase_price.amount 是「主货币单位」的十进制字符串
	// （官方样例 {"amount":"0.01","currency":"USD"}），合约 Amount 要求
	// 「最小货币单位」——按 ISO 4217 小数位换算（见 amountToMinorUnits）。
	var (
		minorAmount int64
		currency    string
	)
	if payload.PurchasePrice != nil {
		currency = payload.PurchasePrice.Currency
		minorAmount, err = amountToMinorUnits(payload.PurchasePrice.Amount, currency)
		if err != nil {
			return nil, errs.New(PlatformName, opVerifyPayment, "",
				"purchase_price 金额换算失败: "+err.Error())
		}
	}
	if receipt.Amount > 0 {
		if payload.PurchasePrice == nil {
			// 官方原文：purchasePrice 字段在 web 与 Facebook for Android v323+
			// 才出现。业务提交了期望金额但载荷没有金额可核——宁可失败不可放行。
			return nil, errs.New(PlatformName, opVerifyPayment, "",
				"业务期望核对金额，但载荷未携带 purchase_price（旧客户端不下发该字段）").
				WithCause(ErrReceiptMismatch)
		}
		if minorAmount != receipt.Amount {
			return nil, errs.New(PlatformName, opVerifyPayment, "",
				"金额不符: 平台="+payload.PurchasePrice.Amount+" "+currency+
					"（最小单位 "+formatInt(minorAmount)+"）期望最小单位 "+formatInt(receipt.Amount)).
				WithCause(ErrReceiptMismatch)
		}
		if receipt.Currency != "" && !strings.EqualFold(receipt.Currency, currency) {
			return nil, errs.New(PlatformName, opVerifyPayment, "",
				"币种不符: 平台="+currency+" 期望="+receipt.Currency).
				WithCause(ErrReceiptMismatch)
		}
	}

	result := &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       receipt.OrderID,
		TransactionID: paymentID,
		ProductID:     payload.ProductID,
		Amount:        minorAmount,
		Currency:      currency,
		// 走到这里：签名有效 + app_id 归属本应用 + 动作类型为购买 + 核对全部通过。
		Paid: true,
		// mock 交易特征见方法注释（官方 In-App Test Payment 文档）。
		Sandbox: isMockPurchaseID(paymentID) || isMockPurchaseID(purchaseToken),
		PaidAt:  unixFlexible(payload.PurchaseTime),
		Raw: map[string]string{
			"algorithm":           payload.Algorithm,
			"app_id":              appID,
			"developer_payload":   payload.DeveloperPayload,
			"is_consumed":         rawJSONToString(payload.IsConsumed),
			"issued_at":           formatInt(payload.IssuedAt),
			"payment_action_type": payload.PaymentActionType,
			"purchase_platform":   payload.PurchasePlatform,
			"purchase_time":       payload.PurchaseTime.String(),
			"purchase_token":      purchaseToken,
		},
	}
	if payload.PurchasePrice != nil {
		result.Raw["purchase_price_amount"] = payload.PurchasePrice.Amount
		result.Raw["purchase_price_currency"] = payload.PurchasePrice.Currency
	}
	return result, nil
}

// decodeBase64Flexible 宽容地解码 base64：先做 url-safe 字符还原（'-'→'+'、
// '_'→'/'，官方校验样例对签名段就是这么做的），再补齐 '=' padding 后按标准
// base64 解码——同时覆盖官方样例的标准 base64 与 signedRequest 实际使用的
// base64url 两种形态。注意 HMAC 永远对**原始字符串**计算，宽容解码不影响验签语义。
func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.StdEncoding.DecodeString(s)
}

// rawJSONToString 把可能是 JSON 字符串或数字的原始字段归一为字符串
// （官方：2021-08-25 前 id 类字段是数字、之后是字符串；数字形态可能超出
// float64 安全整数范围，必须按原文文本处理，绝不经 float64 转手）。
func rawJSONToString(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return ""
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var out string
		if err := json.Unmarshal(raw, &out); err == nil {
			return out
		}
		return strings.Trim(s, `"`)
	}
	return s
}

// isMockPurchaseID 报告 id 是否符合官方 In-App Test Payment mock 交易特征：
// 17 位数字且以 "111111111" 开头（文档：
// https://developers.facebook.com/docs/games/monetize/in-app-purchases ，
// 2026-06-11 拉取，"All successful mock purchases will have the same paymentID
// and purchaseToken structure and length (17 digits): 111111111randomNumber"）。
func isMockPurchaseID(id string) bool {
	if len(id) != 17 || !strings.HasPrefix(id, "111111111") {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// unixFlexible 把官方载荷的 purchase_time 归一为 time.Time。
//
// 单位说明（官方文档自身存在两种形态，均出自
// https://developers.facebook.com/docs/games/monetize/in-app-purchases ，
// 2026-06-11 拉取）：
//   - 2021 样例载荷 purchase_time: 1628171348（10 位，Unix 秒）；
//   - In-App Test Payment mock 样例 signedRequest 解码后
//     purchase_time: 1755529556226（13 位，Unix 毫秒）。
//
// 故按数量级归一：>= 1e12 视为毫秒，否则视为秒。解析失败返回零值
// （合约约定零值表示平台未提供）。
func unixFlexible(n json.Number) time.Time {
	v, err := n.Int64()
	if err != nil || v <= 0 {
		return time.Time{}
	}
	if v >= 1_000_000_000_000 {
		return time.UnixMilli(v)
	}
	return time.Unix(v, 0)
}

// zeroDecimalCurrencies ISO 4217 标准中小数位为 0 的货币（金额最小单位即主单位）。
// 这是 ISO 4217 通用标准，非 Facebook 私有协议。
var zeroDecimalCurrencies = map[string]struct{}{
	"BIF": {}, "CLP": {}, "DJF": {}, "GNF": {}, "ISK": {}, "JPY": {},
	"KMF": {}, "KRW": {}, "PYG": {}, "RWF": {}, "UGX": {}, "VND": {},
	"VUV": {}, "XAF": {}, "XOF": {}, "XPF": {},
}

// threeDecimalCurrencies ISO 4217 标准中小数位为 3 的货币。
var threeDecimalCurrencies = map[string]struct{}{
	"BHD": {}, "IQD": {}, "JOD": {}, "KWD": {}, "LYD": {}, "OMR": {}, "TND": {},
}

// currencyExponent 返回货币的 ISO 4217 小数位（默认 2）。
func currencyExponent(currency string) int {
	c := strings.ToUpper(currency)
	if _, ok := zeroDecimalCurrencies[c]; ok {
		return 0
	}
	if _, ok := threeDecimalCurrencies[c]; ok {
		return 3
	}
	return 2
}

// amountToMinorUnits 把主货币单位的十进制字符串金额（官方样例 "0.01" / "0.89"）
// 按 ISO 4217 小数位换算为最小货币单位整数（USD "0.01" → 1 cent）。
// 纯整数运算，不经浮点；小数位超过该币种 ISO 小数位、或出现非数字字符时报错。
func amountToMinorUnits(amount, currency string) (int64, error) {
	if amount == "" {
		return 0, errors.New("金额字符串为空")
	}
	if amount[0] == '-' {
		return 0, errors.New("金额不允许为负: " + amount)
	}
	exp := currencyExponent(currency)
	intPart, fracPart, _ := strings.Cut(amount, ".")
	if intPart == "" {
		intPart = "0"
	}
	if len(fracPart) > exp {
		// 小数位超出币种精度（如 JPY 带小数），说明单位假设不成立——报错而不是静默截断。
		return 0, errors.New("金额 " + amount + " 的小数位超过币种 " + currency + " 的 ISO 4217 精度")
	}
	// 右补零到精度位：USD "0.1" → frac "10"。
	fracPart += strings.Repeat("0", exp-len(fracPart))
	var v int64
	for _, c := range intPart + fracPart {
		if c < '0' || c > '9' {
			return 0, errors.New("金额含非数字字符: " + amount)
		}
		d := int64(c - '0')
		if v > (1<<63-1-d)/10 {
			return 0, errors.New("金额溢出: " + amount)
		}
		v = v*10 + d
	}
	return v, nil
}

// formatInt 十进制格式化（错误信息拼接用）。
func formatInt(v int64) string {
	return strconv.FormatInt(v, 10)
}
