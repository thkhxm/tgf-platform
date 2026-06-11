//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description xiaomi：PaymentProvider——主动查询订单支付状态接口（queryOrder.do）
//2026/6/11
//***************************************************

package xiaomi

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opQueryOrder = "query_order"

// queryOrderPath 主动查询订单支付状态接口。
//
// 文档：《小米游戏SDK3.0接入指南》5.3.2 主动查询订单支付状态接口
// https://dev.mi.com/distribute/doc/details?pId=1616（2026-06-11 拉取）；
// https 地址以《小米游戏渠道服务器升级通知》为准
// https://dev.mi.com/distribute/doc/details?pId=1559（2026-06-11 拉取）：
//   - GET https://mis.migc.xiaomi.com/api/biz/service/queryOrder.do
//   - 请求参数：appId / cpOrderId（开发商订单 ID）/ uid（用户 ID）
//     / signature（HMAC-SHA1 签名，算法见 xiaomi.go buildSignSource）
//   - 成功返回 JSON（自身也带 signature，须验签）：appId / cpOrderId /
//     cpUserInfo（可选，开发商透传）/ uid / orderId（平台订单 ID）/
//     orderStatus（TRADE_SUCCESS 成功；WAIT_BUYER_PAY 未支付；
//     REPEAT_PURCHASE 订购关系已存在）/ payFee（单位"分"，即 0.01 米币）/
//     productCode / productName / productCount /
//     payTime（yyyy-MM-dd HH:mm:ss）/ orderConsumeType（可选，10 普通订单；
//     11 直充直消订单）/ signature
//   - 错误返回 JSON：errcode（1506 cpOrderId 错误；1515 appId 错误；
//     1516 uid 错误；1525 signature 错误）/ errMsg（可选）
//
// 注意（官方 5.3.4 接口格式说明 + 5.3.5 签名说明）：返回 JSON 里的文本字段是
// URLencoding 后的形态（官方示例 productName="%E9%93%B6%E5%AD%901%E4%B8%A4"），
// 而签名必须用字符串原值——验签前须对各值做 URL 解码。
const queryOrderPath = "/api/biz/service/queryOrder.do"

// orderStatusPaid 官方订单成功状态值（TRADE_SUCCESS 代表成功）。
const orderStatusPaid = "TRADE_SUCCESS"

// VerifyPayment 实现 platform.PaymentProvider。
//
// 以平台服务端应答为准判定 Paid——绝不信任客户端上报。receipt 必填字段：
//
//   - Platform = "xiaomi"（防串单冗余校验位）
//   - OrderID  = cpOrderId（开发商订单 ID，下单时业务侧生成）
//   - OpenID   = uid（付款用户的平台 ID，查询接口必填参数）
//
// receipt.TransactionID 非空时与应答 orderId 核对，不一致判失败（防串单）。
//
// 安全要求（《小米游戏SDK服务器端接入最佳安全实践》
// https://dev.mi.com/distribute/doc/details?pId=1543 ，2026-06-11 拉取）：
// 校验订单时务必校验 signature 以及 appId、cpOrderId、uid 等字段是否匹配，
// 全部匹配之后才能发货——本方法对应答验签 + 核对三字段，任一不符即失败。
// 金额/商品是否货对板由业务侧拿 PaymentResult 与本地订单核对（合约约定）。
func (x *Xiaomi) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"receipt.Platform 不匹配（防串单）: "+receipt.Platform)
	}
	if receipt.OrderID == "" {
		return nil, errs.New(PlatformName, opQueryOrder, "", "receipt.OrderID（cpOrderId）不能为空")
	}
	if receipt.OpenID == "" {
		return nil, errs.New(PlatformName, opQueryOrder, "", "receipt.OpenID（uid）不能为空")
	}

	params := map[string]string{
		"appId":     x.cfg.AppID,
		"cpOrderId": receipt.OrderID,
		"uid":       receipt.OpenID,
	}
	query := url.Values{
		"appId":     {x.cfg.AppID},
		"cpOrderId": {receipt.OrderID},
		"uid":       {receipt.OpenID},
		"signature": {x.signParams(params)},
	}

	resp, err := x.hc.Get(ctx, httpx.JoinURL(x.cfg.BaseURL, queryOrderPath), query, nil)
	if err != nil {
		// 传输层失败——GET 查询幂等，可安全重试。
		return nil, errs.Wrap(PlatformName, opQueryOrder, err).WithRetryable(true)
	}

	// 应答按 RawMessage 解析：成功应答的数值字段（appId/payFee/productCount）需要
	// 保留原始 JSON token 文本参与验签，经 float64 转一道会破坏大数/格式。
	var fields map[string]json.RawMessage
	if err := resp.JSON(&fields); err != nil {
		return nil, errs.Wrap(PlatformName, opQueryOrder, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	// 错误应答带 errcode（成功应答无该字段，见 queryOrderPath 注释）。
	if raw, ok := fields["errcode"]; ok {
		code := strings.Trim(string(raw), `"`)
		msg := ""
		if m, ok := fields["errMsg"]; ok {
			msg = decodeJSONString(m)
		}
		return nil, errs.New(PlatformName, opQueryOrder, code, msg).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opQueryOrder, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	// 把应答字段统一转为「URL 解码后的原值」字符串表（验签与取值共用）。
	values := make(map[string]string, len(fields))
	for k, raw := range fields {
		values[k] = decodeFieldValue(raw)
	}

	// 应答验签（官方硬要求，见方法注释）。签名串构造规则与请求侧同一套
	// （5.3.5：排除 signature、排除空值、字母序、用原值）。
	sigHex := values["signature"]
	if sigHex == "" {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"应答缺少 signature 字段: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}
	// buildSignSource 自身会排除 signature 键，values 可整表传入。
	if !x.verifyParams(values, sigHex) {
		return nil, errs.New(PlatformName, opQueryOrder, "", "应答签名校验失败（密钥不符或应答被篡改）").
			WithHTTPStatus(resp.StatusCode)
	}

	// 防串单三字段核对（官方硬要求：appId、cpOrderId、uid 必须匹配）。
	if got := values["appId"]; got != x.cfg.AppID {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"应答 appId 不匹配: "+got+" != "+x.cfg.AppID)
	}
	if got := values["cpOrderId"]; got != receipt.OrderID {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"应答 cpOrderId 不匹配: "+got+" != "+receipt.OrderID)
	}
	if got := values["uid"]; got != receipt.OpenID {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"应答 uid 不匹配: "+got+" != "+receipt.OpenID)
	}
	if receipt.TransactionID != "" && values["orderId"] != receipt.TransactionID {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"应答 orderId 与 receipt.TransactionID 不匹配: "+values["orderId"]+" != "+receipt.TransactionID)
	}

	// payFee：官方单位"分"（0.01 米币），与合约 Amount 的最小货币单位语义一致，
	// 原样透传不换算（单位纪律：以官方文档为准，见 doc.go NEEDS-DOC 货币条目）。
	var amount int64
	if v := values["payFee"]; v != "" {
		amount, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, errs.New(PlatformName, opQueryOrder, "",
				"应答 payFee 非整数（官方单位为分）: "+truncate(v, 64))
		}
	}

	// payTime：yyyy-MM-dd HH:mm:ss，默认按北京时间解析（官方未注明时区，
	// 见 doc.go NEEDS-DOC）。解析失败不阻断（PaidAt 留零值，原文在 Raw）。
	var paidAt time.Time
	if v := values["payTime"]; v != "" {
		if t, perr := time.ParseInLocation(payTimeLayout, v, x.cfg.PayTimeLocation); perr == nil {
			paidAt = t
		}
	}

	return &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       values["cpOrderId"],
		TransactionID: values["orderId"],
		ProductID:     values["productCode"],
		Amount:        amount,
		Currency:      x.cfg.Currency,
		// Paid 仅认官方成功态 TRADE_SUCCESS；WAIT_BUYER_PAY / REPEAT_PURCHASE
		// 等其它状态一律 false（原始状态在 Raw["orderStatus"]，业务自行分支）。
		Paid: values["orderStatus"] == orderStatusPaid,
		// 小米联运无沙箱交易标识概念（官方文档未定义），恒 false。
		Sandbox: false,
		PaidAt:  paidAt,
		Raw:     values,
	}, nil
}

// decodeFieldValue 把应答 JSON 字段还原成「URL 解码后的原值」：
//   - JSON 字符串 → 去引号转义后再 URL 解码（官方应答文本字段是 URLencoding
//     形态，而签名/取值用原值，见 queryOrderPath 注释）；
//   - JSON 数字等其它 token → 原样文本（数字不含需解码字符）。
//
// URL 解码失败时按原样返回（值本身含裸 % 的极端情况，宁可保留原值参与验签）。
func decodeFieldValue(raw json.RawMessage) string {
	s := decodeJSONString(raw)
	if decoded, err := url.QueryUnescape(s); err == nil {
		return decoded
	}
	return s
}

// decodeJSONString 把 JSON token 还原为字符串：字符串 token 反序列化
// （处理引号与转义），其它 token（数字/布尔）原样返回。
func decodeJSONString(raw json.RawMessage) string {
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return string(raw)
}
