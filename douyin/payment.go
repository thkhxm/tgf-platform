//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：PaymentProvider——queryPayState 按业务订单号主动回查支付状态
//2026/6/11
//***************************************************

package douyin

import (
	"context"
	"net/url"
	"strconv"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opQueryPayState = "query_pay_state"

// queryPayStatePath 主动查询订单状态接口。
//
// 文档：https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/api/javascript-api/payment/order-status-check
// （2026-06-11 curl 拉取正文）
//   - GET https://developer.toutiao.com/api/apps/game/payment/queryPayState
//     （官方文档给出的 URL 仍在原域名，本包严格按文档使用）
//   - Query 参数：access_token（必填，小游戏 access_token，获取方法见 token.go）/
//     orderno（必填，cp 自定义订单号，即下单时 tt.requestGamePayment 传入的 customId）
//   - 输出字段：status（string）——
//     "success" 表示支付成功且发币到账；
//     "unsuccess" 表示支付失败或支付成功未发币到账
//   - 用途（官方原文）：服务端支付回调可能由于网络异常等原因导致无法 100% 触达，
//     开发者可以通过该接口主动回查订单状态，防止超发漏发
//
// NEEDS-DOC：官方文档只给出输出字段 status，未给出错误应答的 JSON 形态与错误码表
// ——下方对 err_no / errcode 做的是防御性解析，实测发现其它错误形态需按真实应答补充。
const queryPayStatePath = "/api/apps/game/payment/queryPayState"

// queryPayState 的 status 取值（官方文档枚举，见 queryPayStatePath 注释）。
const (
	// payStateSuccess 支付成功且发币到账。
	payStateSuccess = "success"
	// payStateUnsuccess 支付失败，或支付成功但未发币到账。
	payStateUnsuccess = "unsuccess"
)

// queryPayStateResp 是 queryPayState 接口的应答。
// 官方文档只定义了 status；err_no / err_tips / errcode / errmsg 是对错误应答的
// 防御性解析（见 queryPayStatePath 注释的 NEEDS-DOC）。
type queryPayStateResp struct {
	Status  string `json:"status"`
	ErrNo   int64  `json:"err_no"`
	ErrTips string `json:"err_tips"`
	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// VerifyPayment 实现 platform.PaymentProvider。
//
// 以 receipt.OrderID（业务侧自定义订单号，必须等于下单时 tt.requestGamePayment
// 的 customId）调 queryPayState 回查支付状态，status=="success" 才判 Paid——
// 以平台服务端应答为准，绝不信任客户端上报。
//
// 结果字段说明（抖音该接口的能力边界）：
//   - queryPayState 不返回金额 / 商品 / 平台交易号——PaymentResult.Amount 恒为 0、
//     Currency 恒为空、TransactionID 原样回传 receipt 的值；
//   - 金额核对请以「支付服务端回调」包体的 amount_cent（单位人民币分）为准
//     （VerifyWebhook 验签通过后用 ParseOrderCallback 取，见 webhook.go）；
//   - status=="unsuccess" 官方语义是「支付失败或支付成功未发币到账」，本方法返回
//     Paid=false 的结果（不是 error）——业务严禁对其发货，可稍后重查。
func (d *Douyin) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	// 防串单：冗余校验位非空时必须与本平台一致（合约约定）。
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opQueryPayState, "",
			"receipt.Platform 与平台不符（疑似串单）: "+receipt.Platform)
	}
	if receipt.OrderID == "" {
		return nil, errs.New(PlatformName, opQueryPayState, "",
			"receipt.OrderID（下单时的 customId）为空")
	}

	token, err := d.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	query := url.Values{
		"access_token": {token},
		"orderno":      {receipt.OrderID},
	}
	resp, err := d.hc.Get(ctx, httpx.JoinURL(d.cfg.ToutiaoBaseURL, queryPayStatePath), query, nil)
	if err != nil {
		// 传输层失败——查询接口幂等，可安全重试。
		return nil, errs.Wrap(PlatformName, opQueryPayState, err).WithRetryable(true)
	}
	var body queryPayStateResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opQueryPayState, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 防御性错误解析（官方未给错误形态，见 NEEDS-DOC）：status 缺失且携带错误字段
	// 时按平台业务错误处理；token 失效类错误顺手作废缓存，下次强制刷新。
	if body.Status == "" {
		code := body.ErrNo
		if code == 0 {
			code = body.ErrCode
		}
		msg := body.ErrTips
		if msg == "" {
			msg = body.ErrMsg
		}
		if code != 0 || msg != "" {
			d.invalidateToken()
			return nil, errs.New(PlatformName, opQueryPayState, strconv.FormatInt(code, 10), msg).
				WithHTTPStatus(resp.StatusCode).
				WithRetryable(retryableStatus(resp.StatusCode))
		}
		return nil, errs.New(PlatformName, opQueryPayState, "",
			"应答缺少 status 字段: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opQueryPayState, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	switch body.Status {
	case payStateSuccess, payStateUnsuccess:
		return &platform.PaymentResult{
			Platform:      PlatformName,
			OrderID:       receipt.OrderID,
			TransactionID: receipt.TransactionID,
			ProductID:     receipt.ProductID,
			Paid:          body.Status == payStateSuccess,
			Raw: map[string]string{
				"status": body.Status,
			},
		}, nil
	default:
		// 官方枚举只有 success / unsuccess——未知取值视为协议异常，宁可失败不可误发货。
		return nil, errs.New(PlatformName, opQueryPayState, "",
			"未知的 status 取值: "+truncate(body.Status, 64)).
			WithHTTPStatus(resp.StatusCode)
	}
}
