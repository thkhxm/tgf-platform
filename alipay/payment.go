//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：PaymentProvider——alipay.trade.query 查交易状态判定已支付
//2026/6/11
//***************************************************

package alipay

import (
	"context"
	"encoding/json"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opTradeQuery = "trade_query"

// methodTradeQuery 统一收单交易查询接口 alipay.trade.query。
//
// 文档：https://opendocs.alipay.com/open/6f534d7f_alipay.trade.query
// （2026-06-11 经本机代理直连拉取正文核对）
//   - 统一网关 POST gateway.do，公共参数 + RSA2 签名（见 callGateway 注释）
//   - 业务参数走 biz_content（JSON 串）：out_trade_no（商户订单号）与
//     trade_no（支付宝交易号）二选一必填，同时存在优先取 trade_no；
//     query_options 可选（本实现不传）
//   - 成功响应节点 alipay_trade_query_response（code=10000）：
//     trade_no / out_trade_no / trade_status / total_amount（订单金额，
//     「单位为元，两位小数」）/ buyer_user_id 或 buyer_open_id /
//     send_pay_date（打款时间 yyyy-MM-dd HH:mm:ss，特殊可选）/
//     receipt_amount / buyer_pay_amount 等
//   - trade_status 官方枚举（仅四档）：WAIT_BUYER_PAY（交易创建，等待买家付款）、
//     TRADE_CLOSED（未付款交易超时关闭，或支付完成后全额退款）、
//     TRADE_SUCCESS（交易支付成功）、TRADE_FINISHED（交易结束，不可退款）
//   - 业务错误码：ACQ.TRADE_NOT_EXIST（交易不存在）/ ACQ.INVALID_PARAMETER /
//     ACQ.SYSTEM_ERROR（重新发起请求）
const methodTradeQuery = "alipay.trade.query"

// trade_status 枚举（官方四档，见 methodTradeQuery 注释）。
const (
	tradeStatusWaitBuyerPay = "WAIT_BUYER_PAY"
	tradeStatusClosed       = "TRADE_CLOSED"
	tradeStatusSuccess      = "TRADE_SUCCESS"
	tradeStatusFinished     = "TRADE_FINISHED"
)

// tradeQueryBiz alipay.trade.query 的 biz_content（字段名以官方文档为准）。
type tradeQueryBiz struct {
	OutTradeNo string `json:"out_trade_no,omitempty"`
	TradeNo    string `json:"trade_no,omitempty"`
}

// tradeQueryResp alipay.trade.query 的业务响应节点（字段名以官方文档为准，
// 金额类字段官方类型 price、响应示例带引号，用 flexString 容错数字形态）。
type tradeQueryResp struct {
	gatewayCommonResp
	TradeNo        string     `json:"trade_no"`
	OutTradeNo     string     `json:"out_trade_no"`
	TradeStatus    string     `json:"trade_status"`
	TotalAmount    flexString `json:"total_amount"`
	ReceiptAmount  flexString `json:"receipt_amount"`
	BuyerPayAmount flexString `json:"buyer_pay_amount"`
	BuyerUserID    string     `json:"buyer_user_id"`
	BuyerOpenID    string     `json:"buyer_open_id"`
	BuyerLogonID   string     `json:"buyer_logon_id"`
	SendPayDate    string     `json:"send_pay_date"`
}

// VerifyPayment 实现 platform.PaymentProvider：调 alipay.trade.query 查交易，
// 以平台服务端应答的 trade_status 判定 Paid——绝不信任客户端上报。
//
// receipt 字段约定：
//   - OrderID：商户订单号（下单时的 out_trade_no）；
//   - TransactionID：支付宝交易号（trade_no）；
//   - 两者至少填一个（官方：二选一必填，同时存在平台优先取 trade_no）。
//
// 结果映射：
//   - Paid          ← trade_status ∈ {TRADE_SUCCESS, TRADE_FINISHED}（官方四档
//     枚举中仅这两档代表支付成功；WAIT_BUYER_PAY 未付、TRADE_CLOSED 关单/全额退款）
//   - TransactionID ← trade_no（以平台应答为准）
//   - OrderID       ← out_trade_no（平台应答回传）
//   - Amount        ← total_amount 由「元」精确换算为「分」（合约单位纪律）
//   - Currency      = "CNY"：trade.query 响应无币种字段；异步通知参数表对
//     total_amount 的官方描述为「单位为人民币（元）」（203/105286，2026-06-11
//     拉取），本实现仅覆盖境内人民币交易
//   - ProductID     = ""：trade.query 响应无商品字段——业务发货前必须按本地
//     订单记录核对商品与金额，不能拿 ProductID 当核对依据
//   - PaidAt        ← send_pay_date（打款时间，特殊可选；零值表示平台未返回）
//   - Sandbox       ← 网关域名是否指向沙箱（alipaydev，见 SandboxGatewayURL）
//   - Raw           ← trade_status / trade_no / out_trade_no / total_amount /
//     receipt_amount / buyer_pay_amount / buyer_user_id / buyer_open_id /
//     buyer_logon_id / send_pay_date 透传
//
// 防串单：receipt.Platform 非空时必须等于 "alipay"；应答 out_trade_no 与请求
// 不一致时直接报错。
func (a *Alipay) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opTradeQuery, "",
			"receipt.Platform 不匹配（防串单）: "+receipt.Platform)
	}
	if receipt.OrderID == "" && receipt.TransactionID == "" {
		return nil, errs.New(PlatformName, opTradeQuery, "",
			"receipt.OrderID（out_trade_no）与 receipt.TransactionID（trade_no）至少填一个")
	}

	bizJSON, err := json.Marshal(tradeQueryBiz{
		OutTradeNo: receipt.OrderID,
		TradeNo:    receipt.TransactionID,
	})
	if err != nil {
		return nil, errs.Wrap(PlatformName, opTradeQuery, err)
	}
	node, status, err := a.callGateway(ctx, opTradeQuery, methodTradeQuery, map[string]string{
		"biz_content": string(bizJSON),
	})
	if err != nil {
		return nil, err
	}
	var body tradeQueryResp
	if err := json.Unmarshal(node, &body); err != nil {
		return nil, errs.Wrap(PlatformName, opTradeQuery, err).WithHTTPStatus(status)
	}
	if e := bizError(opTradeQuery, status, body.gatewayCommonResp); e != nil {
		return nil, e
	}
	// 防串单：应答的商户订单号必须与请求一致。
	if receipt.OrderID != "" && body.OutTradeNo != "" && body.OutTradeNo != receipt.OrderID {
		return nil, errs.New(PlatformName, opTradeQuery, "",
			"应答 out_trade_no 与请求不一致（疑似串单）: "+body.OutTradeNo+" != "+receipt.OrderID).
			WithHTTPStatus(status)
	}
	switch body.TradeStatus {
	case tradeStatusWaitBuyerPay, tradeStatusClosed, tradeStatusSuccess, tradeStatusFinished:
	default:
		// 官方枚举仅四档——未知状态视为协议异常，宁可失败不可误判发货。
		return nil, errs.New(PlatformName, opTradeQuery, "",
			"未知 trade_status: "+truncate(body.TradeStatus, 64)).
			WithHTTPStatus(status)
	}

	amount, err := yuanToFen(string(body.TotalAmount))
	if err != nil {
		// total_amount 官方标注必选——解析失败视为协议异常。
		return nil, errs.New(PlatformName, opTradeQuery, "",
			"total_amount 解析失败: "+err.Error()).
			WithHTTPStatus(status)
	}
	var paidAt time.Time
	if body.SendPayDate != "" {
		if t, err := parseAlipayTime(body.SendPayDate); err == nil {
			paidAt = t
		}
		// 解析失败不阻断主流程：PaidAt 留零值，原文在 Raw 里。
	}

	return &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       body.OutTradeNo,
		TransactionID: body.TradeNo,
		ProductID:     "",
		Amount:        amount,
		Currency:      "CNY",
		Paid:          body.TradeStatus == tradeStatusSuccess || body.TradeStatus == tradeStatusFinished,
		Sandbox:       a.sandbox(),
		PaidAt:        paidAt,
		Raw: map[string]string{
			"trade_status":     body.TradeStatus,
			"trade_no":         body.TradeNo,
			"out_trade_no":     body.OutTradeNo,
			"total_amount":     string(body.TotalAmount),
			"receipt_amount":   string(body.ReceiptAmount),
			"buyer_pay_amount": string(body.BuyerPayAmount),
			"buyer_user_id":    body.BuyerUserID,
			"buyer_open_id":    body.BuyerOpenID,
			"buyer_logon_id":   body.BuyerLogonID,
			"send_pay_date":    body.SendPayDate,
		},
	}, nil
}
