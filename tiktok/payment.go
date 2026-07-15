//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：PaymentProvider——Minis trade_order 下单 / 查单 / 支付校验 + 支付 webhook 事件解析
//2026/6/11
//***************************************************

package tiktok

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op），按平台 API 名命名。
const (
	opTradeOrderCreate  = "trade_order_create"
	opTradeOrderQuery   = "trade_order_query"
	opParseWebhookEvent = "parse_webhook_event"
)

// endpoint 路径。
//
// 文档：https://developers.tiktok.com/doc/minis-payment-apis（2026-06-11 经本机
// 代理直连拉取正文核对）。两个接口的鉴权完全一致：
//
//	Authorization: Bearer <用户 access token>
//
// 官方对 Authorization 的原文描述："The token that bears the authorization of
// the TikTok user, which is obtained through /oauth/access_token/"，示例值
// "Bearer act.example12345Example12345Example"——即 VerifyLogin（oauth/token）换到
// 的「用户 OAuth token」（act.* 前缀），**不是** client_credentials 换的应用
// client token（历史在 TikTok IAP 上吃过 token 种类用错的亏，平台直接报
// access_token_invalid，全部真实内购线上失败）。
const (
	// tradeOrderCreatePath 创建交易订单（IAP 下单，发起 TTMinis.game.pay 前必经步骤）。
	//
	//   - POST https://open.tiktokapis.com/v2/minis/trade_order/create/
	//   - Content-Type: application/json
	//   - 请求体：token_type（目前仅 "BEANS"）/ token_amount（int，单位是平台虚拟币
	//     Beans 的个数——不是法币金额）/ order_info{order_id, order_url, product_name,
	//     product_id, quantity, quantity_unit, image_url}
	//   - 成功响应：data.trade_order_id（官方要求务必持久化——后续只能用它查单）
	//   - 错误响应：error{code, message, log_id}，code == "ok" 为成功
	tradeOrderCreatePath = "/v2/minis/trade_order/create/"

	// tradeOrderQueryPath 查询交易订单状态。
	//
	//   - POST https://open.tiktokapis.com/v2/minis/trade_order/query/
	//   - Content-Type: application/json
	//   - 请求体：{"trade_order_id": "..."}
	//   - 成功响应：data{trade_order_id, trade_order_status}
	//   - trade_order_status 官方枚举（原文 "Available values are: \"PENDING\" and
	//     \"SUCCESS\""）：PENDING / SUCCESS——仅 SUCCESS 表示支付完成
	tradeOrderQueryPath = "/v2/minis/trade_order/query/"
)

// TokenTypeBeans 是 TikTok Minis 支付的代币类型。官方原文："For now, there is
// only one type: \"BEANS\". Please only use \"BEANS\" in this field."
// 文档：https://developers.tiktok.com/doc/minis-payment-apis（2026-06-11 拉取）。
const TokenTypeBeans = "BEANS"

// trade_order_status 官方枚举。
// 文档：https://developers.tiktok.com/doc/minis-payment-apis（2026-06-11 拉取，
// 原文 "Available values are: \"PENDING\" and \"SUCCESS\""）。
const (
	// TradeOrderStatusPending 订单待支付。
	TradeOrderStatusPending = "PENDING"
	// TradeOrderStatusSuccess 订单支付成功（唯一可发货状态）。
	TradeOrderStatusSuccess = "SUCCESS"
)

// 支付相关 webhook 事件名。
// 文档：https://developers.tiktok.com/doc/mini-games-monetization（2026-06-11 拉取）。
const (
	// EventTradeOrderRedeemSuccess 订单支付成功完成（官方："The order payment has
	// been successfully completed"）——官方明确发放虚拟商品必须以本事件为准。
	EventTradeOrderRedeemSuccess = "minis.trade_order.redeem.success"
	// EventTradeOrderRefundTraceback 用户在商店发起退款，订单金额被部分追回
	// （官方："The refund_amount value is the amount that was recovered"）。
	EventTradeOrderRefundTraceback = "minis.trade_order.redeem.refund_traceback"
)

// ReceiptRawKeyAccessToken 是 platform.PaymentReceipt.Raw 中携带「付款用户的
// OAuth access token」的键名。TikTok 的查单接口按用户维度鉴权（见 endpoint 注释），
// 业务调 VerifyPayment 前必须把该用户登录时 VerifyLogin 返回的
// Raw["access_token"]（act.* 前缀，必要时先用 refresh_token 续期）放进
// receipt.Raw[ReceiptRawKeyAccessToken]。
const ReceiptRawKeyAccessToken = "access_token"

// apiError 是 TikTok Open API v2 通用错误结构（data/error 包封中的 error 部分）。
// 文档：https://developers.tiktok.com/doc/minis-payment-apis（2026-06-11 拉取，
// 响应表中的 "ErrorStruct: The common error structure returned by TikTok Open API"）。
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	LogID   string `json:"log_id"`
}

// ok 报告业务是否成功（code == "ok"）。
func (e *apiError) ok() bool {
	return e.Code == "" || strings.EqualFold(e.Code, "ok")
}

// errMessage 拼接给 errs.Error 的描述（带 log_id 便于向平台报障）。
func (e *apiError) errMessage() string {
	msg := e.Message
	if e.LogID != "" {
		msg += " (log_id=" + e.LogID + ")"
	}
	return msg
}

// retryableAPIError 报告平台业务错误码是否属暂时性失败。
// 官方错误码表（https://developers.tiktok.com/doc/minis-error-codes ，2026-06-11
// 拉取）：50001000 = "TikTok Internal Error"，处置建议 "Retry or do nothing"——
// 唯一标注可重试的码；40001000（参数错误）与 2002xxxx（业务约束）均为确定性失败。
func retryableAPIError(code string, httpStatus int) bool {
	return code == "50001000" || retryableStatus(httpStatus)
}

// OrderInfo 是创建交易订单时业务侧的订单信息（trade_order/create 的 order_info）。
// 字段表见 tradeOrderCreatePath 注释；官方未对子字段标注必填性，本实现只强制
// OrderID（订单关联的根本），其余按需填写、零值省略。
type OrderInfo struct {
	// OrderID 业务系统内的订单号（官方："The ID of your order created in your
	// system"）——webhook 回调 content.order_id 会原样回传，用于对账与幂等发货。
	OrderID string `json:"order_id"`
	// OrderURL 业务系统内订单详情页 URL（用户订单历史页跳转用），可空。
	OrderURL string `json:"order_url,omitempty"`
	// ProductName 用户购买的商品名。
	ProductName string `json:"product_name,omitempty"`
	// ProductID 用户购买的商品 id，可空。
	ProductID string `json:"product_id,omitempty"`
	// Quantity 本单商品数量，可空。
	Quantity int64 `json:"quantity,omitempty"`
	// QuantityUnit 商品计量单位（官方示例 "episode"），可空。
	QuantityUnit string `json:"quantity_unit,omitempty"`
	// ImageURL 订单封面图 URL（用户订单历史页展示），可空。
	ImageURL string `json:"image_url,omitempty"`
}

// tradeOrderCreateReq trade_order/create 请求体（字段名以官方文档为准，
// 见 tradeOrderCreatePath 注释）。
type tradeOrderCreateReq struct {
	TokenType   string    `json:"token_type"`
	TokenAmount int64     `json:"token_amount"`
	OrderInfo   OrderInfo `json:"order_info"`
}

// tradeOrderCreateResp trade_order/create 应答。
type tradeOrderCreateResp struct {
	Data struct {
		TradeOrderID string `json:"trade_order_id"`
	} `json:"data"`
	Error apiError `json:"error"`
}

// tradeOrderQueryResp trade_order/query 应答。
type tradeOrderQueryResp struct {
	Data struct {
		TradeOrderID     string `json:"trade_order_id"`
		TradeOrderStatus string `json:"trade_order_status"`
	} `json:"data"`
	Error apiError `json:"error"`
}

// TradeOrderInfo 是查单结果。
type TradeOrderInfo struct {
	// TradeOrderID TikTok 侧交易订单号。
	TradeOrderID string
	// Status 订单状态，官方枚举 TradeOrderStatusPending / TradeOrderStatusSuccess。
	Status string
}

// CreateTradeOrder 在 TikTok 服务端创建交易订单（IAP 下单第一步），返回
// trade_order_id——客户端随后用它调 TTMinis.game.pay 完成支付。
// 流程（文档：https://developers.tiktok.com/doc/mini-games-monetization ，
// 2026-06-11 拉取）：服务端 create → 客户端 pay → 支付成功后平台投递
// EventTradeOrderRedeemSuccess webhook（发货以该 webhook 为准）。
//
// userAccessToken 必须是付款用户的 OAuth access token（act.* 前缀，VerifyLogin
// 换到的那个），不是应用 client token——见本文件头部 endpoint 注释。
// tokenAmount 单位是 Beans 个数（平台虚拟币，**不是**法币最小单位）。
//
// 返回的 trade_order_id 官方要求持久化：后续只能用它查单。
// 注意：下单是非幂等操作，本方法不做 HTTP 层重试；业务重试应换新的
// OrderInfo.OrderID 或先查单（官方错误码 20021002 = 外部订单号重复）。
func (t *TikTok) CreateTradeOrder(ctx context.Context, userAccessToken string, tokenAmount int64, order OrderInfo) (string, error) {
	if userAccessToken == "" {
		return "", errs.New(PlatformName, opTradeOrderCreate, "", "userAccessToken 为空（需要付款用户的 OAuth access token，act.* 前缀）")
	}
	if tokenAmount <= 0 {
		return "", errs.New(PlatformName, opTradeOrderCreate, "", "tokenAmount 必须为正（单位是 Beans 个数）")
	}
	if order.OrderID == "" {
		return "", errs.New(PlatformName, opTradeOrderCreate, "", "OrderInfo.OrderID 不能为空（业务订单号，webhook 对账依据）")
	}

	header := http.Header{}
	header.Set("Authorization", "Bearer "+userAccessToken)
	reqBody := tradeOrderCreateReq{TokenType: TokenTypeBeans, TokenAmount: tokenAmount, OrderInfo: order}

	resp, err := t.hc.PostJSON(ctx, httpx.JoinURL(t.cfg.BaseURL, tradeOrderCreatePath), reqBody, header)
	if err != nil {
		// 传输层失败——标记可重试，但下单非幂等，重试与否由上层按业务订单号去重决策。
		return "", errs.Wrap(PlatformName, opTradeOrderCreate, err).WithRetryable(true)
	}
	var body tradeOrderCreateResp
	if err := resp.JSON(&body); err != nil {
		return "", errs.Wrap(PlatformName, opTradeOrderCreate, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !body.Error.ok() {
		return "", errs.New(PlatformName, opTradeOrderCreate, body.Error.Code, body.Error.errMessage()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableAPIError(body.Error.Code, resp.StatusCode))
	}
	if !resp.OK() {
		return "", errs.New(PlatformName, opTradeOrderCreate, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.Data.TradeOrderID == "" {
		return "", errs.New(PlatformName, opTradeOrderCreate, "",
			"应答缺少 trade_order_id 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}
	return body.Data.TradeOrderID, nil
}

// QueryTradeOrder 查询交易订单状态（endpoint 协议见 tradeOrderQueryPath 注释）。
// userAccessToken 同 CreateTradeOrder：必须是付款用户的 OAuth access token。
// 查单是幂等只读操作，暂时性失败（网络 / 429 / 5xx / 50001000）可安全重试。
func (t *TikTok) QueryTradeOrder(ctx context.Context, userAccessToken, tradeOrderID string) (*TradeOrderInfo, error) {
	if userAccessToken == "" {
		return nil, errs.New(PlatformName, opTradeOrderQuery, "", "userAccessToken 为空（需要付款用户的 OAuth access token，act.* 前缀）")
	}
	if tradeOrderID == "" {
		return nil, errs.New(PlatformName, opTradeOrderQuery, "", "tradeOrderID 为空")
	}

	header := http.Header{}
	header.Set("Authorization", "Bearer "+userAccessToken)
	reqBody := map[string]string{"trade_order_id": tradeOrderID}

	resp, err := t.hc.PostJSON(ctx, httpx.JoinURL(t.cfg.BaseURL, tradeOrderQueryPath), reqBody, header)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opTradeOrderQuery, err).WithRetryable(true)
	}
	var body tradeOrderQueryResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opTradeOrderQuery, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !body.Error.ok() {
		return nil, errs.New(PlatformName, opTradeOrderQuery, body.Error.Code, body.Error.errMessage()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableAPIError(body.Error.Code, resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opTradeOrderQuery, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.Data.TradeOrderID == "" || body.Data.TradeOrderStatus == "" {
		return nil, errs.New(PlatformName, opTradeOrderQuery, "",
			"应答缺少 trade_order_id / trade_order_status 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}
	return &TradeOrderInfo{TradeOrderID: body.Data.TradeOrderID, Status: body.Data.TradeOrderStatus}, nil
}

// VerifyPayment 实现 platform.PaymentProvider：以 TikTok 服务端查单应答为准
// 判定支付状态（绝不信任客户端上报）。
//
// 入参映射（platform.PaymentReceipt）：
//   - TransactionID：TikTok 侧 trade_order_id（CreateTradeOrder 的返回值，必填）；
//   - Raw[ReceiptRawKeyAccessToken]：付款用户的 OAuth access token（必填，
//     TikTok 查单接口按用户鉴权，见本文件头部 endpoint 注释）；
//   - Platform：非空时必须等于 "tiktok"（合约防串单要求）；
//   - OrderID：原样回传到结果，便于调用方关联。
//
// 出参映射（platform.PaymentResult）：
//   - Paid：仅当 trade_order_status == "SUCCESS"（官方枚举只有 PENDING/SUCCESS；
//     未知状态保守按未支付处理并经 Raw 透传——宁可漏发不可错发）；
//   - TransactionID：以平台应答的 trade_order_id 为准；
//   - Amount/Currency：恒为 0/""——官方查单接口不返回金额，且 TikTok IAP 计价
//     单位是平台虚拟币 Beans 而非法币最小单位（合约 Amount 语义不适用），金额
//     对账应在下单（token_amount）与 webhook 回调环节由业务完成；
//   - ProductID：恒为空——官方查单接口不返回商品信息，宁缺毋假；
//   - Sandbox：恒为 false——官方查单接口不返回环境标识（webhook 退款事件的
//     content.is_sandbox 才有，见 TradeOrderEventContent）；
//   - PaidAt：恒为零值——官方查单接口不返回支付时间；
//   - Raw：透传 trade_order_id / trade_order_status。
//
// 发货纪律：官方明确（https://developers.tiktok.com/doc/mini-games-monetization ，
// 2026-06-11 拉取）发放虚拟商品应以 EventTradeOrderRedeemSuccess webhook 为准；
// 本方法适用于回调丢失后的主动对账 / 补单确认场景，两条链路都要做幂等发货。
func (t *TikTok) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	// 合约防串单：Platform 非空时必须与自身一致。
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opTradeOrderQuery, "",
			"receipt.Platform = "+receipt.Platform+"，与本实现（tiktok）不符（防串单拦截）")
	}
	if receipt.TransactionID == "" {
		return nil, errs.New(PlatformName, opTradeOrderQuery, "",
			"receipt.TransactionID 为空（应填 TikTok trade_order_id，即 CreateTradeOrder 的返回值）")
	}
	userToken := receipt.Raw[ReceiptRawKeyAccessToken]
	if userToken == "" {
		return nil, errs.New(PlatformName, opTradeOrderQuery, "",
			"receipt.Raw[\""+ReceiptRawKeyAccessToken+"\"] 为空——TikTok 查单接口按用户鉴权，"+
				"需要付款用户登录时 VerifyLogin 返回的 OAuth access token（act.* 前缀，过期请先用 refresh_token 续期）")
	}

	info, err := t.QueryTradeOrder(ctx, userToken, receipt.TransactionID)
	if err != nil {
		return nil, err
	}
	return &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       receipt.OrderID,
		TransactionID: info.TradeOrderID,
		Paid:          info.Status == TradeOrderStatusSuccess,
		Raw: map[string]string{
			"trade_order_id":     info.TradeOrderID,
			"trade_order_status": info.Status,
		},
	}, nil
}

// WebhookEvent 是 TikTok webhook 回调体的通用 envelope。
// 文档：https://developers.tiktok.com/doc/webhooks-events（2026-06-11 拉取）。
type WebhookEvent struct {
	// ClientKey 应用的 client key（官方："The unique identification key
	// provisioned to the partner"）。
	ClientKey string `json:"client_key"`
	// Event 事件名（如 EventTradeOrderRedeemSuccess）。
	Event string `json:"event"`
	// CreateTime 事件发生时间，UTC epoch 秒（官方："UTC epoch time is in seconds"）。
	CreateTime int64 `json:"create_time"`
	// UserOpenID 关联用户的 open_id（部分事件为空）。
	UserOpenID string `json:"user_openid"`
	// Content 事件内容，序列化的 JSON 字符串（官方："A serialized JSON string
	// of event information"）——支付事件用 TradeOrderContent 解码。
	Content string `json:"content"`
}

// TradeOrderEventContent 是支付相关事件（EventTradeOrderRedeemSuccess /
// EventTradeOrderRefundTraceback）Content 的解码结果。
// 文档：https://developers.tiktok.com/doc/mini-games-monetization（2026-06-11
// 拉取，官方示例 payload）：
//
//	redeem.success：           {"trade_order_id":"TOID...","order_id":"..."}
//	redeem.refund_traceback：  {"trade_order_id":"TOID...","order_id":"...",
//	                            "is_sandbox":true,"refund_amount":80}
type TradeOrderEventContent struct {
	// TradeOrderID TikTok 侧交易订单号。
	TradeOrderID string `json:"trade_order_id"`
	// OrderID 业务侧订单号（下单时 OrderInfo.OrderID 原样回传，对账依据）。
	OrderID string `json:"order_id"`
	// IsSandbox 是否沙箱交易（官方示例仅退款事件携带；缺省为 false）。
	IsSandbox bool `json:"is_sandbox"`
	// RefundAmount 退款事件中被追回的金额（官方："The refund_amount value is
	// the amount that was recovered"；单位官方未明示——结合下单 token_amount
	// 单位为 Beans，按 Beans 个数理解，真回调时务必复核）。
	RefundAmount int64 `json:"refund_amount"`
}

// ParseWebhookEvent 解析 webhook 回调体的通用 envelope，并核对 client_key 与
// 本应用一致（防止多应用共用回调地址时串单）。
//
// 用法：业务 handler 先经 VerifyWebhook（或 platform.WebhookMiddleware）验签，
// 再读 body 调本方法取事件；防重放已由 VerifyWebhook 完成，本方法只做解析。
func (t *TikTok) ParseWebhookEvent(body []byte) (*WebhookEvent, error) {
	var ev WebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, errs.Wrap(PlatformName, opParseWebhookEvent, err)
	}
	if ev.Event == "" {
		return nil, errs.New(PlatformName, opParseWebhookEvent, "", "回调体缺少 event 字段: "+httpx.SafeBodySummary(body))
	}
	if ev.ClientKey != t.cfg.ClientKey {
		return nil, errs.New(PlatformName, opParseWebhookEvent, "",
			"回调 client_key 与本应用不符（防串单拦截）: "+truncate(ev.ClientKey, 64))
	}
	return &ev, nil
}

// TradeOrderContent 把支付相关事件的 Content 解码为结构化内容。
// 仅接受 EventTradeOrderRedeemSuccess / EventTradeOrderRefundTraceback，
// 其他事件调用属误用，直接报错。
func (e *WebhookEvent) TradeOrderContent() (*TradeOrderEventContent, error) {
	if e.Event != EventTradeOrderRedeemSuccess && e.Event != EventTradeOrderRefundTraceback {
		return nil, errs.New(PlatformName, opParseWebhookEvent, "",
			"事件 "+e.Event+" 不是交易订单事件，不能用 TradeOrderContent 解码")
	}
	var c TradeOrderEventContent
	if err := json.Unmarshal([]byte(e.Content), &c); err != nil {
		return nil, errs.Wrap(PlatformName, opParseWebhookEvent, err)
	}
	if c.TradeOrderID == "" {
		return nil, errs.New(PlatformName, opParseWebhookEvent, "",
			"事件 content 缺少 trade_order_id: "+httpx.SafeBodySummary([]byte(e.Content)))
	}
	return &c, nil
}
