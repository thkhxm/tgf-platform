//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：PaymentProvider——米大师虚拟支付查询订单状态（pay_v2.queryOrder）判定已支付
//2026/6/11
//***************************************************

package wechat

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opQueryOrder = "query_order"

// queryOrderPath 米大师虚拟支付「查询订单状态」（pay_v2.queryOrder）。
//
// 文档：https://developers.weixin.qq.com/minigame/dev/api-backend/midas-payment/order/api_pay_v2.queryorder.html
// （2026-06-11 拉取）
//   - POST https://api.weixin.qq.com/wxa/game/queryorderinfo?access_token=ACCESS_TOKEN
//     &signature=SIGNATURE&sig_method=SIG_METHOD&pay_sig=PAY_SIG
//   - 查询参数：access_token / signature（用户登录态签名）/ sig_method（只支持
//     hmac_sha256，固定传 "hmac_sha256"）/ pay_sig（支付请求签名）
//   - 请求体（JSON）：openid / offer_id（支付应用 ID）/ ts（当前 Unix 时间戳，
//     单位秒）/ zone_id（已发布的分区 ID，需与 env 对应）/ env（0 现网 1 沙箱）/
//     out_trade_no（充值时传入的外部订单号）/ biz_id（1 代币 2 道具直购）
//   - 响应：errcode / errmsg / product_id / pay_state（1 未支付 2 已支付）/
//     deliver_state（1 未发货 2 已发货）/ pay_finish_time（支付完成时间）/
//     out_trade_no / mch_order_no（微信支付商户单号，仅微信支付方式存在）/
//     transaction_id（微信支付订单号，仅微信支付方式存在）
//   - 注意：响应**不含金额与币种字段**——PaymentResult.Amount/Currency 无法由
//     平台确认（见 VerifyPayment 注释）。
//
// 两个签名（均为小写十六进制 HMAC-SHA256，官方 Python 示例 hexdigest）：
//   - signature = hmac_sha256(session_key, post_body)
//     文档：https://developers.weixin.qq.com/minigame/dev/guide/open-ability/signature.html
//     与 https://developers.weixin.qq.com/minigame/dev/guide/open-ability/virtual-payment/signature.html
//     的 calc_signature 示例（2026-06-11 拉取）——key 是该用户当前有效的
//     session_key（来自 jscode2session），消息就是 POST 包体；
//   - pay_sig = hmac_sha256(app_key, uri + "&" + post_body)
//     文档：https://developers.weixin.qq.com/minigame/dev/guide/open-ability/virtual-payment/signature.html
//     （2026-06-11 拉取）——uri 为不带 query 的 API 路径（本接口即
//     /wxa/game/queryorderinfo），app_key 为当前支付环境（env）对应的 AppKey
//     （MP-支付基础配置；现网与沙箱不同，用错平台必拒——凭据种类/环境错配是
//     历史踩坑高发区）。
//
// 签名纪律：参与签名的 post_body 必须与真正发出的 HTTP 包体逐字节一致
// （官方注释原文），故本实现先 json.Marshal 出字节再分别用于签名与发送。
const queryOrderPath = "/wxa/game/queryorderinfo"

// sigMethodHMACSHA256 sig_method 固定取值（官方：只支持 hmac_sha256）。
const sigMethodHMACSHA256 = "hmac_sha256"

// 米大师订单状态枚举（响应 pay_state / deliver_state，文档见 queryOrderPath 注释）。
const (
	payStateUnpaid = 1 // 未支付
	payStatePaid   = 2 // 已支付
)

// queryOrderReq queryorderinfo 请求体（字段名与序列顺序以官方文档为准）。
type queryOrderReq struct {
	OpenID     string `json:"openid"`
	OfferID    string `json:"offer_id"`
	TS         int64  `json:"ts"`
	ZoneID     string `json:"zone_id"`
	Env        int    `json:"env"`
	OutTradeNo string `json:"out_trade_no"`
	BizID      int    `json:"biz_id"`
}

// queryOrderResp queryorderinfo 应答。
type queryOrderResp struct {
	ErrCode       int64  `json:"errcode"`
	ErrMsg        string `json:"errmsg"`
	ProductID     string `json:"product_id"`
	PayState      int    `json:"pay_state"`
	DeliverState  int    `json:"deliver_state"`
	PayFinishTime int64  `json:"pay_finish_time"`
	OutTradeNo    string `json:"out_trade_no"`
	MchOrderNo    string `json:"mch_order_no"`
	TransactionID string `json:"transaction_id"`
}

// VerifyPayment 实现 platform.PaymentProvider：调米大师「查询订单状态」，
// 以平台服务端应答的 pay_state 判定 Paid——绝不信任客户端上报。
//
// receipt 字段约定：
//   - OrderID（必填）：充值时传给 wx.requestMidasPayment 的外部订单号
//     （out_trade_no）；
//   - OpenID（必填）：付款用户 openid；
//   - Raw["session_key"]（可选）：该用户当前有效 session_key；缺省时经
//     Config.SessionKeyFunc(ctx, openID) 取回——两者都没有则报错（登录态
//     签名必需，见 queryOrderPath 注释）；
//   - Raw["biz_id"]（可选）："1" 代币 / "2" 道具直购；缺省用 Config.BizID。
//
// 结果映射：
//   - Paid          ← pay_state == 2（已支付）
//   - ProductID     ← product_id
//   - TransactionID ← transaction_id（缺省依次回退 mch_order_no、请求值）
//   - PaidAt        ← pay_finish_time（Unix 秒；官方示例 1669364790）
//   - Sandbox       ← 请求 env == 1（沙箱）
//   - Amount = 0、Currency = ""：**官方响应不含金额/币种字段**（响应字段表见
//     queryOrderPath 注释），平台无法确认实付金额——业务发货前必须按
//     product_id 对照后台商品配置核对价格，不能拿 Amount 当核对依据。
//   - Raw           ← pay_state / deliver_state / mch_order_no / transaction_id
//     / env / zone_id / biz_id 透传
//
// 防串单：receipt.Platform 非空时必须等于 "wechat"；应答 out_trade_no 与请求
// 不一致时直接报错。
func (w *WeChat) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"receipt.Platform 与本平台不符（防串单）: "+receipt.Platform)
	}
	if receipt.OpenID == "" {
		return nil, errs.New(PlatformName, opQueryOrder, "", "receipt.OpenID 为空（官方必填）")
	}
	if receipt.OrderID == "" {
		return nil, errs.New(PlatformName, opQueryOrder, "", "receipt.OrderID 为空（即 out_trade_no，充值时传入的外部订单号）")
	}
	if w.cfg.OfferID == "" {
		return nil, errs.New(PlatformName, opQueryOrder, "", "Config.OfferID 未配置（MP-支付基础配置的支付应用 ID）")
	}

	// biz_id：单笔覆盖优先，否则取配置。
	bizID := w.cfg.BizID
	if v, ok := receipt.Raw["biz_id"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, errs.New(PlatformName, opQueryOrder, "", "receipt.Raw[biz_id] 非法: "+v)
		}
		bizID = n
	}
	if bizID != BizIDCoin && bizID != BizIDGoods {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"biz_id 未配置或非法（官方枚举：1 代币 / 2 道具直购；设 Config.BizID 或传 receipt.Raw[biz_id]）")
	}

	// 支付环境对应的 AppKey（pay_sig 密钥；现网/沙箱不同，文档见 queryOrderPath 注释）。
	appKey := w.cfg.AppKey
	if w.cfg.Env == EnvSandbox {
		appKey = w.cfg.SandboxAppKey
	}
	if appKey == "" {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"当前支付环境（env="+strconv.Itoa(w.cfg.Env)+"）对应的 AppKey 未配置（MP-支付基础配置）")
	}

	// 用户登录态签名密钥 session_key：单笔传入优先，否则经钩子取回。
	sessionKey := receipt.Raw["session_key"]
	if sessionKey == "" {
		if w.cfg.SessionKeyFunc == nil {
			return nil, errs.New(PlatformName, opQueryOrder, "",
				"缺少 session_key（登录态签名必需）：传 receipt.Raw[session_key] 或配置 Config.SessionKeyFunc")
		}
		var err error
		sessionKey, err = w.cfg.SessionKeyFunc(ctx, receipt.OpenID)
		if err != nil {
			return nil, errs.Wrap(PlatformName, opQueryOrder, err)
		}
		if sessionKey == "" {
			return nil, errs.New(PlatformName, opQueryOrder, "",
				"Config.SessionKeyFunc 返回空 session_key（openid="+receipt.OpenID+"）")
		}
	}

	// 序列化请求体——同一份字节既用于两个签名也用于发送（逐字节一致，官方硬要求）。
	bodyBytes, err := json.Marshal(queryOrderReq{
		OpenID:     receipt.OpenID,
		OfferID:    w.cfg.OfferID,
		TS:         w.now().Unix(),
		ZoneID:     w.cfg.ZoneID,
		Env:        w.cfg.Env,
		OutTradeNo: receipt.OrderID,
		BizID:      bizID,
	})
	if err != nil {
		return nil, errs.Wrap(PlatformName, opQueryOrder, err)
	}

	token, err := w.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	query := url.Values{
		"access_token": {token},
		// signature = hmac_sha256(session_key, post_body)，小写 hex。
		"signature":  {sign.HMACSHA256Hex([]byte(sessionKey), bodyBytes)},
		"sig_method": {sigMethodHMACSHA256},
		// pay_sig = hmac_sha256(app_key, uri + "&" + post_body)，小写 hex；
		// uri 不带 query（官方示例「切记不可带参数」）。
		"pay_sig": {sign.HMACSHA256Hex([]byte(appKey), append([]byte(queryOrderPath+"&"), bodyBytes...))},
	}
	target, err := mergeQueryURL(httpx.JoinURL(w.cfg.BaseURL, queryOrderPath), query)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opQueryOrder, err)
	}

	resp, err := w.hc.PostJSON(ctx, target, json.RawMessage(bodyBytes), nil)
	if err != nil {
		// 查单是只读幂等接口，传输层失败可安全重试。
		return nil, errs.Wrap(PlatformName, opQueryOrder, err).WithRetryable(true)
	}
	var body queryOrderResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opQueryOrder, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.ErrCode != 0 {
		// 米大师专属错误码表官方页未提供（让查通用错误码，NEEDS-DOC 见 doc.go），
		// 按通用语义分类：-1 可重试、40001 重取 token 后可重试、其余确定性失败。
		return nil, w.platformErr(opQueryOrder, body.ErrCode, body.ErrMsg, resp.StatusCode)
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opQueryOrder, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 防串单：平台回的 out_trade_no 必须与请求一致（宁可失败不可错绑订单）。
	if body.OutTradeNo != "" && body.OutTradeNo != receipt.OrderID {
		return nil, errs.New(PlatformName, opQueryOrder, "",
			"应答 out_trade_no 与请求不一致（疑似串单）: "+body.OutTradeNo+" != "+receipt.OrderID)
	}

	transactionID := body.TransactionID
	if transactionID == "" {
		transactionID = body.MchOrderNo // 仅微信支付方式存在，按官方说明回退
	}
	if transactionID == "" {
		transactionID = receipt.TransactionID
	}
	result := &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       receipt.OrderID,
		TransactionID: transactionID,
		ProductID:     body.ProductID,
		// Amount/Currency：官方响应无金额/币种字段，无法由平台确认——业务按
		// product_id 对照后台商品配置核对（见方法注释）。
		Amount:   0,
		Currency: "",
		Paid:     body.PayState == payStatePaid,
		Sandbox:  w.cfg.Env == EnvSandbox,
		Raw: map[string]string{
			"pay_state":      strconv.Itoa(body.PayState),
			"deliver_state":  strconv.Itoa(body.DeliverState),
			"mch_order_no":   body.MchOrderNo,
			"transaction_id": body.TransactionID,
			"env":            strconv.Itoa(w.cfg.Env),
			"zone_id":        w.cfg.ZoneID,
			"biz_id":         strconv.Itoa(bizID),
		},
	}
	if body.PayFinishTime > 0 {
		result.PaidAt = time.Unix(body.PayFinishTime, 0)
	}
	return result, nil
}
