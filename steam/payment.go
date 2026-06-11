//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description steam：PaymentProvider——QueryTxn 查单判定发货 + FinalizeTxn 资金捕获
//2026/6/11
//***************************************************

package steam

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

// 操作名（errs.Error.Op），按平台 API 名命名。
const (
	opQueryTxn    = "query_txn"
	opFinalizeTxn = "finalize_txn"
)

// 微交易接口路径（接口名按 Config.Sandbox 在 ISteamMicroTxn / ISteamMicroTxnSandbox
// 间切换，两者协议完全一致，见 steam.go microTxnInterface 注释）。
//
// queryTxnPath 订单状态查询。
//
// 文档：https://partner.steamgames.com/doc/webapi/ISteamMicroTxn（2026-06-11 拉取）
//   - GET https://partner.steam-api.com/ISteamMicroTxn/QueryTxn/v3/
//   - 请求参数（query）：
//     key      带 Microtransaction 权限的 publisher key（必填）
//     appid    游戏 AppID（必填）
//     orderid  业务侧 64-bit 订单号（可选）
//     transid  Steam 侧 64-bit 交易号（可选；与 orderid 至少给一个）
//   - 应答 response：
//     result   "OK" / "Failure"
//     params.orderid / transid / steamid（64 位，JSON 字符串形态）
//     params.status    订单状态，取值见 steam.go Status* 常量（官方附录 A）
//     params.currency  ISO 4217 货币码
//     params.time      交易时间，RFC 3339 UTC（如 2010-01-01T00:00:00Z）
//     params.country   ISO 3166-1-alpha-2 国家码
//     params.usstate   美国州 / 部分国家的省州
//     params.items[]   itemid / qty / amount / vat / itemstatus
//     —— amount 是"用户支付总额减去 VAT"（单位 cents，官方注 199 = 1.99），
//     vat 是税额（cents）；用户实付 = amount + vat
//     error.errorcode / errordesc（仅 result=Failure 时返回，码表见官方附录 B）
//   - v3 变更：新增疑似欺诈 / 友好欺诈状态（官方 change history）
//
// finalizeTxnPath 资金捕获（完成购买）。
//
// 文档：同上（2026-06-11 拉取）
//   - POST https://partner.steam-api.com/ISteamMicroTxn/FinalizeTxn/v2/
//   - 请求参数（form，Content-Type: application/x-www-form-urlencoded——
//     官方 Web API 总则要求，https://partner.steamgames.com/doc/webapi_overview ，
//     2026-06-11 拉取）：key / orderid / appid
//   - 应答 response：result；params.orderid / transid；error.errorcode / errordesc
//   - 语义（官方正文）：只能在用户授权成功后调用；成功应答即资金已捕获、可安全
//     发货；超时或通信异常时**不要盲目重发**，应改用 QueryTxn / GetReport 查状态
const (
	queryTxnPath    = "/QueryTxn/v3/"
	finalizeTxnPath = "/FinalizeTxn/v2/"
)

// queryTxnItem 是 QueryTxn 应答中的购物车明细项。
// 字段名与数字形态以官方正文为准（itemid/qty/amount/vat 在官方 GetReport v5 JSON
// 示例中是 JSON 数字；弹性类型同时容忍字符串形态，见 json.go）。
type queryTxnItem struct {
	ItemID     flexInt64 `json:"itemid"`
	Qty        flexInt64 `json:"qty"`
	Amount     flexInt64 `json:"amount"`
	Vat        flexInt64 `json:"vat"`
	ItemStatus string    `json:"itemstatus"`
}

// queryTxnResp 是 QueryTxn 的应答（字段见 queryTxnPath 注释）。
type queryTxnResp struct {
	Response struct {
		Result string `json:"result"`
		Params struct {
			OrderID  flexString     `json:"orderid"`
			TransID  flexString     `json:"transid"`
			SteamID  flexString     `json:"steamid"`
			Status   string         `json:"status"`
			Currency string         `json:"currency"`
			Time     string         `json:"time"`
			Country  string         `json:"country"`
			USState  string         `json:"usstate"`
			Items    []queryTxnItem `json:"items"`
		} `json:"params"`
		Error *webAPIError `json:"error"`
	} `json:"response"`
}

// VerifyPayment 实现 platform.PaymentProvider。
//
// 以 ISteamMicroTxn/QueryTxn/v3 的服务端应答为准判定支付状态——绝不信任客户端
// 上报。receipt 字段映射（与 platform.PaymentReceipt 的 Steam 语义对齐）：
//
//   - OrderID       → 请求参数 orderid（业务侧下单时传给 InitTxn 的 64-bit 订单号）
//   - TransactionID → 请求参数 transid（Steam 侧交易号）；与 OrderID 至少一个非空
//   - OpenID        非空时与应答 params.steamid 核对（防串单，不一致即失败）
//   - Platform      非空时必须等于 "steam"（防止业务把别家凭据塞错实现）
//
// 结果映射：
//
//   - Paid     ← status == StatusSucceeded（唯一允许发货的状态。注意 StatusApproved
//     只是用户已授权、资金尚未捕获——需先调 FinalizeTxn；StatusPartialRefund 整单
//     判 Paid=false，业务需按 Raw["items"] 的 itemstatus 自行细化增量回收）
//   - Amount   ← Σ(items.amount + items.vat)，即用户实付总额，单位 cents（最小货币
//     单位，与合约 Amount 单位一致；官方明确 amount 不含 VAT、vat 单独给出）
//   - Currency ← params.currency（ISO 4217）
//   - PaidAt   ← params.time（RFC 3339 UTC；为空跳过，非空但解析失败按协议异常报错）
//   - ProductID ← items[0].itemid（多商品购物车时取首项；全部明细以 JSON 透传
//     Raw["items"]，业务核对"货不对板"时遍历明细）
//   - Sandbox  ← Config.Sandbox（走 ISteamMicroTxnSandbox 即沙箱单）
//   - Raw      ← status / steamid / country / usstate / time / amount_ex_vat / vat /
//     items（明细 JSON）等透传
//
// 退款/拒付回收：status 落在逆转状态集（IsReversedStatus）时本方法同样返回
// Paid=false，业务应据 Raw["status"] 执行商品回收（官方实现指南要求，见
// IsReversedStatus 注释）。
func (s *Steam) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opQueryTxn, "",
			"receipt.Platform 不匹配（防串单）: "+receipt.Platform+" != "+PlatformName)
	}
	if receipt.OrderID == "" && receipt.TransactionID == "" {
		return nil, errs.New(PlatformName, opQueryTxn, "",
			"receipt.OrderID 与 receipt.TransactionID 至少需要一个（QueryTxn 按 orderid 或 transid 查单）")
	}

	query := url.Values{
		"key":   {s.cfg.WebAPIKey},
		"appid": {strconv.FormatUint(uint64(s.cfg.AppID), 10)},
	}
	if receipt.OrderID != "" {
		query.Set("orderid", receipt.OrderID)
	}
	if receipt.TransactionID != "" {
		query.Set("transid", receipt.TransactionID)
	}

	resp, err := s.hc.Get(ctx, httpx.JoinURL(s.cfg.BaseURL, "/"+s.microTxnInterface()+queryTxnPath), query, nil)
	if err != nil {
		// 传输层失败——QueryTxn 是只读查询，幂等可重试。
		return nil, errs.Wrap(PlatformName, opQueryTxn, err).WithRetryable(true)
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opQueryTxn, strconv.Itoa(resp.StatusCode),
			httpStatusHint(resp.StatusCode)+": "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	var body queryTxnResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opQueryTxn, err).
			WithHTTPStatus(resp.StatusCode)
	}
	if !strings.EqualFold(body.Response.Result, "OK") {
		code, msg := "", "平台返回非 OK 结果"
		if e := body.Response.Error; e != nil {
			code, msg = string(e.ErrorCode), e.ErrorDesc
		}
		return nil, errs.New(PlatformName, opQueryTxn, code, msg).
			WithHTTPStatus(resp.StatusCode)
	}

	p := body.Response.Params
	if p.Status == "" {
		// result=OK 却缺 status——按官方文档不该发生，视为协议异常，宁可失败不可误发货。
		return nil, errs.New(PlatformName, opQueryTxn, "",
			"应答缺少 status 字段: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}
	// 防串单：业务给了付款用户的 SteamID 时必须与平台应答一致。
	if receipt.OpenID != "" && string(p.SteamID) != "" && receipt.OpenID != string(p.SteamID) {
		return nil, errs.New(PlatformName, opQueryTxn, "",
			"应答 steamid 与 receipt.OpenID 不一致（疑似串单）: "+string(p.SteamID)+" != "+receipt.OpenID)
	}

	// 金额合计：用户实付 = Σ(amount + vat)，单位 cents（官方语义见 queryTxnPath 注释）。
	var amountExVat, vat int64
	for _, it := range p.Items {
		amountExVat += int64(it.Amount)
		vat += int64(it.Vat)
	}

	// 支付时间：RFC 3339 UTC（官方明确格式）；为空跳过，非空解析失败即协议异常。
	var paidAt time.Time
	if p.Time != "" {
		paidAt, err = time.Parse(time.RFC3339, p.Time)
		if err != nil {
			return nil, errs.New(PlatformName, opQueryTxn, "",
				"应答 time 字段不是 RFC 3339 格式: "+p.Time).WithCause(err)
		}
	}

	orderID := string(p.OrderID)
	if orderID == "" {
		orderID = receipt.OrderID
	}
	productID := ""
	if len(p.Items) > 0 {
		productID = strconv.FormatInt(int64(p.Items[0].ItemID), 10)
	}
	itemsJSON, _ := json.Marshal(p.Items)

	return &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       orderID,
		TransactionID: string(p.TransID),
		ProductID:     productID,
		Amount:        amountExVat + vat,
		Currency:      p.Currency,
		Paid:          p.Status == StatusSucceeded,
		Sandbox:       s.cfg.Sandbox,
		PaidAt:        paidAt,
		Raw: map[string]string{
			"status":        p.Status,
			"steamid":       string(p.SteamID),
			"country":       p.Country,
			"usstate":       p.USState,
			"time":          p.Time,
			"amount_ex_vat": strconv.FormatInt(amountExVat, 10),
			"vat":           strconv.FormatInt(vat, 10),
			"items":         string(itemsJSON),
		},
	}, nil
}

// FinalizeTxnResult 是 FinalizeTxn 的结果。
type FinalizeTxnResult struct {
	// OrderID 业务侧 64-bit 订单号（平台应答回传）。
	OrderID string
	// TransactionID Steam 侧 64-bit 交易号。
	TransactionID string
}

// FinalizeTxn 完成购买（资金捕获）——Steam 微交易闭环的专有补充方法（不属
// platform 合约）：InitTxn 下单 → 用户授权（QueryTxn 见 StatusApproved）→
// 本方法捕获资金 → StatusSucceeded → 发货。
//
// 官方语义（见 finalizeTxnPath 注释，2026-06-11 拉取）：
//   - 只能在用户授权成功后调用；
//   - 成功应答 = 资金已捕获，可安全发货；
//   - 超时/通信异常时不要盲目重发——改用 VerifyPayment（QueryTxn）查最终状态
//     （本实现对传输层失败标记 Retryable=false，正是为了阻止上层自动重试）。
func (s *Steam) FinalizeTxn(ctx context.Context, orderID string) (*FinalizeTxnResult, error) {
	if orderID == "" {
		return nil, errs.New(PlatformName, opFinalizeTxn, "", "orderID 为空")
	}

	form := url.Values{
		"key":     {s.cfg.WebAPIKey},
		"orderid": {orderID},
		"appid":   {strconv.FormatUint(uint64(s.cfg.AppID), 10)},
	}
	resp, err := s.hc.PostForm(ctx, httpx.JoinURL(s.cfg.BaseURL, "/"+s.microTxnInterface()+finalizeTxnPath), form, nil)
	if err != nil {
		// 资金捕获遇通信异常：官方要求改查状态而非重发——不标记可重试。
		return nil, errs.Wrap(PlatformName, opFinalizeTxn, err)
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opFinalizeTxn, strconv.Itoa(resp.StatusCode),
			httpStatusHint(resp.StatusCode)+": "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}

	var body struct {
		Response struct {
			Result string `json:"result"`
			Params struct {
				OrderID flexString `json:"orderid"`
				TransID flexString `json:"transid"`
			} `json:"params"`
			Error *webAPIError `json:"error"`
		} `json:"response"`
	}
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opFinalizeTxn, err).
			WithHTTPStatus(resp.StatusCode)
	}
	if !strings.EqualFold(body.Response.Result, "OK") {
		code, msg := "", "平台返回非 OK 结果"
		if e := body.Response.Error; e != nil {
			code, msg = string(e.ErrorCode), e.ErrorDesc
		}
		return nil, errs.New(PlatformName, opFinalizeTxn, code, msg).
			WithHTTPStatus(resp.StatusCode)
	}

	out := &FinalizeTxnResult{
		OrderID:       string(body.Response.Params.OrderID),
		TransactionID: string(body.Response.Params.TransID),
	}
	if out.OrderID == "" {
		out.OrderID = orderID
	}
	return out, nil
}
