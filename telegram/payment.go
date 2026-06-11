//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description telegram：PaymentProvider——Telegram Stars（XTR）交易经 getStarTransactions 服务端核验
//2026/6/11
//***************************************************

package telegram

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opGetStarTransactions = "getStarTransactions"

// starsCurrency Telegram Stars 的货币代码。
// 文档：https://core.telegram.org/bots/payments-stars（2026-06-11 拉取）：
// “all transactions must be carried out in Telegram Stars, with currency tag XTR”。
const starsCurrency = "XTR"

// invoicePaymentType 商品/服务购买交易的 transaction_type。
// 文档：https://core.telegram.org/bots/api#transactionpartneruser（2026-06-11 拉取）：
// “transaction_type … currently one of ‘invoice_payment’ for payments via
// invoices, ‘paid_media_payment’ …, ‘gift_purchase’ …, ‘premium_purchase’ …,
// ‘business_account_transfer’ …”。游戏内购走 sendInvoice，对应 invoice_payment。
const invoicePaymentType = "invoice_payment"

// botAPIEnvelope 是 Bot API 统一应答封装。
// 文档：https://core.telegram.org/bots/api#making-requests（2026-06-11 拉取）：
// “always has a Boolean field 'ok' … If 'ok' equals True … the result of the
// query can be found in the 'result' field. In case of an unsuccessful request,
// 'ok' equals false and the error is explained in the 'description'.
// An Integer 'error_code' field is also returned”。
type botAPIEnvelope[T any] struct {
	OK          bool   `json:"ok"`
	Result      T      `json:"result"`
	Description string `json:"description"`
	ErrorCode   int    `json:"error_code"`
}

// starTransactions / starTransaction / transactionPartner 对应 Bot API 对象。
//
// 字段定义文档（2026-06-11 拉取）：
//   - https://core.telegram.org/bots/api#startransactions ：
//     {transactions: Array of StarTransaction}；
//   - https://core.telegram.org/bots/api#startransaction ：
//     id String——“Coincides with SuccessfulPayment.telegram_payment_charge_id
//     for successful incoming payments from users”，退款交易的 id 与原始交易一致；
//     amount Integer——“Integer amount of Telegram Stars transferred”（单位：
//     整数 Star，非最小分数单位）；nanostar_amount Integer Optional——
//     “1/1000000000 shares of Telegram Stars”（0-999999999）；
//     date Integer——Unix time；source 仅入账交易携带 / receiver 仅出账交易携带；
//   - https://core.telegram.org/bots/api#transactionpartneruser ：
//     type 恒为 "user"；transaction_type；user（含 id）；invoice_payload
//     Optional——“Bot-specified invoice payload. Can be available only for
//     ‘invoice_payment’ transactions”。
type starTransactions struct {
	Transactions []starTransaction `json:"transactions"`
}

type starTransaction struct {
	ID             string              `json:"id"`
	Amount         int64               `json:"amount"`
	NanostarAmount int64               `json:"nanostar_amount"`
	Date           int64               `json:"date"`
	Source         *transactionPartner `json:"source"`
	Receiver       *transactionPartner `json:"receiver"`
}

type transactionPartner struct {
	Type            string `json:"type"`
	TransactionType string `json:"transaction_type"`
	User            struct {
		ID int64 `json:"id"`
	} `json:"user"`
	InvoicePayload string `json:"invoice_payload"`
}

// getStarTransactionsReq 是 getStarTransactions 的请求体。
// 文档：https://core.telegram.org/bots/api#getstartransactions（2026-06-11 拉取）：
// offset Integer Optional——“Number of transactions to skip in the response”；
// limit Integer Optional——“Values between 1-100 are accepted. Defaults to 100”；
// 返回“the bot's Telegram Star transactions in chronological order”。
type getStarTransactionsReq struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// VerifyPayment 实现 platform.PaymentProvider。
//
// 核验依据是 Bot API getStarTransactions 的服务端应答（绝不信任客户端上报）：
// receipt.TransactionID 须传 SuccessfulPayment.telegram_payment_charge_id
// （官方支付流要求 bot 收到 successful_payment 时存档该 id，文档：
// https://core.telegram.org/bots/payments-stars#implementing-payments ，
// 2026-06-11 拉取），本方法按时间序翻页扫描 bot 的 Star 交易流水，定位
// id == TransactionID 的入账交易（StarTransaction.id 与
// telegram_payment_charge_id 一致，见 starTransaction 注释的官方原文）。
//
// 判定规则：
//   - 找到入账交易（source.type == "user" 且 transaction_type ==
//     "invoice_payment"）→ Paid=true；
//   - 同 id 还存在出账退款交易（receiver.type == "user"；官方：退款交易 id 与
//     原始交易一致）→ Paid=false 且 Raw["refunded"]="true"——已退款的单据
//     严禁发货；
//   - 扫描达上限（Config.PaymentScanMaxPages）仍未找到 → 错误码
//     transaction_not_found。
//
// 金额与货币：Amount 直接取 StarTransaction.amount，单位为**整数 Star**
// （官方定义“Integer amount of Telegram Stars”；Stars 没有更小的展示单位，
// sendInvoice 的 XTR 价格本身就以整数 Star 计），Currency 恒为 "XTR"；
// nanostar_amount（十亿分之一 Star 的份额）原样透传 Raw，不并入 Amount。
// 业务核对 receipt.Amount 时请按"1 Star = 1 最小单位"理解。
//
// 防串单核对（实现内强校验，不一致宁可失败）：
//   - receipt.Platform 非空时必须等于 "telegram"；
//   - receipt.OpenID 非空时必须等于交易付款人 user.id；
//   - receipt.ProductID / OrderID：Telegram 无平台侧商品 id，invoice_payload
//     是 bot 自定义透传（业务通常把订单号/商品号编码在内）——本方法把它原样
//     放进 Raw["invoice_payload"]，由业务自行核对，不在此猜测其编码格式。
//
// 已知局限（官方 API 形态所致，非实现缩水）：getStarTransactions 仅支持
// offset/limit 顺序翻页、无按 id 查单接口，高流水 bot 翻页成本高——建议以
// webhook successful_payment 落库为主、本方法作发货前二次确认/对账兜底，
// 并按流水量调大 Config.PaymentScanMaxPages。
func (t *Telegram) VerifyPayment(ctx context.Context, receipt platform.PaymentReceipt) (*platform.PaymentResult, error) {
	if receipt.Platform != "" && receipt.Platform != PlatformName {
		return nil, errs.New(PlatformName, opGetStarTransactions, "",
			"receipt.Platform 串单: "+receipt.Platform+" != "+PlatformName)
	}
	if receipt.TransactionID == "" {
		return nil, errs.New(PlatformName, opGetStarTransactions, "",
			"receipt.TransactionID（telegram_payment_charge_id）为空")
	}

	var (
		paidTx   *starTransaction // 命中的入账交易
		refunded bool             // 同 id 是否存在出账退款
	)
	pageSize := t.cfg.PaymentScanPageSize
scan:
	for page := 0; page < t.cfg.PaymentScanMaxPages; page++ {
		txs, err := t.fetchStarTransactions(ctx, page*pageSize, pageSize)
		if err != nil {
			return nil, err
		}
		for i := range txs {
			tx := &txs[i]
			if tx.ID != receipt.TransactionID {
				continue
			}
			if tx.Source != nil {
				paidTx = tx
			}
			if tx.Receiver != nil && tx.Receiver.Type == "user" {
				// 官方：退款交易的 id 与原始交易一致、receiver 为用户（出账）。
				refunded = true
			}
		}
		if len(txs) < pageSize {
			break scan // 最后一页（不足整页 = 流水尽头）
		}
	}

	if paidTx == nil {
		return nil, errs.New(PlatformName, opGetStarTransactions, "transaction_not_found",
			"未在最近 "+strconv.Itoa(t.cfg.PaymentScanMaxPages*pageSize)+" 笔流水中找到交易 "+
				receipt.TransactionID+"（charge_id 错误，或流水过深——可调大 PaymentScanMaxPages）")
	}

	// 入账方核验：必须是用户经 invoice 的付款（货不对板/类型不符宁可失败）。
	src := paidTx.Source
	if src.Type != "user" {
		return nil, errs.New(PlatformName, opGetStarTransactions, "",
			"交易入账方不是用户（source.type="+src.Type+"），非内购交易")
	}
	if src.TransactionType != invoicePaymentType {
		return nil, errs.New(PlatformName, opGetStarTransactions, "",
			"交易类型不是 invoice_payment（transaction_type="+src.TransactionType+"），非商品购买")
	}
	payerID := strconv.FormatInt(src.User.ID, 10)
	if receipt.OpenID != "" && receipt.OpenID != payerID {
		return nil, errs.New(PlatformName, opGetStarTransactions, "",
			"付款人不匹配（疑似串单）: 交易付款人 "+payerID+" != receipt.OpenID "+receipt.OpenID)
	}

	return &platform.PaymentResult{
		Platform:      PlatformName,
		OrderID:       receipt.OrderID,
		TransactionID: paidTx.ID,
		Amount:        paidTx.Amount, // 单位：整数 Star（见方法注释的单位说明）
		Currency:      starsCurrency,
		Paid:          !refunded,
		Sandbox:       t.cfg.TestEnvironment,
		PaidAt:        time.Unix(paidTx.Date, 0),
		Raw: map[string]string{
			"telegram_payment_charge_id": paidTx.ID,
			"payer_user_id":              payerID,
			"invoice_payload":            src.InvoicePayload,
			"nanostar_amount":            strconv.FormatInt(paidTx.NanostarAmount, 10),
			"refunded":                   strconv.FormatBool(refunded),
		},
	}, nil
}

// fetchStarTransactions 调一页 getStarTransactions（endpoint 协议见
// getStarTransactionsReq / botAPIEnvelope 注释）。
func (t *Telegram) fetchStarTransactions(ctx context.Context, offset, limit int) ([]starTransaction, error) {
	resp, err := t.hc.PostJSON(ctx, t.botAPIURL(opGetStarTransactions),
		getStarTransactionsReq{Offset: offset, Limit: limit}, nil)
	if err != nil {
		// 传输层失败（网络错误/超时）——只读查询，可安全重试。
		return nil, errs.Wrap(PlatformName, opGetStarTransactions, err).WithRetryable(true)
	}
	var body botAPIEnvelope[starTransactions]
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opGetStarTransactions, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !body.OK {
		return nil, errs.New(PlatformName, opGetStarTransactions,
			strconv.Itoa(body.ErrorCode), body.Description).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		// ok=true 却非 2xx——按官方封装不该发生，视为协议异常。
		return nil, errs.New(PlatformName, opGetStarTransactions, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	return body.Result.Transactions, nil
}

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 其余 4xx 是确定性失败（参数/凭据错误），重试无意义。
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}
