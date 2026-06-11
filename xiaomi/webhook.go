//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description xiaomi：WebhookVerifier——订单支付结果通知验签 + payTime 窗口 + 防重放去重
//2026/6/11
//***************************************************

package xiaomi

import (
	"errors"
	"net/http"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, xiaomi.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookMissingSignature 通知缺少 signature 参数。
	ErrWebhookMissingSignature = errors.New("xiaomi: 通知缺少 signature 参数")
	// ErrWebhookSignatureMismatch 签名比对失败（密钥不符或参数被篡改）。
	ErrWebhookSignatureMismatch = errors.New("xiaomi: webhook 签名比对失败")
	// ErrWebhookMalformedNotify 通知参数非法（payTime 缺失或格式不符）。
	ErrWebhookMalformedNotify = errors.New("xiaomi: webhook 通知参数非法")
	// ErrWebhookTimestampOutOfWindow 签名有效但 payTime 超出容忍窗口（过旧或超前）。
	ErrWebhookTimestampOutOfWindow = errors.New("xiaomi: webhook payTime 超出容忍窗口")
	// ErrWebhookReplayed 防重放拦截：同一签名在窗口内重复出现。
	ErrWebhookReplayed = errors.New("xiaomi: webhook 重复投递（防重放拦截）")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// VerifyWebhook 实现 platform.WebhookVerifier：校验小米「订单支付结果通知」
// 回调签名，并按合约硬要求完成时间窗口校验 + 重放去重。
//
// 协议
// 文档：《小米游戏SDK3.0接入指南》5.3.1 订单支付结果通知接口
// https://dev.mi.com/distribute/doc/details?pId=1616（2026-06-11 拉取）：
//   - 通知地址由开发者在小米开发者站预先配置（官方升级通知 pId=1559 要求 https）；
//   - 请求方法 GET，参数拼在 URL 上：appId / cpOrderId / cpUserInfo（可选）/
//     uid / orderId / orderStatus（TRADE_SUCCESS 代表成功）/ payFee（单位"分"）/
//     productCode / productName / productCount / payTime（yyyy-MM-dd HH:mm:ss）/
//     orderConsumeType（可选）/ partnerGiftConsume（可选，有值则参与签名）/ signature；
//   - signature = HMAC-SHA1(key=AppSecret, 待签名串)，待签名串按 5.3.5 规则构造
//     （排除 signature、排除空值、参数名字母序、k=v&k=v 拼接、值用 URL 解码后的
//     原值——Go 的 r.URL.Query() 已完成解码，直接可用）；
//   - 处理成功业务侧须应答 {"errcode":200}（应答由业务 handler 负责，本方法只验真）。
//
// 时间窗口
// 通知无独立投递时间戳，以参与签名的 payTime 字段做新鲜度校验（攻击者无法单独
// 篡改）。官方重试节奏是「前 10 次每分钟 1 次，10 次后每小时 1 次」且未给总时长
// 上限，合法重试可能滞后数小时——窗口默认 24h（DefaultWebhookTolerance），经
// Config.WebhookTolerance 调整。payTime 时区官方未注明，默认按北京时间解析
// （Config.PayTimeLocation 可覆盖，见 doc.go NEEDS-DOC）。
//
// 防重放
// 官方要求「对于同一个订单号的多次通知，开发商要自己保证只处理一次发货」
// （5.3.1，pId=1616）。通知无 nonce——以签名值本身作去重 key（签名对全参数集
// 唯一），窗口为 2×WebhookTolerance。注意：官方重试投递的参数与签名完全相同，
// 验签通过即入去重表——业务 handler 必须在首次验真后及时应答 {"errcode":200}
// 止住重试；幂等发货仍须业务侧按 cpOrderId/orderId 兜底（本方法只验真）。
// 单机默认内存去重；多实例部署必须经 Config.WebhookSeen 注入共享存储实现。
//
// Body：通知是 GET、参数全在 URL 上，本方法不读 r.Body（合约对 Body 重置的
// 要求仅约束"读了 Body"的实现，此处不适用）。
func (x *Xiaomi) VerifyWebhook(r *http.Request) error {
	query := r.URL.Query()
	sigHex := query.Get("signature")
	if sigHex == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 signature 参数").
			WithCause(ErrWebhookMissingSignature)
	}

	// Query() 已 URL 解码——正是官方 5.3.5 要求的「字符串原值」。
	// 同名多值参数取首个（官方协议各参数单值）。
	params := make(map[string]string, len(query))
	for k, vs := range query {
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}
	if !x.verifyParams(params, sigHex) {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名比对失败").
			WithCause(ErrWebhookSignatureMismatch)
	}

	// 时间窗口：payTime 是官方必须字段且参与签名；缺失/非法即协议异常。
	payTimeStr := params["payTime"]
	if payTimeStr == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 payTime 参数").
			WithCause(ErrWebhookMalformedNotify)
	}
	payTime, err := time.ParseInLocation(payTimeLayout, payTimeStr, x.cfg.PayTimeLocation)
	if err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"payTime 格式非法（应为 yyyy-MM-dd HH:mm:ss）: "+truncate(payTimeStr, 64)).
			WithCause(ErrWebhookMalformedNotify)
	}
	delta := x.now().Sub(payTime)
	if delta < 0 {
		delta = -delta
	}
	if delta > x.cfg.WebhookTolerance {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"payTime 超出容忍窗口 "+x.cfg.WebhookTolerance.String()+"（偏差 "+delta.String()+"）").
			WithCause(ErrWebhookTimestampOutOfWindow)
	}

	// 防重放去重——只对验签通过的请求记账（垃圾签名进不了去重表）。
	// 去重窗口取 2×容忍窗口：窗口边缘的合法请求过期出表后，其重放已被时间
	// 窗口拦截，两道闸无缝衔接。
	if x.seen(sigHex, 2*x.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "", "重复投递（防重放拦截）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}
