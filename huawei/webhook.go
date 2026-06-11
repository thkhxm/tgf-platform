//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：WebhookVerifier——IAP 关键事件通知 v2 校验（结构 + 时间戳窗口 + 防重放 + 订阅事件验签）
//2026/6/11
//***************************************************

package huawei

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, huawei.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookMalformedBody 回调体不是合法 JSON 或缺少必要字段。
	ErrWebhookMalformedBody = errors.New("huawei: webhook 回调体格式非法")
	// ErrWebhookUnsupportedVersion 通知版本不是 v2（AGC 后台通知版本需配置为 v2）。
	ErrWebhookUnsupportedVersion = errors.New("huawei: webhook 通知版本不支持（仅支持 v2）")
	// ErrWebhookAppMismatch applicationId 与本应用 ClientID（App ID）不一致。
	ErrWebhookAppMismatch = errors.New("huawei: webhook applicationId 与本应用不一致")
	// ErrWebhookTimestampOutOfWindow notifyTime 超出容忍窗口（过旧或超前）。
	ErrWebhookTimestampOutOfWindow = errors.New("huawei: webhook 时间戳超出容忍窗口")
	// ErrWebhookSignatureMismatch 订阅事件签名比对失败（公钥不符或 payload 被篡改）。
	ErrWebhookSignatureMismatch = errors.New("huawei: webhook 签名比对失败")
	// ErrWebhookReplayed 防重放拦截：同一通知在窗口内重复出现。
	// 注意华为投递语义是 at-least-once（官方："可能出现重发的通知比预期的多"），
	// 业务对已处理过的事件可 errors.Is 本错误后按"已处理"返回 HTTP 200，
	// 避免平台无限重发。
	ErrWebhookReplayed = errors.New("huawei: webhook 重复投递（防重放拦截）")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// webhookNotification 是关键事件通知 v2 的顶层结构。
// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/api-notifications-about-subscription-events-v2-0000001385268541
// （2026-06-11 拉取）：
//   - version="v2"；eventType="ORDER"|"SUBSCRIPTION"；notifyTime=UTC 毫秒；
//     applicationId=应用 ID；
//   - orderNotification（eventType=ORDER）：{version, notificationType(1=支付成功
//     2=退款成功), purchaseToken, productId}——官方字段表中【没有】签名字段；
//   - subNotification（eventType=SUBSCRIPTION）：{version, statusUpdateNotification
//     (JSON 字符串), notificationSignature(对 statusUpdateNotification 的签名),
//     signatureAlgorithm}。
type webhookNotification struct {
	Version       string    `json:"version"`
	EventType     string    `json:"eventType"`
	NotifyTime    flexInt64 `json:"notifyTime"`
	ApplicationID string    `json:"applicationId"`

	OrderNotification *struct {
		Version          string `json:"version"`
		NotificationType int    `json:"notificationType"`
		PurchaseToken    string `json:"purchaseToken"`
		ProductID        string `json:"productId"`
	} `json:"orderNotification"`

	SubNotification *struct {
		Version                  string `json:"version"`
		StatusUpdateNotification string `json:"statusUpdateNotification"`
		NotificationSignature    string `json:"notificationSignature"`
		SignatureAlgorithm       string `json:"signatureAlgorithm"`
	} `json:"subNotification"`
}

// VerifyWebhook 实现 platform.WebhookVerifier：校验华为 IAP「关键事件通知 v2」
// 回调，并按合约硬要求完成时间戳窗口校验 + 重放去重；读过的 Body 在返回前重置，
// 业务 handler 可正常再读。
//
// 校验链（协议细节见 webhookNotification 注释的文档引用）：
//
//  1. 结构：version 必须为 "v2"；eventType 必须为 ORDER / SUBSCRIPTION 且携带
//     对应通知体；applicationId 与本应用 ClientID（App ID）一致（防串单）；
//  2. 时间戳：notifyTime（UTC 毫秒）与本地时钟偏差超出 Config.WebhookTolerance
//     即拒绝；
//  3. 验签：
//     - SUBSCRIPTION：用 IAP 公钥对 statusUpdateNotification 的 JSON 字符串
//     （原样字节，绝不可反序列化再序列化）按 signatureAlgorithm 验签
//     （Config.IAPPublicKey 必须已配置）；
//     - ORDER：官方字段表【未定义】签名字段，无签可验——本方法只完成结构 /
//     时间戳 / 防重放校验。其真实性须由业务拿通知里的 purchaseToken 调
//     VerifyPayment 以华为服务端应答为准核实后再发货（官方设计的安全闭环：
//     通知只是触发器，事实源是验证购买 Token 接口）；
//  4. 防重放：SUBSCRIPTION 以 notificationSignature 为去重 key（签名对内容唯一）；
//     ORDER 无签名/无流水号，以整个回调体的 SHA-256 为去重 key。窗口为
//     2×WebhookTolerance（与时间戳窗口两道闸无缝衔接）。单机默认内存去重；
//     多实例部署必须经 Config.WebhookSeen 注入共享存储实现。
//
// 响应语义提示（官方）：验证通过且业务受理后应返回 HTTP 200（无需响应体）；
// 非 200 会触发平台周期性重发。
func (h *Huawei) VerifyWebhook(r *http.Request) error {
	raw, err := readAndRestoreBody(r, h.cfg.WebhookMaxBodySize)
	if err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err)
	}
	if len(raw) == 0 {
		return errs.New(PlatformName, opVerifyWebhook, "", "回调体为空").
			WithCause(ErrWebhookMalformedBody)
	}

	var n webhookNotification
	if err := httpx.DecodeJSON(raw, &n); err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "", "回调体解析失败").
			WithCause(errors.Join(ErrWebhookMalformedBody, err))
	}
	if n.Version != "v2" {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"通知版本不支持: "+truncate(n.Version, 16)+"（本实现仅支持 v2，请在 AGC 配置通知版本 v2）").
			WithCause(ErrWebhookUnsupportedVersion)
	}
	// 防串单：applicationId 即应用 ID（= Config.ClientID）。
	if n.ApplicationID != "" && n.ApplicationID != h.cfg.ClientID {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"applicationId 不一致: "+truncate(n.ApplicationID, 64)).
			WithCause(ErrWebhookAppMismatch)
	}

	// 时间戳窗口（notifyTime 为 UTC 毫秒）。
	if n.NotifyTime <= 0 {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 notifyTime 字段").
			WithCause(ErrWebhookMalformedBody)
	}
	delta := h.now().UnixMilli() - int64(n.NotifyTime)
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Millisecond > h.cfg.WebhookTolerance {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"notifyTime 超出容忍窗口 "+h.cfg.WebhookTolerance.String()+
				"（偏差 "+strconv.FormatInt(delta, 10)+"ms）").
			WithCause(ErrWebhookTimestampOutOfWindow)
	}

	var dedupeKey string
	switch n.EventType {
	case "SUBSCRIPTION":
		sub := n.SubNotification
		if sub == nil || sub.StatusUpdateNotification == "" || sub.NotificationSignature == "" {
			return errs.New(PlatformName, opVerifyWebhook, "",
				"SUBSCRIPTION 通知缺少 subNotification / statusUpdateNotification / notificationSignature").
				WithCause(ErrWebhookMalformedBody)
		}
		if h.iapPublicKey == nil {
			return errs.New(PlatformName, opVerifyWebhook, "",
				"Config.IAPPublicKey 未配置，无法对订阅事件通知验签")
		}
		// 验签原文 = statusUpdateNotification 的 JSON 字符串原样字节。
		if err := h.verifyIAPSignature([]byte(sub.StatusUpdateNotification),
			sub.NotificationSignature, sub.SignatureAlgorithm); err != nil {
			return errs.New(PlatformName, opVerifyWebhook, "", "订阅事件通知验签失败").
				WithCause(errors.Join(ErrWebhookSignatureMismatch, err))
		}
		dedupeKey = "sub:" + sub.NotificationSignature
	case "ORDER":
		ord := n.OrderNotification
		if ord == nil || ord.PurchaseToken == "" || ord.ProductID == "" {
			return errs.New(PlatformName, opVerifyWebhook, "",
				"ORDER 通知缺少 orderNotification / purchaseToken / productId").
				WithCause(ErrWebhookMalformedBody)
		}
		// ORDER 通知官方未定义签名字段（见方法注释第 3 条）——去重 key 用整个
		// 回调体哈希。
		sum := sha256.Sum256(raw)
		dedupeKey = "order:" + hex.EncodeToString(sum[:])
	default:
		return errs.New(PlatformName, opVerifyWebhook, "",
			"未知 eventType: "+truncate(n.EventType, 32)).
			WithCause(ErrWebhookMalformedBody)
	}

	// 防重放去重——只对校验通过的请求记账（垃圾请求进不了去重表）。
	// 去重窗口取 2×容忍窗口：窗口边缘的合法请求过期出表后，其重放已被时间戳
	// 窗口拦截，两道闸无缝衔接。
	if h.seen(dedupeKey, 2*h.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "", "重复投递（防重放拦截）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}

// readAndRestoreBody 全量读取请求 body（上限 maxSize 字节）并重置 r.Body
// （合约硬要求：实现读了 Body 必须在返回前重置，否则业务 handler 读不到）。
// body 为 nil 时按空 payload 处理（同样重置，保证 handler 侧行为一致）。
func readAndRestoreBody(r *http.Request, maxSize int64) ([]byte, error) {
	if r.Body == nil {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return nil, nil
	}
	// 多读 1 字节用于精确判定"恰好超限"。
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxSize+1))
	_ = r.Body.Close()
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if int64(len(raw)) > maxSize {
		return nil, errors.New("回调体超过上限 " + strconv.FormatInt(maxSize, 10) + " 字节")
	}
	return raw, nil
}
