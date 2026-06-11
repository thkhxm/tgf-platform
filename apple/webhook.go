//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：WebhookVerifier——App Store Server Notifications V2 验签 + 时间戳窗口 + 防重放
//2026/6/11
//***************************************************

package apple

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, apple.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookMissingPayload 回调体缺少 signedPayload 字段或不是合法 JSON。
	ErrWebhookMissingPayload = errors.New("apple: 回调体缺少 signedPayload")
	// ErrWebhookInvalidJWS signedPayload 验签失败（证书链非法或 payload 被篡改）。
	ErrWebhookInvalidJWS = errors.New("apple: signedPayload JWS 验签失败")
	// ErrWebhookTimestampOutOfWindow 签名有效但 signedDate 超出容忍窗口（过旧或超前）。
	ErrWebhookTimestampOutOfWindow = errors.New("apple: webhook signedDate 超出容忍窗口")
	// ErrWebhookReplayed 防重放拦截：同一 notificationUUID 在窗口内重复出现。
	ErrWebhookReplayed = errors.New("apple: webhook 重复投递（防重放拦截）")
	// ErrWebhookBundleMismatch 通知的 bundleId 与配置不符（不是发给本应用的通知）。
	ErrWebhookBundleMismatch = errors.New("apple: webhook bundleId 与配置不符")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// webhookBody 是 App Store Server Notifications V2 的回调体。
// 文档：https://developer.apple.com/documentation/appstoreservernotifications/responsebodyv2
// （2026-06-11 拉取）：POST body 为 {"signedPayload": "<JWS>"}，JWS 由 App Store 签名。
type webhookBody struct {
	SignedPayload string `json:"signedPayload"`
}

// notificationPayload 是 signedPayload 验签后的解码载荷（取校验所需字段）。
//
// 文档：https://developer.apple.com/documentation/appstoreservernotifications/responsebodyv2decodedpayload
// （2026-06-11 拉取）：
//   - notificationUUID："A unique identifier for the notification. Use this
//     value to identify a duplicate notification."——防重放去重 key 的官方依据；
//   - signedDate：App Store 签名该 JWS 的 UNIX 毫秒时间——时间戳窗口校验依据；
//   - data/summary/externalPurchaseToken/appData 四选一互斥；data 内含 bundleId
//     与 environment（文档：https://developer.apple.com/documentation/appstoreservernotifications/data ，
//     2026-06-11 拉取）。
type notificationPayload struct {
	NotificationType string `json:"notificationType"`
	Subtype          string `json:"subtype"`
	NotificationUUID string `json:"notificationUUID"`
	Version          string `json:"version"`
	SignedDate       int64  `json:"signedDate"`
	Data             struct {
		BundleID    string `json:"bundleId"`
		Environment string `json:"environment"`
	} `json:"data"`
	AppData struct {
		BundleID string `json:"bundleId"`
	} `json:"appData"`
}

// VerifyWebhook 实现 platform.WebhookVerifier：校验 App Store Server
// Notifications V2 回调，并按合约硬要求完成时间戳窗口校验 + 重放去重；
// 读过的 Body 在返回前重置，业务 handler 可正常再读。
//
// 校验链（协议来源见 webhookBody / notificationPayload / jws.go 注释）：
//
//  1. 解析 body JSON 取 signedPayload；
//  2. x5c 证书链验签（ES256，锚定 Apple Root CA - G3，含 Apple 专属扩展 OID
//     检查——与交易验签共用 verifyAppleJWS）；
//  3. signedDate（UNIX 毫秒）时间戳窗口校验：偏差超 WebhookTolerance 拒绝；
//  4. bundleId 核对（data.bundleId / appData.bundleId 非空且配置了 BundleID 时）：
//     不是发给本应用的通知拒绝——对照 Apple 官方库 app-store-server-library-node
//     的 INVALID_APP_IDENTIFIER 校验（2026-06-11 拉取）；
//  5. 防重放去重：以 notificationUUID 为 key（官方明示用它识别重复投递），
//     窗口 2×WebhookTolerance——窗口边缘的合法通知过期出表后，其重放已被
//     时间戳窗口拦截，两道闸无缝衔接。
//
// 注意：本方法只完成「请求确实来自 App Store 且非重放」的校验。业务发货/撤销
// 前还须解析 signedPayload 内层的 signedTransactionInfo（可复用
// VerifyPayment 走服务端查询）并做幂等处理。
func (a *Apple) VerifyWebhook(r *http.Request) error {
	// 读原始 body（限量防打爆内存），并立即重置回去（合约硬要求：实现读了
	// Body 必须在返回前重置，否则业务 handler 读不到）。
	raw, err := readAndRestoreBody(r, a.cfg.WebhookMaxBodySize)
	if err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err)
	}
	var body webhookBody
	if err := httpx.DecodeJSON(raw, &body); err != nil || body.SignedPayload == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "回调体缺少 signedPayload 或不是合法 JSON").
			WithCause(ErrWebhookMissingPayload)
	}

	// —— JWS 验签（x5c 链 + ES256，见 jws.go） ——
	payloadRaw, err := a.verifyAppleJWS(body.SignedPayload)
	if err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "", "signedPayload 验签失败: "+err.Error()).
			WithCause(ErrWebhookInvalidJWS)
	}
	var notif notificationPayload
	if err := httpx.DecodeJSON(payloadRaw, &notif); err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err).WithCause(ErrWebhookInvalidJWS)
	}

	// —— 时间戳窗口（signedDate 是 UNIX 毫秒，参与签名，攻击者无法单独篡改） ——
	if notif.SignedDate <= 0 {
		return errs.New(PlatformName, opVerifyWebhook, "", "通知缺少 signedDate").
			WithCause(ErrWebhookInvalidJWS)
	}
	delta := a.now().Sub(time.UnixMilli(notif.SignedDate))
	if delta < 0 {
		delta = -delta
	}
	if delta > a.cfg.WebhookTolerance {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"signedDate 超出容忍窗口 "+a.cfg.WebhookTolerance.String()+"（偏差 "+delta.String()+"）").
			WithCause(ErrWebhookTimestampOutOfWindow)
	}

	// —— bundleId 核对（防别家应用的通知串进来） ——
	if a.cfg.BundleID != "" {
		notifBundle := notif.Data.BundleID
		if notifBundle == "" {
			notifBundle = notif.AppData.BundleID
		}
		// summary / externalPurchaseToken 形态的通知不含 bundleId，跳过核对。
		if notifBundle != "" && notifBundle != a.cfg.BundleID {
			return errs.New(PlatformName, opVerifyWebhook, "",
				"通知 bundleId="+notifBundle+" 与配置 BundleID="+a.cfg.BundleID+" 不符").
				WithCause(ErrWebhookBundleMismatch)
		}
	}

	// —— 防重放去重——只对验签通过的请求记账（垃圾请求进不了去重表）。 ——
	if notif.NotificationUUID == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "通知缺少 notificationUUID").
			WithCause(ErrWebhookInvalidJWS)
	}
	if a.seen(notif.NotificationUUID, 2*a.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"重复投递（notificationUUID="+notif.NotificationUUID+"，防重放拦截）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}

// readAndRestoreBody 全量读取请求 body（上限 maxSize 字节）并重置 r.Body。
// body 为 nil 时按空 payload 处理（同样重置，保证 handler 侧行为一致）。
func readAndRestoreBody(r *http.Request, maxSize int64) ([]byte, error) {
	if r.Body == nil {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return nil, nil
	}
	// 多读 1 字节用于精确判定“恰好超限”。
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
