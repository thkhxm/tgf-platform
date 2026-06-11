//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description telegram：WebhookVerifier——X-Telegram-Bot-Api-Secret-Token 校验 + update_id 防重放
//2026/6/11
//***************************************************

package telegram

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, telegram.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookSecretNotConfigured Config.WebhookSecretToken 未配置——
	// 无校验依据，fail-closed 一律拒绝。
	ErrWebhookSecretNotConfigured = errors.New("telegram: Config.WebhookSecretToken 未配置（fail-closed 拒绝）")
	// ErrWebhookMissingSecretToken 请求缺少 X-Telegram-Bot-Api-Secret-Token header。
	ErrWebhookMissingSecretToken = errors.New("telegram: 缺少 X-Telegram-Bot-Api-Secret-Token header")
	// ErrWebhookSecretTokenMismatch secret token 比对失败（非本 bot 配置的回调来源）。
	ErrWebhookSecretTokenMismatch = errors.New("telegram: webhook secret token 比对失败")
	// ErrWebhookMalformedBody 回调体不是合法的 Update JSON（缺 update_id 等）。
	ErrWebhookMalformedBody = errors.New("telegram: webhook 回调体非法（不是合法的 Update JSON）")
	// ErrWebhookReplayed 防重放拦截：同一 update_id 在窗口内重复出现。
	ErrWebhookReplayed = errors.New("telegram: webhook 重复投递（防重放拦截）")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// webhookSecretHeader Telegram webhook 的 secret token header。
// 文档：https://core.telegram.org/bots/api#setwebhook（2026-06-11 拉取）：
// “If specified, the request will contain a header
// ‘X-Telegram-Bot-Api-Secret-Token’ with the secret token as content.”
// （http.Header.Get 大小写不敏感，canonical 化处理。）
const webhookSecretHeader = "X-Telegram-Bot-Api-Secret-Token"

// webhookUpdateEnvelope 只取 Update 的 update_id 字段做防重放去重。
// 文档：https://core.telegram.org/bots/api#update（2026-06-11 拉取）：
// update_id Integer——“The update's unique identifier. Update identifiers
// start from a certain positive number and increase sequentially. This
// identifier becomes especially handy if you're using webhooks, since it
// allows you to ignore repeated updates…”。
// 用指针区分“字段缺失”与“值为 0”（官方说明 id 从正数起，0/缺失均非法）。
type webhookUpdateEnvelope struct {
	UpdateID *int64 `json:"update_id"`
}

// VerifyWebhook 实现 platform.WebhookVerifier：校验 Telegram Bot API webhook
// 回调来源，并按合约硬要求完成防重放；读过的 Body 在返回前重置，业务 handler
// 可正常再读。
//
// 校验机制（官方唯一来源校验手段，文档见 webhookSecretHeader 注释）：
//
//  1. setWebhook 时配置 secret_token（1-256 字符，A-Z a-z 0-9 _ -），Telegram
//     每个回调请求都会带 X-Telegram-Bot-Api-Secret-Token header；
//  2. 本方法用常量时间比较（core/sign）校验该 header 与
//     Config.WebhookSecretToken 一致——header 缺失 / 不匹配 / 本地未配置
//     均拒绝（fail-closed）。
//
// 防重放
// 官方投递语义是 at-least-once（“In case of an unsuccessful request … we will
// repeat the request and give up after a reasonable amount of attempts”，
// setWebhook 文档同上）；以 Update.update_id 作去重 key（官方明确该 id 可用于
// “ignore repeated updates”，见 webhookUpdateEnvelope 注释），窗口
// Config.WebhookReplayTTL。单机默认内存去重；多实例部署必须经
// Config.WebhookSeen 注入共享存储实现。
//
// 关于合约的"时间戳窗口"要求：Telegram webhook 信封**没有**时间戳/签名字段
// （2026-06-11 拉取的 https://core.telegram.org/bots/api 正文中，Update 对象
// 无顶层时间字段、官方亦无回调签名机制）——平台无对应物，无法做时间戳窗口
// 校验，以 secret token（来源证明）+ update_id 去重（防重放）为官方协议下的
// 完整替代，不凭空发明协议外字段。
//
// 注意：本方法只完成「请求确实来自本 bot 配置的 webhook 且非重复投递」的校验。
// 业务发货前还须对 successful_payment 走 VerifyPayment 二次确认 + 幂等发货。
// 可选加固（本方法不做，部署层可做）：官方建议 webhook 服务仅放行 Telegram
// 出口网段，详见 https://core.telegram.org/bots/webhooks 。
func (t *Telegram) VerifyWebhook(r *http.Request) error {
	if t.cfg.WebhookSecretToken == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "WebhookSecretToken 未配置").
			WithCause(ErrWebhookSecretNotConfigured)
	}
	got := r.Header.Get(webhookSecretHeader)
	if got == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 "+webhookSecretHeader+" header").
			WithCause(ErrWebhookMissingSecretToken)
	}
	if !sign.ConstantTimeEqualString(got, t.cfg.WebhookSecretToken) {
		return errs.New(PlatformName, opVerifyWebhook, "", "secret token 比对失败").
			WithCause(ErrWebhookSecretTokenMismatch)
	}

	// 读原始 body（限量防打爆内存），并立即重置回去（合约硬要求：实现读了
	// Body 必须在返回前重置，否则业务 handler 读不到）。
	raw, err := readAndRestoreBody(r, t.cfg.WebhookMaxBodySize)
	if err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err)
	}

	// 防重放：解析 update_id 去重（来源已经 secret token 证明，去重 key 可信）。
	var upd webhookUpdateEnvelope
	if err := json.Unmarshal(raw, &upd); err != nil || upd.UpdateID == nil || *upd.UpdateID <= 0 {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"回调体缺少合法 update_id: "+truncate(string(raw), 128)).
			WithCause(ErrWebhookMalformedBody)
	}
	if t.seen(strconv.FormatInt(*upd.UpdateID, 10), t.cfg.WebhookReplayTTL) {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"update_id "+strconv.FormatInt(*upd.UpdateID, 10)+" 重复投递（防重放拦截）").
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
