//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description line：WebhookVerifier——x-line-signature 验签 + 事件时间戳窗口 + 防重放去重
//2026/6/11
//***************************************************

package line

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, line.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookSecretMissing 配置缺少 ChannelSecret，无法验签。
	ErrWebhookSecretMissing = errors.New("line: Config.ChannelSecret 未配置，无法校验 webhook 签名")
	// ErrWebhookMissingSignature 请求缺少 x-line-signature header。
	ErrWebhookMissingSignature = errors.New("line: 缺少 x-line-signature header")
	// ErrWebhookMalformedSignature x-line-signature 不是合法 base64。
	ErrWebhookMalformedSignature = errors.New("line: x-line-signature 不是合法 base64")
	// ErrWebhookSignatureMismatch 签名比对失败（密钥不符或 payload 被篡改）。
	ErrWebhookSignatureMismatch = errors.New("line: webhook 签名比对失败")
	// ErrWebhookMalformedBody 签名有效但回调体不是官方结构的 JSON。
	ErrWebhookMalformedBody = errors.New("line: webhook 回调体结构非法")
	// ErrWebhookTimestampOutOfWindow 签名有效但事件时间戳超出容忍窗口（过旧或超前）。
	ErrWebhookTimestampOutOfWindow = errors.New("line: webhook 事件时间戳超出容忍窗口")
	// ErrWebhookReplayed 防重放拦截：同一签名在窗口内重复出现。
	ErrWebhookReplayed = errors.New("line: webhook 重复投递（防重放拦截）")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// webhookSignatureHeader LINE webhook 签名 header。
// 官方 Go SDK（LINE Corporation 官方仓库 https://github.com/line/line-bot-sdk-go
// linebot/webhook.go，2026-06-11 拉取）原文取 r.Header.Get("x-line-signature")；
// http.Header.Get 大小写不敏感（canonical 化）。
const webhookSignatureHeader = "x-line-signature"

// webhookCallback 是 webhook 回调体（只解析验证所需字段，事件业务字段由
// 业务 handler 自行解析）。
//
// 结构以 LINE 官方 OpenAPI 规格为准（LINE Corporation 官方仓库
// https://github.com/line/line-openapi 的 webhook.yml，2026-06-11 拉取）：
//   - CallbackRequest：required [destination, events]；destination 是接收
//     事件的 bot 的 user ID（^U[0-9a-f]{32}$）；events 是事件数组，官方原文
//     "The LINE Platform may send an empty array that doesn't include a
//     webhook event object to confirm communication."（Verify 探测）；
//   - Event 公共必填字段：type / timestamp（int64，官方原文 "Time of the
//     event in milliseconds."）/ mode / webhookEventId（ULID，唯一标识一次
//     webhook 事件）/ deliveryContext.isRedelivery（bool，是否重投）。
type webhookCallback struct {
	Destination string `json:"destination"`
	Events      []struct {
		Type            string `json:"type"`
		Timestamp       int64  `json:"timestamp"`
		WebhookEventID  string `json:"webhookEventId"`
		DeliveryContext struct {
			IsRedelivery bool `json:"isRedelivery"`
		} `json:"deliveryContext"`
	} `json:"events"`
}

// VerifyWebhook 实现 platform.WebhookVerifier：校验 LINE Messaging API webhook
// 回调签名，并按合约硬要求完成时间戳窗口校验 + 重放去重；读过的 Body 在返回前
// 重置，业务 handler 可正常再读。
//
// 验签算法
// 以 LINE 官方 Go SDK 实现为准（LINE Corporation 官方仓库
// https://github.com/line/line-bot-sdk-go 的 linebot/webhook.go ValidateSignature，
// 2026-06-11 拉取；官方 reference 章节
// https://developers.line.biz/en/reference/messaging-api/#signature-validation
// 正文为前端懒加载，本环境未能抓到该章节文字，算法以上述官方第一方代码为准）：
//
//	期望签名 = Base64(HMAC-SHA256(key = channel secret, HTTP 请求原始 body))
//	与 x-line-signature header 值做常量时间比对。
//
// 时间戳窗口
// LINE webhook 没有 header 级时间戳，新鲜度校验作用在已验签 body 内的事件
// timestamp 字段（毫秒，字段定义见 webhookCallback 注释）：
//   - isRedelivery=false 的事件：|now - timestamp| 超出 WebhookTolerance 即拒绝；
//   - isRedelivery=true 的事件：跳过窗口校验——官方重投携带的是原事件时间，
//     可能远早于当前（isRedelivery 在已验签 body 内，攻击者无法伪造；逐字节
//     重放原请求由下方签名去重拦截）；
//   - events 为空数组：无时间戳可校验，验签通过即放行（官方 Verify 探测语义）。
//
// 防重放
// 以签名值本身作去重 key（签名对「channel secret + 完整 body」唯一，逐字节
// 重放必然命中），窗口为 2×WebhookTolerance。官方合法重投的 body 中
// isRedelivery 字段翻转为 true，签名随之变化，不会被误拦。单机默认内存去重；
// 多实例部署必须经 Config.WebhookSeen 注入共享存储实现。
//
// 注意：本方法只完成「请求确实来自 LINE 且非重放」的校验。事件级幂等
// （官方重投与本次投递的 webhookEventId 相同）由业务 handler 按
// webhookEventId 自行去重落账。
func (l *Line) VerifyWebhook(r *http.Request) error {
	if l.cfg.ChannelSecret == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "ChannelSecret 未配置").
			WithCause(ErrWebhookSecretMissing)
	}
	sigB64 := r.Header.Get(webhookSignatureHeader)
	if sigB64 == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 "+webhookSignatureHeader+" header").
			WithCause(ErrWebhookMissingSignature)
	}
	expected, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名 header 不是合法 base64: "+truncate(sigB64, 128)).
			WithCause(ErrWebhookMalformedSignature)
	}

	// 读原始 body（限量防打爆内存），并立即重置回去（合约硬要求：实现读了
	// Body 必须在返回前重置，否则业务 handler 读不到）。
	raw, err := readAndRestoreBody(r, l.cfg.WebhookMaxBodySize)
	if err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err)
	}

	// 验签必须用原始 body 字节，绝不可用反序列化再序列化的结果——字段顺序/
	// 空白差异会让签名永远对不上。
	if !sign.VerifyHMACSHA256([]byte(l.cfg.ChannelSecret), raw, expected) {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名比对失败").
			WithCause(ErrWebhookSignatureMismatch)
	}

	// 解析已验签 body 的验证所需字段（结构见 webhookCallback 注释）。
	var cb webhookCallback
	if err := httpx.DecodeJSON(raw, &cb); err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err).WithCause(ErrWebhookMalformedBody)
	}

	// 事件时间戳窗口（毫秒；重投事件跳过，理由见方法注释）。
	nowMs := l.now().UnixMilli()
	tolMs := l.cfg.WebhookTolerance.Milliseconds()
	for _, ev := range cb.Events {
		if ev.DeliveryContext.IsRedelivery {
			continue
		}
		delta := nowMs - ev.Timestamp
		if delta < 0 {
			delta = -delta
		}
		if delta > tolMs {
			return errs.New(PlatformName, opVerifyWebhook, "",
				"事件时间戳超出容忍窗口 "+l.cfg.WebhookTolerance.String()+
					"（事件 "+truncate(ev.WebhookEventID, 64)+" 偏差 "+strconv.FormatInt(delta, 10)+"ms）").
				WithCause(ErrWebhookTimestampOutOfWindow)
		}
	}

	// 防重放去重——只对验签通过的请求记账（垃圾签名进不了去重表）。
	// 去重窗口取 2×容忍窗口：窗口边缘的合法请求过期出表后，其重放已被时间戳
	// 窗口拦截，两道闸无缝衔接。
	if l.seen(sigB64, 2*l.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "", "重复投递（防重放拦截）").
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
