//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：WebhookVerifier——Play RTDN（Pub/Sub push）OIDC token 验签 + messageId 防重放
//2026/6/11
//***************************************************

package google

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, google.ErrWebhookXxx) 区分失败原因（JWT 本身的失败原因
// 复用 ErrJWTXxx 系列哨兵，见 jwt.go）。
var (
	// ErrWebhookNotConfigured 未配置 webhook 能力（PubSubAudience /
	// PubSubServiceAccountEmail）。
	ErrWebhookNotConfigured = errors.New("google: webhook 能力未配置")
	// ErrWebhookMissingAuthorization push 请求缺少 Authorization: Bearer 头。
	ErrWebhookMissingAuthorization = errors.New("google: 缺少 Authorization Bearer 头")
	// ErrWebhookAudienceMismatch OIDC token 的 aud 与配置的 PubSubAudience 不符。
	ErrWebhookAudienceMismatch = errors.New("google: webhook OIDC token aud 不符")
	// ErrWebhookEmailMismatch OIDC token 的 email 与配置的 push service account
	// 不符，或 email_verified 不为 true。
	ErrWebhookEmailMismatch = errors.New("google: webhook OIDC token email 校验失败")
	// ErrWebhookBadVerificationToken 自管共享口令（query 参数 token）比对失败。
	ErrWebhookBadVerificationToken = errors.New("google: webhook 共享口令比对失败")
	// ErrWebhookBadEnvelope Pub/Sub push 包体非法（非 JSON / 缺 messageId /
	// data 不是合法 base64）。
	ErrWebhookBadEnvelope = errors.New("google: Pub/Sub push 包体非法")
	// ErrWebhookPackageMismatch RTDN 通知的 packageName 与配置不符（串包）。
	ErrWebhookPackageMismatch = errors.New("google: RTDN packageName 不符")
	// ErrWebhookReplayed 防重放拦截：同一 messageId 在窗口内重复出现。
	ErrWebhookReplayed = errors.New("google: webhook 重复投递（防重放拦截）")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// dedupKeyPrefix messageId 去重 key 前缀（与其他平台共用去重存储时隔离命名空间）。
const dedupKeyPrefix = "google_rtdn:"

// pushEnvelope 是 Cloud Pub/Sub push 投递的 HTTP 包体。
// 文档：https://developer.android.com/google/play/billing/rtdn-reference（2026-06-11 拉取）：
//
//	{"message":{"attributes":{...},"data":"<base64>","messageId":"136969346945"},
//	 "subscription":"projects/myproject/subscriptions/mysubscription"}
type pushEnvelope struct {
	Message struct {
		Attributes map[string]string `json:"attributes"`
		Data       string            `json:"data"`
		MessageID  string            `json:"messageId"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// developerNotification 是 data 字段 base64 解码后的 RTDN 通知体（本方法只取
// packageName 做归属核对；完整结构含 oneTimeProductNotification /
// subscriptionNotification / voidedPurchaseNotification / testNotification，
// 由业务 handler 解析。文档同上）。
type developerNotification struct {
	PackageName string `json:"packageName"`
}

// VerifyWebhook 实现 platform.WebhookVerifier：校验 Play RTDN（经 Cloud
// Pub/Sub push 投递）回调的真实性，并按合约硬要求完成新鲜度校验 + 重放去重；
// 读过的 Body 在返回前重置，业务 handler 可正常再读。
//
// 验真算法
// 文档：https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions（2026-06-11 拉取）：
//
//  1. push 订阅开启鉴权后，Pub/Sub 在每个 push 请求的 Authorization 头携带
//     "Bearer <OIDC JWT>"（RS256，header 带 kid）；
//  2. 官方校验步骤：「Checking the token integrity by using signature
//     validation. Checking that the email and audience claims in the token
//     match the values set in the push subscription」——即验签 + aud +
//     email（push 订阅配置的 service account）+ email_verified 为 true；
//  3. 签名用 Google 公钥验证（与 ID token 同一 JWKS 端点，iss 为
//     accounts.google.com；本实现复用 jwt.go 的 verifyGoogleJWT，含 iss /
//     exp / iat 校验）。
//
// 新鲜度（时间戳窗口）
// 官方明确「The tokens attached to requests sent to push endpoints may be up
// to an hour old」——token 寿命 1 小时，新鲜度以 token 的 exp 为准（verifyGoogleJWT
// 已校验，超时钟漂移容忍即拒）。注意不能用通知体的 eventTimeMillis 做窗口：
// Pub/Sub at-least-once 语义下未 ack 的消息会在事件发生很久之后合法重投。
//
// 防重放
// 文档：https://developer.android.com/google/play/billing/rtdn-reference（2026-06-11 拉取）：
// 「The messageId field is a unique identifier for the notification. ...
// it's recommended that you check the uniqueness of these IDs to avoid
// processing duplicate notifications」——以 messageId 为去重 key，窗口
// Config.WebhookDedupTTL（默认 2h，覆盖 token 整个有效期：超窗的重放已被
// token exp 拦截，两道闸无缝衔接）。单机默认内存去重；多实例部署必须经
// Config.WebhookSeen 注入共享存储实现。
//
// 注意：
//   - 本方法只完成「请求确实来自 Pub/Sub push 订阅且非重放」的校验。RTDN 官方
//     明确通知只代表「状态变了」——业务发货前必须回查 Play Developer API
//     （本包 VerifyPayment）拿完整购买状态，并以订单幂等发货；
//   - 验真通过后业务 handler 必须回 2xx 让 Pub/Sub ack，否则会按退避重投
//     （重投会被本方法的去重拦截为 ErrWebhookReplayed——这正是"业务处理失败
//     需重试"与"重放攻击"的语义分界，业务侧若依赖 Pub/Sub 重投补偿，应在
//     首次处理成功前不进入去重，即用 Config.WebhookSeen 注入"处理成功才记账"
//     的实现）。
func (g *Google) VerifyWebhook(r *http.Request) error {
	if g.cfg.PubSubAudience == "" || g.cfg.PubSubServiceAccountEmail == "" {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"未配置 webhook 能力：Config.PubSubAudience / PubSubServiceAccountEmail").
			WithCause(ErrWebhookNotConfigured)
	}

	// 自管共享口令（可选附加防线，常量时间比对防侧信道）。
	if g.cfg.PubSubVerificationToken != "" {
		got := r.URL.Query().Get("token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(g.cfg.PubSubVerificationToken)) != 1 {
			return errs.New(PlatformName, opVerifyWebhook, "", "query 参数 token 比对失败").
				WithCause(ErrWebhookBadVerificationToken)
		}
	}

	// Authorization: Bearer <OIDC JWT>。
	authHeader := r.Header.Get("Authorization")
	const bearerPrefix = "bearer "
	if len(authHeader) <= len(bearerPrefix) ||
		!strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 Authorization Bearer 头").
			WithCause(ErrWebhookMissingAuthorization)
	}
	token := strings.TrimSpace(authHeader[len(bearerPrefix):])

	claims, err := g.verifyGoogleJWT(r.Context(), opVerifyWebhook, token)
	if err != nil {
		return err
	}
	// aud：必须等于 push 订阅配置的 audience（官方校验步骤）。
	if !claims.Aud.contains(g.cfg.PubSubAudience) {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"aud 不符: "+truncate(strings.Join(claims.Aud, ","), 128)).
			WithCause(ErrWebhookAudienceMismatch)
	}
	// email + email_verified：必须等于 push 订阅配置的 service account（官方
	// 校验步骤；少了它任何 GCP 用户都能签出 aud 相同的合法 token）。邮箱按
	// 大小写不敏感比对。
	if !strings.EqualFold(claims.Email, g.cfg.PubSubServiceAccountEmail) || !claims.EmailVerified {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"email 校验失败: "+truncate(claims.Email, 128)).
			WithCause(ErrWebhookEmailMismatch)
	}

	// 读原始 body（限量防打爆内存），并立即重置回去（合约硬要求：实现读了
	// Body 必须在返回前重置，否则业务 handler 读不到）。
	raw, err := readAndRestoreBody(r, g.cfg.WebhookMaxBodySize)
	if err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err)
	}

	var envelope pushEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"push 包体不是合法 JSON: "+httpx.SafeBodySummary(raw)).
			WithCause(ErrWebhookBadEnvelope)
	}
	if envelope.Message.MessageID == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "push 包体缺少 message.messageId").
			WithCause(ErrWebhookBadEnvelope)
	}

	// data 解码 + packageName 归属核对（防串包；Config.PackageName 配置时才做）。
	// base64 形态：rtdn-reference 示例为标准 base64；按 protobuf JSON 映射规范
	// 解码端同时容忍 URL-safe 变体。
	if envelope.Message.Data != "" {
		data, decErr := decodeBase64Flexible(envelope.Message.Data)
		if decErr != nil {
			return errs.New(PlatformName, opVerifyWebhook, "", "message.data 不是合法 base64").
				WithCause(ErrWebhookBadEnvelope)
		}
		if g.cfg.PackageName != "" {
			var notification developerNotification
			// data 解析失败不在此拦截（业务 handler 自会处理语义），只核对
			// 能解析出 packageName 且明确不符的情况。
			if json.Unmarshal(data, &notification) == nil &&
				notification.PackageName != "" &&
				notification.PackageName != g.cfg.PackageName {
				return errs.New(PlatformName, opVerifyWebhook, "",
					"RTDN packageName 不符: "+truncate(notification.PackageName, 64)+" != "+g.cfg.PackageName).
					WithCause(ErrWebhookPackageMismatch)
			}
		}
	}

	// 防重放去重——只对验真通过的请求记账（垃圾请求进不了去重表）。
	if g.seen(dedupKeyPrefix+envelope.Message.MessageID, g.cfg.WebhookDedupTTL) {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"重复投递（防重放拦截，messageId="+truncate(envelope.Message.MessageID, 64)+"）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}

// decodeBase64Flexible 依次按标准 / URL-safe、带 / 不带 padding 四种形态解码。
func decodeBase64Flexible(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
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
