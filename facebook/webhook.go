//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description facebook：WebhookVerifier——X-Hub-Signature-256 验签 + hub.verify_token 订阅核验 + 时间戳窗口 + 防重放
//2026/6/11
//***************************************************

package facebook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, facebook.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookMissingSignature 请求缺少 X-Hub-Signature-256 header。
	ErrWebhookMissingSignature = errors.New("facebook: 缺少 X-Hub-Signature-256 header")
	// ErrWebhookMalformedSignature X-Hub-Signature-256 header 格式非法
	// （缺 "sha256=" 前缀或签名不是十六进制）。
	ErrWebhookMalformedSignature = errors.New("facebook: X-Hub-Signature-256 header 格式非法")
	// ErrWebhookSignatureMismatch 签名比对失败（App Secret 不符或 payload 被篡改）。
	ErrWebhookSignatureMismatch = errors.New("facebook: webhook 签名比对失败")
	// ErrWebhookTimestampOutOfWindow 签名有效但事件时间戳超出容忍窗口（过旧或超前）。
	ErrWebhookTimestampOutOfWindow = errors.New("facebook: webhook 事件时间戳超出容忍窗口")
	// ErrWebhookReplayed 防重放拦截：同一签名在窗口内重复出现。
	ErrWebhookReplayed = errors.New("facebook: webhook 重复投递（防重放拦截）")
	// ErrWebhookVerifyTokenMismatch 订阅核验（GET）请求的 hub.verify_token 不符。
	ErrWebhookVerifyTokenMismatch = errors.New("facebook: webhook 订阅核验 verify_token 不符")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// webhookSignatureHeader 事件通知签名 header。
// 文档：https://developers.facebook.com/docs/graph-api/webhooks/getting-started
// （2026-06-11 拉取）："X-Hub-Signature-256: sha256={SHA256-signature}"。
const webhookSignatureHeader = "X-Hub-Signature-256"

// webhookSignaturePrefix 签名值前缀（官方："preceded with sha256="）。
const webhookSignaturePrefix = "sha256="

// VerifyWebhook 实现 platform.WebhookVerifier：校验 Graph API Webhooks 回调，
// 读过的 Body 在返回前重置，业务 handler 可正常再读。
//
// 两类请求（文档：https://developers.facebook.com/docs/graph-api/webhooks/getting-started ，
// 2026-06-11 拉取）：
//
// 一、订阅核验请求（GET Verification Request）：
//
//	GET ...?hub.mode=subscribe&hub.challenge=1158201444&hub.verify_token=<token>
//
// 官方要求校验 hub.verify_token 与 App Dashboard 配置的 Verify Token 一致后，
// 把 hub.challenge 原样响应。本方法完成 token 校验（常量时间比较）；响应
// challenge 由业务 handler 调 VerificationChallenge 取值回写。
//
// 二、事件通知（POST Event Notification）验签：
//
//	X-Hub-Signature-256: sha256=<hex>
//
// 期望签名 = HMAC-SHA256(key=App Secret, data=请求原始 body) 的十六进制。
// 算法依据：官方校验样例 crypto.createHmac("sha256", appSecret).update(buf).digest("hex")
// （文档：https://developers.facebook.com/docs/messenger-platform/webhooks ，
// 2026-06-11 拉取）。官方同时提醒：签名按「unicode 转义且小写 hex 数字」形态的
// payload 生成（官方例：字符串 äöå 转义为 \u00e4\u00f6\u00e5）——平台投递的
// 原始字节本身就是转义形态，故必须对**原始 body 字节**计算 HMAC，绝不可
// 反序列化再序列化（字段顺序/空白/转义差异会让签名永远对不上）。
//
// 时间戳窗口
// Facebook webhook 协议没有独立的签名时间戳 header；事件载荷的 entry[].time
// 处于签名覆盖范围内（签名覆盖整个 body），官方样例两种单位都出现过：
// getting-started 页 "time": 1520383571（秒）、messenger-platform 页
// "time": 1458692752478（毫秒），按数量级归一。载荷可解析出 entry[].time 时，
// 取**最新**一条与本地时钟比对（一次投递最多聚合 1000 条更新，旧事件属正常），
// 超窗口拒绝；载荷不含 entry[].time（协议没给时间可校）时跳过本道闸，
// 此时仅防重放去重生效——这是该协议能支持的上限，不编造校验。
//
// 防重放
// 官方投递语义是 at-least-once（"If any update sent to your server fails, we
// will retry... Your server should handle deduplication in these cases"，
// getting-started 页原文）；协议无独立 nonce——以签名值本身作去重 key（签名对
// payload 唯一），窗口为 2×WebhookTolerance。单机默认内存去重；多实例部署必须
// 经 Config.WebhookSeen 注入共享存储实现。
//
// 注意：本方法只完成「请求确实来自 Facebook 且非重放」的校验。业务处理前还须
// 按官方要求对事件内容自行去重（entry id / 事件字段幂等）。
func (f *Facebook) VerifyWebhook(r *http.Request) error {
	// 订阅核验请求：GET + hub.mode 参数（官方固定为 "subscribe"）。
	if r.Method == http.MethodGet {
		return f.verifySubscription(r)
	}

	headerVal := r.Header.Get(webhookSignatureHeader)
	if headerVal == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 "+webhookSignatureHeader+" header").
			WithCause(ErrWebhookMissingSignature)
	}
	if !strings.HasPrefix(headerVal, webhookSignaturePrefix) {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"签名 header 缺少 "+webhookSignaturePrefix+" 前缀: "+truncate(headerVal, 128)).
			WithCause(ErrWebhookMalformedSignature)
	}
	sigHex := headerVal[len(webhookSignaturePrefix):]

	// 读原始 body（限量防打爆内存），并立即重置回去（合约硬要求：实现读了
	// Body 必须在返回前重置，否则业务 handler 读不到）。
	raw, err := readAndRestoreBody(r, f.cfg.WebhookMaxBodySize)
	if err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err)
	}
	if !sign.VerifyHMACSHA256Hex([]byte(f.cfg.AppSecret), raw, sigHex) {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名比对失败").
			WithCause(ErrWebhookSignatureMismatch)
	}

	// 时间戳窗口（entry[].time 可得时；语义与单位见方法注释）。
	if newest, ok := newestEntryTime(raw); ok {
		delta := f.now().Unix() - newest
		if delta < 0 {
			delta = -delta
		}
		if time.Duration(delta)*time.Second > f.cfg.WebhookTolerance {
			return errs.New(PlatformName, opVerifyWebhook, "",
				"事件时间戳超出容忍窗口 "+f.cfg.WebhookTolerance.String()+"（偏差 "+strconv.FormatInt(delta, 10)+"s）").
				WithCause(ErrWebhookTimestampOutOfWindow)
		}
	}

	// 防重放去重——只对验签通过的请求记账（垃圾签名进不了去重表）。
	// 去重窗口取 2×容忍窗口：窗口边缘的合法请求过期出表后，其重放已被时间戳
	// 窗口拦截（载荷带 entry.time 时），两道闸衔接。
	if f.seen(strings.ToLower(sigHex), 2*f.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "", "重复投递（防重放拦截）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}

// verifySubscription 校验订阅核验请求的 hub.verify_token（协议见 VerifyWebhook 注释）。
func (f *Facebook) verifySubscription(r *http.Request) error {
	q := r.URL.Query()
	if q.Get("hub.mode") != "subscribe" {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"GET 请求缺少 hub.mode=subscribe（不是合法的订阅核验请求）").
			WithCause(ErrWebhookVerifyTokenMismatch)
	}
	if f.cfg.WebhookVerifyToken == "" {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"未配置 Config.WebhookVerifyToken，拒绝订阅核验请求").
			WithCause(ErrWebhookVerifyTokenMismatch)
	}
	if !sign.ConstantTimeEqualString(q.Get("hub.verify_token"), f.cfg.WebhookVerifyToken) {
		return errs.New(PlatformName, opVerifyWebhook, "", "hub.verify_token 不符").
			WithCause(ErrWebhookVerifyTokenMismatch)
	}
	return nil
}

// VerificationChallenge 取订阅核验请求的 hub.challenge——VerifyWebhook 对 GET
// 请求返回 nil 后，业务 handler 应把该值以 200 文本原样回写（官方要求
// "Respond with the hub.challenge value"，文档见 VerifyWebhook 注释）。
func VerificationChallenge(r *http.Request) string {
	return r.URL.Query().Get("hub.challenge")
}

// webhookEnvelope 事件通知载荷的最小解析结构——只取时间戳窗口需要的 entry[].time
// （样例见 VerifyWebhook 注释引用的两份官方文档；其余业务字段由 handler 自行解析）。
type webhookEnvelope struct {
	Entry []struct {
		Time json.Number `json:"time"`
	} `json:"entry"`
}

// newestEntryTime 从载荷解析最新一条 entry.time（归一为 Unix 秒）。
// 载荷不是 JSON、无 entry、或 entry 均不带 time 时返回 ok=false（跳过窗口校验）。
func newestEntryTime(raw []byte) (newest int64, ok bool) {
	var env webhookEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, false
	}
	for _, e := range env.Entry {
		v, err := e.Time.Int64()
		if err != nil || v <= 0 {
			continue
		}
		// 单位按数量级归一（两种官方样例：1520383571 秒 / 1458692752478 毫秒）。
		if v >= 1_000_000_000_000 {
			v /= 1000
		}
		if v > newest {
			newest, ok = v, true
		}
	}
	return newest, ok
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

// memorySeen 是单机内存版防重放去重表（key → 过期时刻）。
// 仅适合单实例部署；多实例必须经 Config.WebhookSeen 注入共享存储实现。
type memorySeen struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newMemorySeen() *memorySeen {
	return &memorySeen{entries: make(map[string]time.Time)}
}

// seen 报告 key 是否在 ttl 窗口内已出现过；首次出现记录并返回 false。
// 每次调用顺手清理过期项——条目量与回调速率同阶，线性清理足够。
func (m *memorySeen) seen(key string, ttl time.Duration) bool {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, exp := range m.entries {
		if now.After(exp) {
			delete(m.entries, k)
		}
	}
	if _, dup := m.entries[key]; dup {
		return true
	}
	m.entries[key] = now.Add(ttl)
	return false
}
