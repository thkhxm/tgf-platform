//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：WebhookVerifier——TikTok-Signature 验签 + 时间戳窗口 + 防重放去重
//2026/6/11
//***************************************************

package tiktok

import (
	"bytes"
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
// errors.Is(err, tiktok.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookMissingSignature 请求缺少 TikTok-Signature header。
	ErrWebhookMissingSignature = errors.New("tiktok: 缺少 TikTok-Signature header")
	// ErrWebhookMalformedSignature TikTok-Signature header 格式非法
	// （缺 t= / s= 元素，或 t 不是十进制 Unix 秒）。
	ErrWebhookMalformedSignature = errors.New("tiktok: TikTok-Signature header 格式非法")
	// ErrWebhookSignatureMismatch 签名比对失败（密钥不符或 payload 被篡改）。
	ErrWebhookSignatureMismatch = errors.New("tiktok: webhook 签名比对失败")
	// ErrWebhookTimestampOutOfWindow 签名有效但时间戳超出容忍窗口（过旧或超前）。
	ErrWebhookTimestampOutOfWindow = errors.New("tiktok: webhook 时间戳超出容忍窗口")
	// ErrWebhookReplayed 防重放拦截：同一签名在窗口内重复出现。
	ErrWebhookReplayed = errors.New("tiktok: webhook 重复投递（防重放拦截）")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// webhookSignatureHeader TikTok webhook 签名 header。
// http.Header.Get 大小写不敏感（canonical 化），官方示例写作 "Tiktok-Signature"。
const webhookSignatureHeader = "TikTok-Signature"

// VerifyWebhook 实现 platform.WebhookVerifier：校验 TikTok webhook 回调签名，
// 并按合约硬要求完成时间戳窗口校验 + 重放去重；读过的 Body 在返回前重置，
// 业务 handler 可正常再读。
//
// 验签算法
// 文档：https://developers.tiktok.com/doc/webhooks-verification（2026-06-11 经
// 本机代理直连拉取正文核对。其中「t 与 payload 以 "." 拼接」已经官方正文逐字
// 确认——原文 "signed_payload can be created by concatenating: The timestamp as
// a string / The character . / The actual JSON payload (request body)"，HMAC 为
// "An HMAC with the SHA256 hash function is computed with your client_secret as
// the key and your signed_payload string as the message"）：
//
//  1. header 形如 Tiktok-Signature: t=1633174587,s=1849...e66 ——按 "," 拆元素、
//     按 "=" 拆前缀与值；t 是 Unix 秒时间戳，s 是签名（64 位小写十六进制）；
//  2. signed_payload = <t 原始字符串> + "." + <HTTP 请求原始 body>；
//  3. 期望签名 = HMAC-SHA256(key = client_secret, signed_payload) 的十六进制；
//  4. 先常量时间比对签名；签名有效再校验时间戳新鲜度（时间戳参与签名，攻击者
//     无法单独篡改，官方原文 "Since this timestamp is part of the signed payload,
//     an attacker cannot change the timestamp without invalidating the
//     signature"）——过旧/超前超出窗口即拒绝（窗口大小官方留给应用决定）。
//
// 防重放
// 官方投递语义是 at-least-once（同一事件可能多次送达并以指数退避重投最长 72h，
// 业务必须幂等处理；文档：https://developers.tiktok.com/doc/webhooks-overview ，
// 2026-06-11 拉取），header 中无独立 nonce——以签名值本身作去重 key（签名对
// 「时间戳+payload」唯一），窗口为 2×WebhookTolerance。单机默认内存去重；
// 多实例部署必须经 Config.WebhookSeen 注入共享存储实现。
//
// 注意：官方未明示失败重投（未收到 200 时）是否重新签名/更新时间戳。本去重在
// 验签通过即记账——若业务 handler 验签后处理失败（非 200）且平台重投沿用原
// 签名，重投会被当重放拦截。对"处理可能失败、依赖平台重投兜底"的业务，应经
// Config.WebhookSeen 注入与业务消费状态联动的去重实现（仅对已成功消费的签名
// 判重），或对账兜底（VerifyPayment 主动查单）。
//
// 注意：本方法只完成「请求确实来自 TikTok 且非重放」的校验。业务发货前还须按
// 官方要求核对事件内容（如 minis.trade_order.redeem.success 的 order_id 与本地
// 订单匹配、幂等发货）。
func (t *TikTok) VerifyWebhook(r *http.Request) error {
	headerVal := r.Header.Get(webhookSignatureHeader)
	if headerVal == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 "+webhookSignatureHeader+" header").
			WithCause(ErrWebhookMissingSignature)
	}
	tsStr, sigHex, ok := parseSignatureHeader(headerVal)
	if !ok {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名 header 格式非法: "+truncate(headerVal, 128)).
			WithCause(ErrWebhookMalformedSignature)
	}

	// 读原始 body（限量防打爆内存），并立即重置回去（合约硬要求：实现读了
	// Body 必须在返回前重置，否则业务 handler 读不到）。
	raw, err := readAndRestoreBody(r, t.cfg.WebhookMaxBodySize)
	if err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err)
	}

	// signed_payload = t + "." + raw（验签必须用原始 body 字节，绝不可用
	// 反序列化再序列化的结果——字段顺序/空白差异会让签名永远对不上）。
	signedPayload := make([]byte, 0, len(tsStr)+1+len(raw))
	signedPayload = append(signedPayload, tsStr...)
	signedPayload = append(signedPayload, '.')
	signedPayload = append(signedPayload, raw...)
	if !sign.VerifyHMACSHA256Hex([]byte(t.cfg.ClientSecret), signedPayload, sigHex) {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名比对失败").
			WithCause(ErrWebhookSignatureMismatch)
	}

	// 时间戳窗口（官方步骤：先比签名，再查新鲜度；t 单位为秒，官方示例
	// t=1633174587）。
	tsSec, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "", "时间戳非法: "+truncate(tsStr, 32)).
			WithCause(ErrWebhookMalformedSignature)
	}
	delta := t.now().Unix() - tsSec
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > t.cfg.WebhookTolerance {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"时间戳超出容忍窗口 "+t.cfg.WebhookTolerance.String()+"（偏差 "+strconv.FormatInt(delta, 10)+"s）").
			WithCause(ErrWebhookTimestampOutOfWindow)
	}

	// 防重放去重——只对验签通过的请求记账（垃圾签名进不了去重表）。
	// 去重窗口取 2×容忍窗口：窗口边缘的合法请求过期出表后，其重放已被时间戳
	// 窗口拦截，两道闸无缝衔接。
	if t.seen(sigHex, 2*t.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "", "重复投递（防重放拦截）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}

// parseSignatureHeader 解析 "t=1633174587,s=1849...e66" 形式的签名 header
// （拆分规则见官方文档，VerifyWebhook 注释）。t / s 任一缺失或为空即非法。
func parseSignatureHeader(headerVal string) (ts, sig string, ok bool) {
	for _, part := range strings.Split(headerVal, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "s":
			sig = v
		}
	}
	return ts, sig, ts != "" && sig != ""
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
