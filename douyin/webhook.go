//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：WebhookVerifier——虚拟支付服务端回调 SHA1 验签 + 时间戳窗口 + 防重放
//2026/6/11
//***************************************************

package douyin

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, douyin.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookTokenNotConfigured 未配置 Config.PayCallbackToken。
	ErrWebhookTokenNotConfigured = errors.New("douyin: 未配置 PayCallbackToken（虚拟支付服务器回调 Token）")
	// ErrWebhookMissingSignature 请求缺少 signature 参数。
	ErrWebhookMissingSignature = errors.New("douyin: 回调请求缺少 signature 参数")
	// ErrWebhookMalformedRequest 回调请求格式非法（body 非 JSON / timestamp 非十进制秒）。
	ErrWebhookMalformedRequest = errors.New("douyin: 回调请求格式非法")
	// ErrWebhookSignatureMismatch 签名比对失败（Token 不符或 payload 被篡改）。
	ErrWebhookSignatureMismatch = errors.New("douyin: 回调签名比对失败")
	// ErrWebhookTimestampOutOfWindow 签名有效但时间戳超出容忍窗口（过旧或超前）。
	ErrWebhookTimestampOutOfWindow = errors.New("douyin: 回调时间戳超出容忍窗口")
	// ErrWebhookReplayed 防重放拦截：同一签名在窗口内重复出现。
	ErrWebhookReplayed = errors.New("douyin: 回调重复投递（防重放拦截）")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// orderCallbackEnvelope 是支付回调的外层包封。
//
// 文档：https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/api/javascript-api/payment/payment-server-callback
// （2026-06-11 curl 拉取正文）
//
// 两类请求共用同一验签算法（详见 VerifyWebhook 注释）：
//   - GET 可访问性验证：参数在 query——signature / timestamp / nonce / msg（可空）
//     / echostr，校验通过后业务须回传 echostr 完成验证；
//   - POST 正式订单回调（订单成功支付才回调，支付失败不回调）：参数在 JSON body——
//     {"timestamp":"...","nonce":"...","msg":"...","signature":"..."}（官方 Go 结构体
//     OrderInfo：timestamp 时间戳 / nonce 随机数 / msg 包体 / signature 根据 token
//     生成的签名），msg 是 JSON 字符串包体，结构见 OrderCallback。
type orderCallbackEnvelope struct {
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Msg       string `json:"msg"`
	Signature string `json:"signature"`
}

// OrderCallback 是支付回调包体 msg 反序列化后的订单信息（字段名与注释取自官方
// 文档的 Go 结构体 OrderSuccessPayInfo，文档 URL 见 orderCallbackEnvelope 注释）。
type OrderCallback struct {
	// AppID 小游戏 appid。
	AppID string `json:"appid"`
	// CpOrderNo 开发者自定义订单号（下单时 tt.requestGamePayment 的 customId）。
	CpOrderNo string `json:"cp_orderno"`
	// CpExtra 开发者传的额外参数（下单时的 extraInfo）。
	CpExtra string `json:"cp_extra"`
	// OrderNoChannel 小游戏后台交易单号（官方交易单号，路径：小游戏后台 -
	// 商业化 - 虚拟支付 - 支付指标明细）。
	OrderNoChannel string `json:"order_no_channel"`
	// AmountCent 订单金额，单位人民币分。
	AmountCent int64 `json:"amount_cent"`
	// AmountCoin 购买游戏币数量。
	AmountCoin int64 `json:"amount_coin"`
	// Currency 支付币种：CNY 人民币 / DIAMOND 钻石。
	Currency string `json:"currency"`
}

// VerifyWebhook 实现 platform.WebhookVerifier：校验抖音虚拟支付服务端回调的
// 签名，并按合约硬要求完成时间戳窗口校验 + 重放去重；读过的 Body 在返回前重置，
// 业务 handler 可正常再读。
//
// 前置配置：开发者平台 商业化->虚拟支付->支付设置 填写服务器地址与「服务器回调
// Token」（即 Config.PayCallbackToken）。
//
// 验签算法
// 文档：https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/api/javascript-api/payment/payment-server-callback
// （2026-06-11 curl 拉取正文，官方原文）：
//
//  1. 将 token（服务器回调 Token）、timestamp、nonce、msg 四个参数进行拼接，
//     然后按照字符串自然大小进行排序（官方 Go 示例即 sort.Strings 后 join ""）；
//  2. 使用 SHA1 算法得到 signature（十六进制小写）；
//  3. 与请求携带的 signature 对比，一致说明请求来自字节平台服务端。
//
// 参数位置（官方明确两种请求逻辑不一致）：GET 可访问性验证请求在 query；
// POST 正式订单回调在 JSON body（结构见 orderCallbackEnvelope）。
//
// 时间戳窗口与防重放
// 官方文档未规定时间戳窗口与去重要求——这两道闸是 tgf 合约对 WebhookVerifier
// 的硬要求：时间戳参与签名（攻击者无法单独篡改），先比签名再校验新鲜度；
// timestamp 按 Unix 秒解析（官方仅注释「时间戳」未标单位，同域「支付签名生成
// 算法」文档对 ts 明确“单位：秒”，端到端验证时务必复核，见 doc.go NEEDS-DOC
// 第 1 条）。官方投递语义是 at-least-once（通知失败按 10s/30s/1m/.../2h 递增
// 重试，总共 4 小时 45 分），以签名值本身作去重 key（签名对「时间戳+nonce+包体」
// 唯一），窗口为 2×WebhookTolerance。单机默认内存去重；多实例部署必须经
// Config.WebhookSeen 注入共享存储实现。
//
// 注意：本方法只完成「请求确实来自字节平台且非重放」的校验。
//   - GET 验证请求：业务 handler 还须回传 echostr 完成可访问性验证（用
//     WebhookEcho 取）；
//   - POST 订单回调：业务发货前还须解析包体核对订单（用 ParseOrderCallback 取
//     cp_orderno / amount_cent 与本地订单匹配、幂等发货），处理成功返回
//     HTTP 200，非 200 平台会按上述节奏重试。
func (d *Douyin) VerifyWebhook(r *http.Request) error {
	if d.cfg.PayCallbackToken == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "未配置 PayCallbackToken").
			WithCause(ErrWebhookTokenNotConfigured)
	}

	var env orderCallbackEnvelope
	if r.Method == http.MethodGet {
		// GET 可访问性验证：参数在 query。
		q := r.URL.Query()
		env.Timestamp = q.Get("timestamp")
		env.Nonce = q.Get("nonce")
		env.Msg = q.Get("msg") // 验证请求中可能为空串，空串照常参与排序拼接
		env.Signature = q.Get("signature")
	} else {
		// POST 正式订单回调：参数在 JSON body。读原始 body（限量防打爆内存），
		// 并立即重置回去（合约硬要求：实现读了 Body 必须在返回前重置）。
		raw, err := readAndRestoreBody(r, d.cfg.WebhookMaxBodySize)
		if err != nil {
			return errs.Wrap(PlatformName, opVerifyWebhook, err)
		}
		if err := httpx.DecodeJSON(raw, &env); err != nil {
			return errs.Wrap(PlatformName, opVerifyWebhook, err).
				WithCause(ErrWebhookMalformedRequest)
		}
	}
	if env.Signature == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 signature 参数").
			WithCause(ErrWebhookMissingSignature)
	}

	// 官方算法：token + timestamp + nonce + msg 自然序排序 → join("") → SHA1 hex。
	// 常量时间比对（验签比较的硬要求，防时序侧信道）。
	expected := paySign(d.cfg.PayCallbackToken, env.Timestamp, env.Nonce, env.Msg)
	if !sign.ConstantTimeEqualString(expected, strings.ToLower(env.Signature)) {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名比对失败").
			WithCause(ErrWebhookSignatureMismatch)
	}

	// 时间戳窗口（先比签名再查新鲜度；timestamp 按 Unix 秒解析，单位依据见方法注释）。
	tsSec, err := strconv.ParseInt(env.Timestamp, 10, 64)
	if err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "", "时间戳非法: "+truncate(env.Timestamp, 32)).
			WithCause(ErrWebhookMalformedRequest)
	}
	delta := d.now().Unix() - tsSec
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > d.cfg.WebhookTolerance {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"时间戳超出容忍窗口 "+d.cfg.WebhookTolerance.String()+"（偏差 "+strconv.FormatInt(delta, 10)+"s）").
			WithCause(ErrWebhookTimestampOutOfWindow)
	}

	// 防重放去重——只对验签通过的请求记账（垃圾签名进不了去重表）。
	// 去重窗口取 2×容忍窗口：窗口边缘的合法请求过期出表后，其重放已被时间戳
	// 窗口拦截，两道闸无缝衔接。
	if d.seen(strings.ToLower(env.Signature), 2*d.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "", "重复投递（防重放拦截）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}

// WebhookEcho 识别平台的 GET 可访问性验证请求并返回应回传的 echostr。
// 第二个返回值为 true 时，业务 handler 应把 echostr 以 HTTP 200 原文回传完成验证
// （官方流程见 VerifyWebhook 注释）；调用前须先过 VerifyWebhook 验签。
func (d *Douyin) WebhookEcho(r *http.Request) (string, bool) {
	if r.Method != http.MethodGet {
		return "", false
	}
	echostr := r.URL.Query().Get("echostr")
	return echostr, echostr != ""
}

// ParseOrderCallback 解析 POST 订单回调的包体 msg 为结构化订单信息
// （字段语义见 OrderCallback；包封结构见 orderCallbackEnvelope）。
// 读过的 Body 同样在返回前重置。调用前须先过 VerifyWebhook 验签——本方法只做
// 反序列化，不做任何安全校验。
func (d *Douyin) ParseOrderCallback(r *http.Request) (*OrderCallback, error) {
	raw, err := readAndRestoreBody(r, d.cfg.WebhookMaxBodySize)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opVerifyWebhook, err)
	}
	var env orderCallbackEnvelope
	if err := httpx.DecodeJSON(raw, &env); err != nil {
		return nil, errs.Wrap(PlatformName, opVerifyWebhook, err).
			WithCause(ErrWebhookMalformedRequest)
	}
	var order OrderCallback
	if err := httpx.DecodeJSON([]byte(env.Msg), &order); err != nil {
		return nil, errs.Wrap(PlatformName, opVerifyWebhook, err).
			WithCause(ErrWebhookMalformedRequest)
	}
	return &order, nil
}

// paySign 按官方算法计算回调签名：token / timestamp / nonce / msg 四参数
// 自然序排序 → 无分隔符拼接 → SHA1 → 十六进制小写（算法出处见 VerifyWebhook 注释）。
func paySign(token, timestamp, nonce, msg string) string {
	parts := []string{token, timestamp, nonce, msg}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	return hex.EncodeToString(sum[:])
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
