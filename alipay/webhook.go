//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：WebhookVerifier——异步通知 RSA2 验签 + notify_time 时间窗 + notify_id 防重放
//2026/6/11
//***************************************************

package alipay

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, alipay.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookMalformed 通知体不是合法的表单，或缺少 sign / notify_id /
	// notify_time 等必备参数（官方参数表均标注必读）。
	ErrWebhookMalformed = errors.New("alipay: 异步通知格式非法或缺少必备参数")
	// ErrWebhookSignTypeUnsupported sign_type 不是 RSA2（本包仅支持 RSA2，
	// 官方：新建应用仅支持 RSA2）。
	ErrWebhookSignTypeUnsupported = errors.New("alipay: 异步通知 sign_type 不支持（仅支持 RSA2）")
	// ErrWebhookSignatureMismatch 签名比对失败（支付宝公钥不符或参数被篡改）。
	ErrWebhookSignatureMismatch = errors.New("alipay: 异步通知签名比对失败")
	// ErrWebhookAppIDMismatch 通知中的 app_id 与配置不一致（疑似串应用）。
	ErrWebhookAppIDMismatch = errors.New("alipay: 异步通知 app_id 与配置不一致")
	// ErrWebhookTimestampOutOfWindow 签名有效但 notify_time 超出容忍窗口。
	ErrWebhookTimestampOutOfWindow = errors.New("alipay: 异步通知 notify_time 超出容忍窗口")
	// ErrWebhookReplayed 防重放拦截：同一 notify_id 在窗口内重复出现。
	ErrWebhookReplayed = errors.New("alipay: 异步通知重复投递（防重放拦截）")
)

// 操作名（errs.Error.Op）。
const opVerifyWebhook = "verify_webhook"

// VerifyWebhook 实现 platform.WebhookVerifier：校验支付宝异步通知（POST 表单）
// 签名，并按合约硬要求完成时间窗校验 + 重放去重；读过的 Body 在返回前重置，
// 业务 handler 可正常再读。
//
// 验签算法
// 文档：https://opendocs.alipay.com/common/02mse7（2026-06-11 经本机代理直连
// 拉取正文核对；公钥、证书两种模式下异步通知验签方式相同）：
//
//  1. 「在通知返回参数列表中，除去 sign、sign_type 两个参数外，凡是通知返回的
//     参数皆是待验签的参数」（生活号通知需保留 sign_type，见 Config.NotifyKeepSignType）；
//  2. 「将剩下参数进行 url_decode，然后进行字典排序，组成字符串，得到待签名
//     字符串」——本实现用 url.ParseQuery 解析原始 body（解析即完成 url_decode），
//     参数名 ASCII 字典排序后按 key=value 用 & 拼接；
//  3. 「将签名参数（sign）使用 base64 解码为字节码串」，用支付宝公钥按 RSA
//     验签（sign_type=RSA2 即 SHA256WithRSA，仅支持此档）。
//
// 与请求签名的差异（容易踩坑）：通知验签串不排除空值参数——官方原文是「凡是
// 通知返回的参数皆是待验签的参数」，没有请求签名规则（057k53）里「排除空值」
// 一条；本实现照官方原文全量参与。
//
// 防重放
// 通知参数表（https://opendocs.alipay.com/open/203/105286 ，2026-06-11 拉取）
// 定义 notify_id 为「通知校验 ID」（每次通知唯一）、notify_time 为「通知的发送
// 时间」（yyyy-MM-dd HH:mm:ss，按北京时间解析）：
//   - notify_time 超出 Config.WebhookTolerance 窗口（过旧或超前）即拒绝；
//   - 验签通过后以 notify_id 作去重 key，窗口 2×WebhookTolerance，重复即拒绝。
//     单机默认内存去重；多实例部署必须经 Config.WebhookSeen 注入共享存储实现。
//
// 注意：支付宝对未应答 success 的通知会按递增间隔重投（间隔可达小时级）。若
// 业务依赖平台重投兜底，应调大 WebhookTolerance，并经 Config.WebhookSeen 注入
// 与业务消费状态联动的去重实现（仅对已成功消费的 notify_id 判重），或对账兜底
// （VerifyPayment 主动查单）。官方未明示重投是否更新 notify_time / notify_id，
// 真凭据验证时复核（见 STATUS.md）。
//
// 注意：本方法只完成「请求确实来自支付宝（含 app_id 归属核对）且非重放」的
// 校验。业务发货前还须自行核对通知内容与本地订单一致（out_trade_no 匹配、
// total_amount 与下单金额一致、seller_id 归属、trade_status 为 TRADE_SUCCESS /
// TRADE_FINISHED、幂等发货）——这些字段语义见上述官方参数表。
func (a *Alipay) VerifyWebhook(r *http.Request) error {
	// 读原始 body（限量防打爆内存），并立即重置回去（合约硬要求：实现读了
	// Body 必须在返回前重置，否则业务 handler 读不到）。
	raw, err := readAndRestoreBody(r, a.cfg.WebhookMaxBodySize)
	if err != nil {
		return errs.Wrap(PlatformName, opVerifyWebhook, err)
	}
	// 支付宝异步通知是 POST application/x-www-form-urlencoded 表单。
	form, err := url.ParseQuery(string(raw))
	if err != nil || len(form) == 0 {
		return errs.New(PlatformName, opVerifyWebhook, "", "通知体不是合法表单").
			WithCause(ErrWebhookMalformed)
	}

	sigB64 := form.Get("sign")
	if sigB64 == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 sign 参数").
			WithCause(ErrWebhookMalformed)
	}
	// 仅支持 RSA2（SHA256WithRSA）；RSA（SHA1）是历史遗留档，本包不支持。
	if st := form.Get("sign_type"); st != signTypeRSA2 {
		return errs.New(PlatformName, opVerifyWebhook, "", "sign_type 不支持: "+truncate(st, 32)).
			WithCause(ErrWebhookSignTypeUnsupported)
	}

	// 拼待验签串（规则见本方法注释；ParseQuery 已完成 url_decode）。
	if err := sign.RSASHA256VerifyBase64(a.alipayPub, []byte(a.notifySignContent(form)), sigB64); err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名比对失败").
			WithCause(ErrWebhookSignatureMismatch)
	}

	// app_id 归属核对（通知参数表必读字段）：不是发给本应用的通知一律拒绝，
	// 防止同一回调地址被其他应用/伪造报文串用。
	if appID := form.Get("app_id"); appID != a.cfg.AppID {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"app_id 不一致: "+truncate(appID, 64)).
			WithCause(ErrWebhookAppIDMismatch)
	}

	// notify_time 时间窗（官方格式 yyyy-MM-dd HH:mm:ss，北京时间）。
	// notify_time 参与签名，攻击者无法单独篡改。
	notifyTime := form.Get("notify_time")
	if notifyTime == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 notify_time 参数").
			WithCause(ErrWebhookMalformed)
	}
	ts, err := parseAlipayTime(notifyTime)
	if err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "", "notify_time 非法: "+truncate(notifyTime, 32)).
			WithCause(ErrWebhookMalformed)
	}
	delta := a.now().Sub(ts)
	if delta < 0 {
		delta = -delta
	}
	if delta > a.cfg.WebhookTolerance {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"notify_time 超出容忍窗口 "+a.cfg.WebhookTolerance.String()+"（偏差 "+strconv.FormatInt(int64(delta/time.Second), 10)+"s）").
			WithCause(ErrWebhookTimestampOutOfWindow)
	}

	// 防重放去重——只对验签通过的请求记账（垃圾报文进不了去重表）。
	// 去重 key 用官方语义的「通知校验 ID」notify_id；窗口取 2×容忍窗口：窗口
	// 边缘的合法通知过期出表后，其重放已被时间窗拦截，两道闸无缝衔接。
	notifyID := form.Get("notify_id")
	if notifyID == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 notify_id 参数").
			WithCause(ErrWebhookMalformed)
	}
	if a.seen(notifyID, 2*a.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "", "重复投递（防重放拦截）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}

// notifySignContent 拼异步通知待验签串：除 sign（以及 sign_type，除非
// Config.NotifyKeepSignType）外的全部参数按参数名 ASCII 字典排序，
// key=value 用 & 拼接（值为 url_decode 后的原文，不排除空值——规则出处见
// VerifyWebhook 注释）。同名多值参数取首值（官方通知参数表无多值参数）。
func (a *Alipay) notifySignContent(form url.Values) string {
	keys := make([]string, 0, len(form))
	for k := range form {
		if k == "sign" {
			continue
		}
		if k == "sign_type" && !a.cfg.NotifyKeepSignType {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(form.Get(k))
	}
	return b.String()
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
		return nil, errors.New("通知体超过上限 " + strconv.FormatInt(maxSize, 10) + " 字节")
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
// 每次调用顺手清理过期项——条目量与通知速率同阶，线性清理足够。
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
