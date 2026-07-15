//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description telegram：构造器 / 配置 / 能力断言
//2026/6/11
//***************************************************

package telegram

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "telegram"

// DefaultBotAPIBaseURL Telegram Bot API 域名。
// 文档：https://core.telegram.org/bots/api#making-requests（2026-06-11 拉取）：
// “All queries to the Telegram Bot API must be served over HTTPS and need to be
// presented in this form: https://api.telegram.org/bot<token>/METHOD_NAME”。
const DefaultBotAPIBaseURL = "https://api.telegram.org"

// 默认值。
const (
	// DefaultAuthMaxAge initData auth_date 新鲜度窗口默认值。
	// 官方（https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app ，
	// 2026-06-11 拉取）只要求“可额外校验 auth_date 防止过期数据”，未给出具体
	// 窗口数值——1 小时是工程取值（登录凭据宜短），可经 Config.AuthMaxAge 调整。
	DefaultAuthMaxAge = time.Hour
	// DefaultWebhookReplayTTL webhook update_id 防重放去重窗口默认值。
	// 官方（https://core.telegram.org/bots/api#setwebhook ，2026-06-11 拉取）的
	// 投递语义是 at-least-once（非 2xx 应答会重试），信封无时间戳字段，故窗口
	// 数值是工程取值，可经 Config.WebhookReplayTTL 调整。
	DefaultWebhookReplayTTL = 10 * time.Minute
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// Telegram Update 是小 JSON，1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
	// DefaultPaymentScanPageSize getStarTransactions 单页条数默认值。
	// 官方（https://core.telegram.org/bots/api#getstartransactions ，2026-06-11 拉取）：
	// limit “Values between 1-100 are accepted. Defaults to 100”。
	DefaultPaymentScanPageSize = 100
	// DefaultPaymentScanMaxPages VerifyPayment 翻页扫描上限默认值（10 页 ×
	// 100 条 = 最多回看 1000 笔交易）。官方未提供按 charge_id 精确查单的接口
	// （getStarTransactions 仅有 offset/limit 顺序翻页），上限防失控扫描；
	// 高流水 bot 请调大 Config.PaymentScanMaxPages 或以 webhook
	// successful_payment 落库为主、本方法作对账兜底。
	DefaultPaymentScanMaxPages = 10
)

// 编译期断言：Telegram 实现的合约子集
// （ContentAuditProvider 不实现，原因见 doc.go 的 NEEDS-DOC 说明）。
var (
	_ platform.Provider        = (*Telegram)(nil)
	_ platform.LoginProvider   = (*Telegram)(nil)
	_ platform.PaymentProvider = (*Telegram)(nil)
	_ platform.WebhookVerifier = (*Telegram)(nil)
)

// Config 是 Telegram 平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（tgf v2.1.0 的 config.PlatformConfig 尚无
// Telegram 字段位——需后续版本补充 TelegramBotToken / TelegramWebhookSecretToken，
// 见 doc.go），本包绝不直读环境变量、绝不落盘。
type Config struct {
	// BotToken @BotFather 颁发的 Bot API token（必填，形如 "123456:ABC-DEF..."）。
	// 双重用途：① initData 验签密钥派生原料（secret_key = HMAC_SHA256(
	// data=bot_token, key="WebAppData")）；② Bot API 调用凭据（拼进 URL path）。
	// 属最高敏感级凭据：严禁打日志、严禁下发客户端。
	BotToken string
	// WebhookSecretToken setWebhook 时指定的 secret_token（VerifyWebhook 必填）。
	// 官方约束（https://core.telegram.org/bots/api#setwebhook ，2026-06-11 拉取）：
	// 1-256 字符，仅允许 A-Z a-z 0-9 _ -；Telegram 会在每个回调请求带
	// “X-Telegram-Bot-Api-Secret-Token” header。留空时 VerifyWebhook 一律
	// fail-closed 拒绝（无校验依据，绝不裸放行）。
	WebhookSecretToken string
	// AuthMaxAge initData auth_date 新鲜度窗口，默认 DefaultAuthMaxAge（1 小时）。
	AuthMaxAge time.Duration
	// TestEnvironment 是否对接 Telegram 测试环境。true 时 Bot API 调用走
	// /bot<token>/test/METHOD_NAME 路径（文档：
	// https://core.telegram.org/bots/webapps#using-bots-in-the-test-environment ，
	// 2026-06-11 拉取），且 VerifyPayment 结果 Sandbox=true。
	TestEnvironment bool
	// BotAPIBaseURL Bot API 域名，默认 DefaultBotAPIBaseURL；单测注入 httptest 地址用。
	BotAPIBaseURL string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
	// WebhookReplayTTL webhook update_id 去重窗口，默认 DefaultWebhookReplayTTL。
	WebhookReplayTTL time.Duration
	// WebhookMaxBodySize webhook 回调体大小上限（字节），默认 DefaultWebhookMaxBodySize。
	WebhookMaxBodySize int64
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
	// PaymentScanPageSize getStarTransactions 单页条数（1-100），默认
	// DefaultPaymentScanPageSize；单测构造分页场景用。
	PaymentScanPageSize int
	// PaymentScanMaxPages VerifyPayment 翻页扫描上限，默认 DefaultPaymentScanMaxPages。
	PaymentScanMaxPages int
}

// Telegram 是 Telegram Mini App 平台实现，并发安全
// （构造后配置只读，去重存储自带锁）。
type Telegram struct {
	cfg Config
	hc  *httpx.Client
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造 Telegram 平台实现。BotToken 缺失时返回错误。
func New(cfg Config) (*Telegram, error) {
	if cfg.BotToken == "" {
		return nil, errors.New("telegram: Config.BotToken 不能为空（@BotFather 颁发的 Bot API token）")
	}
	if cfg.BotAPIBaseURL == "" {
		cfg.BotAPIBaseURL = DefaultBotAPIBaseURL
	}
	if cfg.AuthMaxAge <= 0 {
		cfg.AuthMaxAge = DefaultAuthMaxAge
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = httpx.DefaultTimeout
	}
	if cfg.WebhookReplayTTL <= 0 {
		cfg.WebhookReplayTTL = DefaultWebhookReplayTTL
	}
	if cfg.WebhookMaxBodySize <= 0 {
		cfg.WebhookMaxBodySize = DefaultWebhookMaxBodySize
	}
	if cfg.PaymentScanPageSize <= 0 || cfg.PaymentScanPageSize > 100 {
		cfg.PaymentScanPageSize = DefaultPaymentScanPageSize
	}
	if cfg.PaymentScanMaxPages <= 0 {
		cfg.PaymentScanMaxPages = DefaultPaymentScanMaxPages
	}

	// 重试纪律：getStarTransactions 是只读查询（幂等），但本包保持 httpx 默认
	// 不重试——是否重试由上层按 errs.IsRetryable 自行决策，避免双层重试叠加。
	var hc *httpx.Client
	if cfg.HTTPClient != nil {
		hc = httpx.New(httpx.WithHTTPClient(cfg.HTTPClient))
	} else {
		hc = httpx.New(httpx.WithTimeout(cfg.HTTPTimeout))
	}

	seen := cfg.WebhookSeen
	if seen == nil {
		seen = newMemorySeen().seen
	}
	return &Telegram{cfg: cfg, hc: hc, seen: seen, now: time.Now}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// telegram.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Telegram {
	t, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return t
}

// Name 实现 platform.Provider。
func (t *Telegram) Name() string { return PlatformName }

// botAPIURL 拼接 Bot API 方法的完整 URL。
// 文档：https://core.telegram.org/bots/api#making-requests（2026-06-11 拉取）
// https://api.telegram.org/bot<token>/METHOD_NAME；测试环境为
// /bot<token>/test/METHOD_NAME（https://core.telegram.org/bots/webapps#using-bots-in-the-test-environment ，
// 2026-06-11 拉取）。
func (t *Telegram) botAPIURL(method string) string {
	path := "/bot" + t.cfg.BotToken + "/"
	if t.cfg.TestEnvironment {
		path += "test/"
	}
	return httpx.JoinURL(t.cfg.BotAPIBaseURL, path+method)
}

// truncate 截断非敏感诊断字段到 n 字节，防错误信息过长。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
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
