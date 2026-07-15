//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：构造器 / 配置 / 能力断言
//2026/6/11
//***************************************************

package douyin

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "douyin"

// 接口域名。
const (
	// DefaultMinigameBaseURL 抖音小游戏新域名（jscode2session / v2/token）。
	// 文档：https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/server/log-in/code-2-session
	// （2026-06-11 拉取）——“原域名 https://developer.toutiao.com/api/apps/jscode2session
	// 仍然可用，不过为了后续兼容性和可能的迁移，建议开发者更换到新的域名。”
	DefaultMinigameBaseURL = "https://minigame.zijieapi.com"

	// DefaultToutiaoBaseURL 仍挂在原域名下的接口（queryPayState / 内容安全检测）。
	// 这些接口的官方文档（2026-06-11 拉取，见 payment.go / audit.go）给出的 HTTP URL
	// 仍是 developer.toutiao.com，本包严格按文档使用，不自行迁移域名。
	DefaultToutiaoBaseURL = "https://developer.toutiao.com"
)

// 默认值。
const (
	// DefaultWebhookTolerance webhook 时间戳容忍窗口默认值。
	// 官方文档（payment-server-callback，2026-06-11 拉取）未给出时间戳窗口要求——
	// 时间戳窗口是 tgf 合约对 WebhookVerifier 的硬要求，5 分钟是工程取值，
	// 可经 Config.WebhookTolerance 调整。
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// 抖音支付回调是小 JSON，1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
	// DefaultTokenRefreshMargin access_token 提前刷新余量：token 有效期 7200s，
	// 距过期不足该余量即重新获取，防止边缘过期。官方建议“每小时更新一次即可”
	// （get-access-token 文档，2026-06-11 拉取）。
	DefaultTokenRefreshMargin = 5 * time.Minute
)

// 编译期断言：抖音实现的合约子集（四个能力切面全部实现；AuditImage 的平台限制
// 见 audit.go ErrImageBytesUnsupported）。
var (
	_ platform.Provider             = (*Douyin)(nil)
	_ platform.LoginProvider        = (*Douyin)(nil)
	_ platform.PaymentProvider      = (*Douyin)(nil)
	_ platform.ContentAuditProvider = (*Douyin)(nil)
	_ platform.WebhookVerifier      = (*Douyin)(nil)
)

// Config 是抖音小游戏平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（config.Current().Platform.TiktokAppID /
// TiktokAppSecret——tgf 注释明确该配置项即「抖音/TikTok 小游戏 AppID」），
// 本包绝不直读环境变量、绝不落盘。
type Config struct {
	// AppID 小游戏 ID（tt 开头，必填）。
	// 即 jscode2session / v2/token 请求里的 appid；对接 tgf 配置项 Platform.TiktokAppID。
	AppID string
	// AppSecret 小游戏的 APP Secret（必填，开发者后台->开发管理->开发设置）。
	// 即 jscode2session / v2/token 请求里的 secret；对接 tgf 配置项
	// Platform.TiktokAppSecret（启动日志已脱敏）。
	// 官方告诫（code-2-session 文档，2026-06-11 拉取）：只能在开发者服务器使用
	// AppSecret，泄露可能导致小游戏被下架。
	AppSecret string
	// PayCallbackToken 虚拟支付「服务器回调 Token」（开发者平台 商业化->虚拟支付->
	// 支付设置，开发者自定义），VerifyWebhook 的验签密钥。
	// 不使用支付回调能力可留空——留空时 VerifyWebhook 一律返回错误。
	// 注意：它不是 AppSecret，也不是「支付密钥（签名密钥）」（后者用于游戏币
	// 扣除/赠送/查余额接口的 mp_sig，本包未涉及）。
	PayCallbackToken string
	// MinigameBaseURL 新域名接口（jscode2session / v2/token）的 base，
	// 默认 DefaultMinigameBaseURL；单测注入 httptest 地址用。
	MinigameBaseURL string
	// ToutiaoBaseURL 原域名接口（queryPayState / 内容安全检测）的 base，
	// 默认 DefaultToutiaoBaseURL；单测注入 httptest 地址用。
	ToutiaoBaseURL string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
	// WebhookTolerance webhook 时间戳容忍窗口，默认 DefaultWebhookTolerance。
	WebhookTolerance time.Duration
	// WebhookMaxBodySize webhook 回调体大小上限（字节），默认 DefaultWebhookMaxBodySize。
	WebhookMaxBodySize int64
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
	// TokenRefreshMargin access_token 提前刷新余量，默认 DefaultTokenRefreshMargin。
	// 官方明确（get-access-token 文档，2026-06-11 拉取）：token 有效期 2 小时，
	// 重复获取会把上一个 token 的有效期缩短为 5 分钟——所以必须缓存复用，不能每请求都取。
	TokenRefreshMargin time.Duration
}

// Douyin 是抖音小游戏平台实现，并发安全（构造后配置只读，token 缓存与
// 去重存储自带锁）。
type Douyin struct {
	cfg Config
	hc  *httpx.Client
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time

	// access_token 缓存（getAccessToken 是小游戏级 token，全进程共享一份，
	// 见 token.go）。
	tokenMu       sync.Mutex
	token         string
	tokenExpireAt time.Time
}

// New 构造抖音小游戏平台实现。AppID / AppSecret 缺失时返回错误。
func New(cfg Config) (*Douyin, error) {
	if cfg.AppID == "" {
		return nil, errors.New("douyin: Config.AppID 不能为空（小游戏 ID，tt 开头）")
	}
	if cfg.AppSecret == "" {
		return nil, errors.New("douyin: Config.AppSecret 不能为空（小游戏 APP Secret）")
	}
	if cfg.MinigameBaseURL == "" {
		cfg.MinigameBaseURL = DefaultMinigameBaseURL
	}
	if cfg.ToutiaoBaseURL == "" {
		cfg.ToutiaoBaseURL = DefaultToutiaoBaseURL
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = httpx.DefaultTimeout
	}
	if cfg.WebhookTolerance <= 0 {
		cfg.WebhookTolerance = DefaultWebhookTolerance
	}
	if cfg.WebhookMaxBodySize <= 0 {
		cfg.WebhookMaxBodySize = DefaultWebhookMaxBodySize
	}
	if cfg.TokenRefreshMargin <= 0 {
		cfg.TokenRefreshMargin = DefaultTokenRefreshMargin
	}

	// 重试纪律：code 是一次性凭据（官方明确“登录凭证 code，anonymous_code 只能
	// 使用一次”），网络歧义失败后盲目重试同一 code 会换来确定性的 40018——保持
	// httpx 默认不重试，由上层按 errs.IsRetryable 自行决策。
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
	return &Douyin{cfg: cfg, hc: hc, seen: seen, now: time.Now}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// douyin.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Douyin {
	d, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return d
}

// Name 实现 platform.Provider。
func (d *Douyin) Name() string { return PlatformName }

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 其余 4xx 是确定性失败（参数/凭据错误），重试无意义。
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// truncate 截断非敏感诊断字段到 n 字节，防错误信息过长。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}
