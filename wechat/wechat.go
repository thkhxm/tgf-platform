//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：构造器 / 配置 / 能力断言 / 防重放去重
//2026/6/11
//***************************************************

package wechat

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "wechat"

// DefaultBaseURL 微信开放接口域名。
// 文档：https://developers.weixin.qq.com/minigame/dev/api-backend/login/api_code2session.html
// （2026-06-11 拉取，各服务端接口统一为 https://api.weixin.qq.com）。
const DefaultBaseURL = "https://api.weixin.qq.com"

// 默认值。
const (
	// DefaultWebhookTolerance webhook（消息推送）时间戳容忍窗口默认值。
	// 官方文档（message-push.html，2026-06-11 拉取）只定义 timestamp 参与验签，
	// 未给出窗口数值——5 分钟是工程取值，可经 Config.WebhookTolerance 调整。
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// 微信消息推送是小 JSON/XML，1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
	// DefaultZoneID 米大师分区 ID 默认值（官方请求示例取值 "1"；
	// 实际须与 MP-分区配置一致，见 Config.ZoneID）。
	DefaultZoneID = "1"
)

// 米大师支付环境枚举（Body.env）。
// 文档：https://developers.weixin.qq.com/minigame/dev/api-backend/midas-payment/order/api_pay_v2.queryorder.html
// （2026-06-11 拉取）：0 现网环境（也叫正式环境），1 沙箱环境。
const (
	EnvProduction = 0
	EnvSandbox    = 1
)

// 米大师业务类型枚举（Body.biz_id）。
// 文档同上（2026-06-11 拉取）：1 代币，2 道具直购。
const (
	BizIDCoin  = 1 // 代币（游戏币）
	BizIDGoods = 2 // 道具直购
)

// 内容安全场景枚举（msgSecCheck Body.scene）。
// 文档：https://developers.weixin.qq.com/minigame/dev/api-backend/wxa-sec-check/api_gamemsgseccheck.html
// （2026-06-11 拉取）：1 资料；2 评论；3 论坛；4 社交日志；5 聊天。
// 注意：mediaCheckAsync 的 scene 枚举只有 1-4（无聊天），见 AuditMediaAsync。
const (
	SceneProfile   = 1 // 资料（昵称、签名等）
	SceneComment   = 2 // 评论
	SceneForum     = 3 // 论坛
	SceneSocialLog = 4 // 社交日志
	SceneChat      = 5 // 聊天（仅 msgSecCheck 支持）
)

// 编译期断言：微信实现的合约子集（AuditImage 的特殊语义见 doc.go 与 audit.go）。
var (
	_ platform.Provider             = (*WeChat)(nil)
	_ platform.LoginProvider        = (*WeChat)(nil)
	_ platform.PaymentProvider      = (*WeChat)(nil)
	_ platform.ContentAuditProvider = (*WeChat)(nil)
	_ platform.WebhookVerifier      = (*WeChat)(nil)
)

// Config 是微信小游戏平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（config.Current().Platform.WechatAppID /
// WechatAppSecret），本包绝不直读环境变量、绝不落盘。
type Config struct {
	// AppID 小游戏 AppID（必填）；对接 tgf 配置项 Platform.WechatAppID。
	AppID string
	// AppSecret 小游戏 AppSecret（必填）；对接 tgf 配置项 Platform.WechatAppSecret
	// （启动日志已脱敏）。用于 jscode2session 与 access_token 获取。
	AppSecret string

	// ---- 支付（米大师虚拟支付，VerifyPayment 用；不接支付可全部留空）----

	// OfferID 支付应用 ID（MP-支付基础配置的 OfferId）。
	OfferID string
	// AppKey 现网环境支付 AppKey（MP-支付基础配置）。
	// pay_sig 签名密钥按 env 选取：现网用 AppKey，沙箱用 SandboxAppKey
	// （文档：https://developers.weixin.qq.com/minigame/dev/guide/open-ability/virtual-payment/signature.html ，
	// 2026-06-11 拉取，"app_key 为当前支付环境(env参数)对应的 AppKey"）。
	AppKey string
	// SandboxAppKey 沙箱环境支付 AppKey（Env=EnvSandbox 时必填）。
	SandboxAppKey string
	// Env 支付环境：EnvProduction（0，默认）/ EnvSandbox（1）。
	Env int
	// ZoneID 已发布的分区 ID（MP-分区配置），需与 Env 对应；默认 DefaultZoneID（"1"）。
	ZoneID string
	// BizID 业务类型：BizIDCoin（1 代币）/ BizIDGoods（2 道具直购）。
	// VerifyPayment 必需；可被单笔 receipt.Raw["biz_id"] 覆盖。
	BizID int
	// SessionKeyFunc 按 openid 取该用户当前有效 session_key 的钩子（业务在
	// VerifyLogin 成功后应把 session_key 存入服务端受控存储，此处取回）。
	// 米大师接口的 signature 用 session_key 做 HMAC（不明文传输 session_key，
	// 文档：https://developers.weixin.qq.com/minigame/dev/guide/open-ability/signature.html ，
	// 2026-06-11 拉取）。单笔可用 receipt.Raw["session_key"] 直接传入（优先）。
	SessionKeyFunc func(ctx context.Context, openID string) (string, error)

	// ---- 内容安全（AuditText / AuditMediaAsync 用）----

	// AuditScene AuditText 的场景枚举（Scene* 常量），默认 SceneProfile（1 资料）。
	// 不同 UGC 场景应按官方枚举语义配置（聊天文本应配 SceneChat）。
	AuditScene int

	// ---- webhook（消息推送，VerifyWebhook 用；不接回调可留空）----

	// PushToken MP-开发管理-消息推送配置中的 Token 令牌（VerifyWebhook 必需）。
	PushToken string
	// EncodingAESKey 消息加解密密钥（43 字符；仅 DecryptWebhookEvent 解密
	// 安全模式 Encrypt 密文时必需，验签本身不需要）。
	EncodingAESKey string

	// ---- 通用 ----

	// BaseURL 接口域名，默认 DefaultBaseURL；单测注入 httptest 地址用。
	BaseURL string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
	// AccessTokenFunc 自定义接口调用凭证来源；nil 时用内置 stable_token 管理器
	// （见 token.go）。多实例部署且自建了中心化 token 存储时注入本钩子。
	AccessTokenFunc func(ctx context.Context) (string, error)
	// WebhookTolerance webhook 时间戳容忍窗口，默认 DefaultWebhookTolerance。
	WebhookTolerance time.Duration
	// WebhookMaxBodySize webhook 回调体大小上限（字节），默认 DefaultWebhookMaxBodySize。
	WebhookMaxBodySize int64
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
}

// WeChat 是微信小游戏平台实现，并发安全（构造后配置只读，token 缓存与
// 去重存储自带锁）。
type WeChat struct {
	cfg Config
	hc  *httpx.Client
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
	// token 内置 access_token 缓存（见 token.go）。
	token tokenCache
}

// New 构造微信平台实现。AppID / AppSecret 缺失或枚举字段非法时返回错误；
// 支付/webhook 专属字段在对应方法调用时再做存在性校验（不接该能力可不配）。
func New(cfg Config) (*WeChat, error) {
	if cfg.AppID == "" {
		return nil, errors.New("wechat: Config.AppID 不能为空（小游戏 AppID）")
	}
	if cfg.AppSecret == "" {
		return nil, errors.New("wechat: Config.AppSecret 不能为空（小游戏 AppSecret）")
	}
	if cfg.Env != EnvProduction && cfg.Env != EnvSandbox {
		return nil, errors.New("wechat: Config.Env 非法（只允许 0 现网 / 1 沙箱）")
	}
	if cfg.BizID != 0 && !cfg.BizIDValid() {
		return nil, errors.New("wechat: Config.BizID 非法（只允许 1 代币 / 2 道具直购）")
	}
	if cfg.AuditScene == 0 {
		cfg.AuditScene = SceneProfile
	}
	if cfg.AuditScene < SceneProfile || cfg.AuditScene > SceneChat {
		return nil, errors.New("wechat: Config.AuditScene 非法（官方枚举 1-5）")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = httpx.DefaultTimeout
	}
	if cfg.ZoneID == "" {
		cfg.ZoneID = DefaultZoneID
	}
	if cfg.WebhookTolerance <= 0 {
		cfg.WebhookTolerance = DefaultWebhookTolerance
	}
	if cfg.WebhookMaxBodySize <= 0 {
		cfg.WebhookMaxBodySize = DefaultWebhookMaxBodySize
	}

	// 重试纪律：jscode2session 的 code 是一次性凭据（用过即作废），支付查单虽
	// 幂等但歧义重试由上层按 errs.IsRetryable 决策——保持 httpx 默认不重试。
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
	return &WeChat{cfg: cfg, hc: hc, seen: seen, now: time.Now}, nil
}

// BizIDValid 报告 BizID 是否为官方枚举取值（1 代币 / 2 道具直购）。
func (c Config) BizIDValid() bool {
	return c.BizID == BizIDCoin || c.BizID == BizIDGoods
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// wechat.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *WeChat {
	w, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return w
}

// Name 实现 platform.Provider。
func (w *WeChat) Name() string { return PlatformName }

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 其余 4xx 是确定性失败（参数/凭据错误），重试无意义。
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// truncate 截断字符串到 n 字节（错误信息里附应答片段用，防日志爆量）。
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
