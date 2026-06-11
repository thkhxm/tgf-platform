//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：构造器 / 配置 / 能力断言
//2026/6/11
//***************************************************

package tiktok

import (
	"errors"
	"net/http"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "tiktok"

// DefaultBaseURL TikTok 开放接口域名。
// 文档：https://developers.tiktok.com/doc/minis-server-apis-overview（2026-06-11
// 经本机代理直连拉取正文核对，本包所有 endpoint 引注同此方式，下同）。
const DefaultBaseURL = "https://open.tiktokapis.com"

// 默认值。
const (
	// DefaultWebhookTolerance webhook 时间戳容忍窗口默认值。
	// 官方（https://developers.tiktok.com/doc/webhooks-verification ，2026-06-11 拉取）
	// 只要求“时间戳过旧应拒绝”，未给出具体窗口数值——5 分钟是工程取值，可经
	// Config.WebhookTolerance 调整。
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// TikTok 回调是小 JSON，1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
)

// 编译期断言：TikTok 实现的合约子集（ContentAuditProvider 不实现，见 doc.go）。
var (
	_ platform.Provider        = (*TikTok)(nil)
	_ platform.LoginProvider   = (*TikTok)(nil)
	_ platform.PaymentProvider = (*TikTok)(nil)
	_ platform.WebhookVerifier = (*TikTok)(nil)
)

// Config 是 TikTok 平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（config.Current().Platform.TiktokAppID /
// TiktokAppSecret），本包绝不直读环境变量、绝不落盘。
type Config struct {
	// ClientKey TikTok 开发者后台的 Client key（必填）。
	// 即 OAuth 请求里的 client_key；对接 tgf 配置项 Platform.TiktokAppID。
	// 注意：TikTok 后台另有一个数字 “App ID”，不是这个字段——别填错（凭据种类
	// 用错是历史踩坑高发区）。
	ClientKey string
	// ClientSecret TikTok 开发者后台的 Client secret（必填）。
	// 即 OAuth 请求里的 client_secret，也是 webhook 验签的 HMAC 密钥；
	// 对接 tgf 配置项 Platform.TiktokAppSecret（启动日志已脱敏）。
	ClientSecret string
	// RedirectURI OAuth 回调地址。
	//   - Login Kit（Web/App OAuth 流程）：必填，且必须与请求授权 code 时一致
	//     （文档：https://developers.tiktok.com/doc/oauth-user-access-token-management ，
	//     2026-06-11 拉取）；
	//   - TikTok Minis / 小游戏（tt.login 拿 code）：留空——官方明确 Minis 流程
	//     在换 token 请求体中省略 redirect_uri（与 code_verifier）
	//     （文档：https://developers.tiktok.com/doc/minis-oauth ，2026-06-11 拉取）。
	RedirectURI string
	// FetchUserInfo VerifyLogin 换到 token 后是否再调 user/info 补取 union_id。
	// 需要应用在 TikTok 后台勾选了相应 user.info scope 且用户授权，否则平台会
	// 返回业务错误（此时 VerifyLogin 整体返回错误，不静默降级）。
	FetchUserInfo bool
	// BaseURL 接口域名，默认 DefaultBaseURL；单测注入 httptest 地址用。
	BaseURL string
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
}

// TikTok 是 TikTok 平台实现，并发安全（构造后配置只读，去重存储自带锁）。
type TikTok struct {
	cfg Config
	hc  *httpx.Client
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造 TikTok 平台实现。ClientKey / ClientSecret 缺失时返回错误。
func New(cfg Config) (*TikTok, error) {
	if cfg.ClientKey == "" {
		return nil, errors.New("tiktok: Config.ClientKey 不能为空（TikTok 后台的 Client key）")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("tiktok: Config.ClientSecret 不能为空（TikTok 后台的 Client secret）")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
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

	// 重试纪律：OAuth code 换 token 是一次性凭据消费（code 用过即作废），
	// 网络层面歧义失败后盲目重试会换来确定性的 invalid_grant——保持 httpx
	// 默认不重试，由上层按 errs.IsRetryable 自行决策。
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
	return &TikTok{cfg: cfg, hc: hc, seen: seen, now: time.Now}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// tiktok.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *TikTok {
	t, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return t
}

// Name 实现 platform.Provider。
func (t *TikTok) Name() string { return PlatformName }
