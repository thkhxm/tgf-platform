//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description facebook：构造器 / 配置 / 能力断言
//2026/6/11
//***************************************************

package facebook

import (
	"errors"
	"net/http"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "facebook"

// DefaultBaseURL Graph API 域名。
// 文档：https://developers.facebook.com/docs/graph-api/reference/debug_token/
// （2026-06-11 拉取，"Host: graph.facebook.com"）。
const DefaultBaseURL = "https://graph.facebook.com"

// DefaultGraphVersion Graph API 默认版本。
// 文档：https://developers.facebook.com/docs/graph-api/reference/debug_token/
// （2026-06-11 拉取，官方 reference 当前示例为 "GET /v25.0/debug_token..."）。
const DefaultGraphVersion = "v25.0"

// 默认值。
const (
	// DefaultWebhookTolerance webhook 时间戳容忍窗口默认值。
	// Facebook webhook 协议无独立时间戳 header，仅事件载荷 entry[].time 可用
	// （文档：https://developers.facebook.com/docs/graph-api/webhooks/getting-started ，
	// 2026-06-11 拉取，官方未给出窗口数值）——5 分钟是工程取值，可经
	// Config.WebhookTolerance 调整。
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// 官方说明单次投递最多聚合 1000 条更新（文档同上），1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
)

// 编译期断言：Facebook 实现的合约子集（ContentAuditProvider 见 doc.go 的
// NEEDS-DOC 说明）。
var (
	_ platform.Provider        = (*Facebook)(nil)
	_ platform.LoginProvider   = (*Facebook)(nil)
	_ platform.PaymentProvider = (*Facebook)(nil)
	_ platform.WebhookVerifier = (*Facebook)(nil)
)

// Config 是 Facebook 平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（config.Current().Platform.FacebookAppID /
// FacebookAppSecret），本包绝不直读环境变量、绝不落盘。
type Config struct {
	// AppID Meta App Dashboard 的 App ID（必填）。
	// 对接 tgf 配置项 Platform.FacebookAppID。debug_token 应答的 app_id 与
	// 支付 signedRequest 载荷的 app_id 都会与它核对，防止他人应用的凭据串号。
	AppID string
	// AppSecret Meta App Dashboard（Settings > Basic）的 App Secret（必填）。
	// 同时承担三处职责（均为官方协议要求，见各文件注释）：
	//   - app access token 的 "app_id|app_secret" 形式与 appsecret_proof 计算；
	//   - Instant Games signedRequest 验签的 HMAC 密钥；
	//   - webhook X-Hub-Signature-256 验签的 HMAC 密钥。
	// 对接 tgf 配置项 Platform.FacebookAppSecret（启动日志已脱敏）。
	AppSecret string
	// GraphVersion Graph API 版本（形如 "v25.0"），默认 DefaultGraphVersion。
	GraphVersion string
	// FetchUserInfo VerifyLogin 校验通过后是否再调 /me 补取昵称（name）。
	// public_profile 权限即可读 id / name（文档：
	// https://developers.facebook.com/docs/graph-api/reference/v19.0/user ，
	// 2026-06-11 拉取）。失败时 VerifyLogin 整体返回错误，不静默降级。
	FetchUserInfo bool
	// BaseURL 接口域名，默认 DefaultBaseURL；单测注入 httptest 地址用。
	BaseURL string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
	// WebhookVerifyToken Webhooks 订阅核验（GET Verification Request）的
	// Verify Token，须与 App Dashboard Webhooks 配置里设置的字符串一致
	// （文档：https://developers.facebook.com/docs/graph-api/webhooks/getting-started ，
	// 2026-06-11 拉取）。留空表示不接受 GET 核验请求（VerifyWebhook 对 GET 报错）。
	WebhookVerifyToken string
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

// Facebook 是 Facebook 平台实现，并发安全（构造后配置只读，去重存储自带锁）。
type Facebook struct {
	cfg Config
	hc  *httpx.Client
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造 Facebook 平台实现。AppID / AppSecret 缺失时返回错误。
func New(cfg Config) (*Facebook, error) {
	if cfg.AppID == "" {
		return nil, errors.New("facebook: Config.AppID 不能为空（Meta App Dashboard 的 App ID）")
	}
	if cfg.AppSecret == "" {
		return nil, errors.New("facebook: Config.AppSecret 不能为空（Meta App Dashboard 的 App Secret）")
	}
	if cfg.GraphVersion == "" {
		cfg.GraphVersion = DefaultGraphVersion
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

	// 重试纪律：debug_token / me 都是幂等 GET，但限频（官方错误码 4 / 17）下
	// 盲目原地重试只会加剧限频——保持 httpx 默认不重试，错误带 Retryable 标记
	// 由上层按 errs.IsRetryable 自行决策。
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
	return &Facebook{cfg: cfg, hc: hc, seen: seen, now: time.Now}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// facebook.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Facebook {
	f, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return f
}

// Name 实现 platform.Provider。
func (f *Facebook) Name() string { return PlatformName }
