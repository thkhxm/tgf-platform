//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：构造器 / 配置 / 能力断言 / 共用小工具
//2026/6/11
//***************************************************

package google

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "google"

// 官方 endpoint 默认值。
const (
	// DefaultJWKSURL Google 公钥（JWKS）端点，ID token / Pub/Sub OIDC token 验签共用。
	// 来源：OIDC Discovery 文档（https://accounts.google.com/.well-known/openid-configuration）
	// 的 jwks_uri 元数据值。
	// 文档：https://developers.google.com/identity/openid-connect/openid-connect（2026-06-11 拉取，
	// 文中明确「Google-issued tokens are signed using one of the certificates found at the
	// URI specified in the jwks_uri metadata value」，并给出 Discovery 文档示例
	// jwks_uri = https://www.googleapis.com/oauth2/v3/certs）；
	// 2026-06-11 实抓该端点确认应答格式 {"keys":[{kty:"RSA",alg:"RS256",use:"sig",kid,n,e}]}。
	// 公钥定期轮换，按应答 Cache-Control 缓存（https://developers.google.com/identity/sign-in/web/backend-auth ，
	// 2026-06-11 拉取：「These keys are regularly rotated; examine the Cache-Control header
	// in the response to determine when you should retrieve them again」）。
	DefaultJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

	// DefaultOAuthTokenURL Google OAuth2 token 端点（service account JWT-bearer 流）。
	// 文档：https://developers.google.com/identity/protocols/oauth2/service-account（2026-06-11 拉取）：
	// POST https://oauth2.googleapis.com/token，
	// form 参数 grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer + assertion=<签名 JWT>。
	DefaultOAuthTokenURL = "https://oauth2.googleapis.com/token"

	// DefaultAndroidPublisherBaseURL Play Developer API 域名。
	// 文档：https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products/get
	// （2026-06-11 拉取）。
	DefaultAndroidPublisherBaseURL = "https://androidpublisher.googleapis.com"

	// androidPublisherScope purchases.products.get 要求的 OAuth scope。
	// 文档：https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products/get
	// （2026-06-11 拉取，「Requires the following OAuth scope:
	// https://www.googleapis.com/auth/androidpublisher」）。
	androidPublisherScope = "https://www.googleapis.com/auth/androidpublisher"
)

// 默认值。
const (
	// DefaultClockSkew JWT 时间类 claim（exp / iat）校验的时钟漂移容忍。
	// 官方文档只要求「exp 未过期」（https://developers.google.com/identity/openid-connect/openid-connect ，
	// 2026-06-11 拉取），未给漂移数值——5 分钟是工程取值，可经 Config.ClockSkew 调整。
	DefaultClockSkew = 5 * time.Minute
	// DefaultWebhookDedupTTL webhook messageId 去重窗口默认值。
	// Pub/Sub push 的 OIDC token 寿命 1 小时（https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions ，
	// 2026-06-11 拉取：「The tokens attached to requests sent to push endpoints may be up
	// to an hour old」）——取 2 小时覆盖 token 整个有效期 + 时钟漂移：超窗的重放已被
	// token exp 拦截，两道闸无缝衔接。
	DefaultWebhookDedupTTL = 2 * time.Hour
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// RTDN 通知是小 JSON（base64 后几百字节），1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
)

// 编译期断言：Google 实现的合约子集（ContentAuditProvider 见 doc.go 说明，不实现）。
var (
	_ platform.Provider        = (*Google)(nil)
	_ platform.LoginProvider   = (*Google)(nil)
	_ platform.PaymentProvider = (*Google)(nil)
	_ platform.WebhookVerifier = (*Google)(nil)
)

// Config 是 Google 平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（tgf v2.1.0 的 config.PlatformConfig 尚无
// Google 字段，建议的新增命名见 doc.go），本包绝不直读环境变量、绝不落盘。
//
// 三个能力切面的配置相互独立，只配用到的部分即可（未配置的能力在调用时
// 返回明确错误，不静默降级）：
//   - 登录：ClientIDs（+ 可选 HostedDomain）；
//   - 支付：PackageName + ServiceAccountEmail + ServiceAccountPrivateKeyPEM；
//   - webhook：PubSubAudience + PubSubServiceAccountEmail（+ 可选
//     PubSubVerificationToken；PackageName 配置时顺带核对通知归属）。
type Config struct {
	// ClientIDs 本应用的 OAuth 2.0 Client ID 白名单（必填，登录能力）。
	// ID token 的 aud 必须命中其中之一——多端（Web / Android / iOS）接同一后端时
	// 把各端 client ID 都列上（文档：https://developers.google.com/identity/sign-in/web/backend-auth ，
	// 2026-06-11 拉取：「The value of aud in the ID token is equal to one of your
	// app's client IDs」）。
	ClientIDs []string
	// HostedDomain 可选：要求 ID token 携带 hd claim 且等于本值（仅限定
	// Google Workspace 组织账号时配置；普通消费者账号无 hd claim）。
	// 文档：https://developers.google.com/identity/sign-in/web/backend-auth（2026-06-11 拉取）。
	HostedDomain string

	// PackageName 应用包名（支付能力必填；webhook 能力可选——配置后顺带核对
	// RTDN 通知的 packageName 归属，防串包）。例如 "com.some.thing"。
	PackageName string
	// ServiceAccountEmail service account 的 client_email（支付能力必填）。
	// 即 Play Console 关联的 GCP service account JSON 凭据文件中的 client_email 字段，
	// 作 JWT-bearer 断言的 iss（文档：https://developers.google.com/identity/protocols/oauth2/service-account ，
	// 2026-06-11 拉取）。
	ServiceAccountEmail string
	// ServiceAccountPrivateKeyPEM service account 私钥 PEM 文本（支付能力必填；
	// 凭据，严禁打日志）。即 service account JSON 凭据文件中的 private_key 字段
	// （PKCS#8 PEM），用于 RS256（RSASSA-PKCS1-v1_5 + SHA-256）签 JWT 断言。
	ServiceAccountPrivateKeyPEM string
	// ServiceAccountPrivateKeyID 可选：service account JSON 的 private_key_id，
	// 填入 JWT header 的 kid（官方说明指定错误的 Key ID 时 Google 会遍历该
	// service account 的所有密钥，故可空；文档同上）。
	ServiceAccountPrivateKeyID string

	// PubSubAudience webhook 能力必填：Pub/Sub push 订阅配置的 audience
	// （未显式配置 audience 时默认为 push endpoint URL）。OIDC token 的 aud
	// 必须等于本值（文档：https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions ，
	// 2026-06-11 拉取）。
	PubSubAudience string
	// PubSubServiceAccountEmail webhook 能力必填：push 订阅配置的 service account
	// 邮箱。OIDC token 的 email 必须等于本值且 email_verified 为 true——这是官方
	// 校验步骤的硬要求（同上文档：「Ensure that payload.Email is equal to the
	// expected service account set up in the push subscription settings」）；
	// 缺了它任何 GCP 用户都能为自己的 service account 签出 aud 相同的合法 token。
	PubSubServiceAccountEmail string
	// PubSubVerificationToken 可选：自管共享口令。配置后要求 push 请求的
	// query 参数 token 与之常量时间比对一致（官方示例的附加防线，同上文档）。
	PubSubVerificationToken string

	// JWKSURL Google 公钥端点，默认 DefaultJWKSURL；单测注入 httptest 地址用。
	JWKSURL string
	// OAuthTokenURL OAuth2 token 端点，默认 DefaultOAuthTokenURL；单测注入用。
	// 同时作 JWT-bearer 断言的 aud（默认值即官方要求的
	// https://oauth2.googleapis.com/token）。
	OAuthTokenURL string
	// AndroidPublisherBaseURL Play Developer API 域名，默认
	// DefaultAndroidPublisherBaseURL；单测注入用。
	AndroidPublisherBaseURL string

	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
	// ClockSkew JWT 时间类 claim 校验的时钟漂移容忍，默认 DefaultClockSkew。
	ClockSkew time.Duration
	// WebhookMaxBodySize webhook 回调体大小上限（字节），默认 DefaultWebhookMaxBodySize。
	WebhookMaxBodySize int64
	// WebhookDedupTTL webhook messageId 去重窗口，默认 DefaultWebhookDedupTTL。
	WebhookDedupTTL time.Duration
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
}

// Google 是 Google 平台实现，并发安全（构造后配置只读，JWKS 缓存 / token
// 缓存 / 去重存储自带锁）。
type Google struct {
	cfg  Config
	hc   *httpx.Client
	jwks *jwksCache
	// tokens service account access token 源；未配置支付能力时为 nil。
	tokens *saTokenSource
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造 Google 平台实现。逐能力做 fail-fast 校验：
//   - 三个能力一个都没配 → 报错（空实现没有意义）；
//   - 支付三件套（PackageName / ServiceAccountEmail / ServiceAccountPrivateKeyPEM）
//     配了任一凭据项就必须配齐，且私钥 PEM 必须能解析；
//   - webhook 两件套（PubSubAudience / PubSubServiceAccountEmail）同理。
func New(cfg Config) (*Google, error) {
	loginConfigured := len(cfg.ClientIDs) > 0
	paymentTouched := cfg.ServiceAccountEmail != "" || cfg.ServiceAccountPrivateKeyPEM != ""
	webhookTouched := cfg.PubSubAudience != "" || cfg.PubSubServiceAccountEmail != ""
	if !loginConfigured && !paymentTouched && !webhookTouched {
		return nil, errors.New("google: Config 三个能力（登录/支付/webhook）一个都未配置")
	}

	var priv *rsa.PrivateKey
	if paymentTouched {
		if cfg.ServiceAccountEmail == "" {
			return nil, errors.New("google: 配置了支付能力但 Config.ServiceAccountEmail 为空（service account 的 client_email）")
		}
		if cfg.ServiceAccountPrivateKeyPEM == "" {
			return nil, errors.New("google: 配置了支付能力但 Config.ServiceAccountPrivateKeyPEM 为空（service account 的 private_key）")
		}
		if cfg.PackageName == "" {
			return nil, errors.New("google: 配置了支付能力但 Config.PackageName 为空（purchases.products.get 的路径参数）")
		}
		var err error
		priv, err = sign.ParseRSAPrivateKeyPEM([]byte(cfg.ServiceAccountPrivateKeyPEM))
		if err != nil {
			return nil, errors.New("google: Config.ServiceAccountPrivateKeyPEM 解析失败: " + err.Error())
		}
	}
	if webhookTouched {
		if cfg.PubSubAudience == "" {
			return nil, errors.New("google: 配置了 webhook 能力但 Config.PubSubAudience 为空（push 订阅的 audience）")
		}
		if cfg.PubSubServiceAccountEmail == "" {
			return nil, errors.New("google: 配置了 webhook 能力但 Config.PubSubServiceAccountEmail 为空（push 订阅的 service account 邮箱）")
		}
	}

	if cfg.JWKSURL == "" {
		cfg.JWKSURL = DefaultJWKSURL
	}
	if cfg.OAuthTokenURL == "" {
		cfg.OAuthTokenURL = DefaultOAuthTokenURL
	}
	if cfg.AndroidPublisherBaseURL == "" {
		cfg.AndroidPublisherBaseURL = DefaultAndroidPublisherBaseURL
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = httpx.DefaultTimeout
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = DefaultClockSkew
	}
	if cfg.WebhookMaxBodySize <= 0 {
		cfg.WebhookMaxBodySize = DefaultWebhookMaxBodySize
	}
	if cfg.WebhookDedupTTL <= 0 {
		cfg.WebhookDedupTTL = DefaultWebhookDedupTTL
	}

	// 重试纪律：本包的出站请求全部幂等（JWKS GET / token 换发 / 购买状态 GET），
	// 但仍保持 httpx 默认不重试——暂时性失败统一标 errs.Retryable 由上层决策，
	// 避免在登录/支付关键路径上放大平台故障时的请求量。
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

	g := &Google{cfg: cfg, hc: hc, seen: seen, now: time.Now}
	// 子组件经闭包取 g.now，保证单测改 g.now 后全链路用同一时钟。
	g.jwks = &jwksCache{hc: hc, url: cfg.JWKSURL, now: func() time.Time { return g.now() }}
	if paymentTouched {
		g.tokens = &saTokenSource{
			email:    cfg.ServiceAccountEmail,
			keyID:    cfg.ServiceAccountPrivateKeyID,
			priv:     priv,
			scope:    androidPublisherScope,
			tokenURL: cfg.OAuthTokenURL,
			hc:       hc,
			now:      func() time.Time { return g.now() },
		}
	}
	return g, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// google.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Google {
	g, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return g
}

// Name 实现 platform.Provider。
func (g *Google) Name() string { return PlatformName }

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
