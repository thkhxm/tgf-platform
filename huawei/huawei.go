//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：构造器 / 配置 / 能力断言 / 官方 endpoint 常量
//2026/6/11
//***************************************************

package huawei

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "huawei"

// 华为帐号（Account Kit）OAuth 服务域名与路径。
const (
	// DefaultOAuthBaseURL 华为帐号服务器 OAuth 域名。
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/account-obtain-token_hms_reference-0000001050048618
	// （2026-06-11 拉取）；openid-configuration（2026-06-11 现网实测）确认
	// token_endpoint / jwks_uri 均在该域名下。
	DefaultOAuthBaseURL = "https://oauth-login.cloud.huawei.com"

	// DefaultOAuthAPIBaseURL 华为帐号开放 API（NSP rest.php）域名，
	// 解析凭证 Access Token（getTokenInfo）用。
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/account-gettokeninfo-0000001050050585
	// （2026-06-11 拉取）
	DefaultOAuthAPIBaseURL = "https://oauth-api.cloud.huawei.com"

	// oauthTokenPath 获取凭证 Access Token（authorization_code / refresh_token /
	// client_credentials 三种 grant_type 共用）。
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/account-obtain-token_hms_reference-0000001050048618
	// 与 https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/open-platform-oauth-0000001053629189
	// （均 2026-06-11 拉取）
	//   - POST https://oauth-login.cloud.huawei.com/oauth2/v3/token
	//   - Content-Type: application/x-www-form-urlencoded
	//   - 失败应答（HTTP 400）：{"error":<int 主错误码>,"sub_error":<int 子错误码>,
	//     "error_description":"..."}，错误码表见
	//     https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/open-platform-error-0000001053869182
	//     （2026-06-11 拉取，如 1101/20155 code 已过期、1101/20156 code 已被消费）
	oauthTokenPath = "/oauth2/v3/token"

	// openidConfigurationPath OIDC 发现文档路径，id_token 本地验签的 jwks_uri 来源。
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/android-scenario-id-token-0000001116078504
	// （2026-06-11 拉取："从 https://oauth-login.cloud.huawei.com/.well-known/openid-configuration
	// 的响应消息体中获取 jwks_uri 的属性值"）；2026-06-11 现网实测返回
	// jwks_uri=https://oauth-login.cloud.huawei.com/oauth2/v3/certs，
	// id_token_signing_alg_values_supported=["RS256","PS256"]。
	openidConfigurationPath = "/.well-known/openid-configuration"

	// getTokenInfoPath 解析凭证 Access Token（NSP 风格接口，含固定查询串）。
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/account-gettokeninfo-0000001050050585
	// （2026-06-11 拉取）
	//   - POST https://oauth-api.cloud.huawei.com/rest.php?nsp_fmt=JSON&nsp_svc=huawei.oauth2.user.getTokenInfo
	//   - form：access_token（需 UrlEncode，url.Values 编码已覆盖）/ open_id=OPENID（固定值，传入才返回 open_id）
	//   - 成功应答：{client_id, expire_in(秒), union_id, open_id, scope}
	//   - 平台层错误经响应头 NSP_STATUS 标识（非 0 即错误，如 6=token 过期、102=无效
	//     SESSION_KEY），见 https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/open-platform-error-0000001053869182
	//     （2026-06-11 拉取）
	getTokenInfoPath = "/rest.php?nsp_fmt=JSON&nsp_svc=huawei.oauth2.user.getTokenInfo"
)

// 华为 IAP 服务端站点（rootUrl）。
// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/api-common-statement-0000001050986127
// （2026-06-11 拉取，"站点信息"小节）。官方说明：任选其一即可（华为服务器会做
// 站点间路由），建议按服务器部署地就近选择。
const (
	// Order 服务（消耗型/非消耗型商品验证）站点。
	OrderSiteChina     = "https://orders-drcn.iap.cloud.huawei.com.cn"
	OrderSiteGermany   = "https://orders-dre.iap.cloud.huawei.eu"
	OrderSiteSingapore = "https://orders-dra.iap.cloud.huawei.asia"
	OrderSiteRussia    = "https://orders-drru.iap.cloud.huawei.ru"

	// Subscription 服务（订阅型商品验证）站点。
	SubscriptionSiteChina     = "https://subscr-drcn.iap.cloud.huawei.com.cn"
	SubscriptionSiteGermany   = "https://subscr-dre.iap.cloud.huawei.eu"
	SubscriptionSiteSingapore = "https://subscr-dra.iap.cloud.huawei.asia"
	SubscriptionSiteRussia    = "https://subscr-drru.iap.cloud.huawei.ru"
)

// CredentialType 是 VerifyLogin 的凭据形态（三种均来自官方文档，见各常量注释）。
type CredentialType string

const (
	// CredentialIDToken credential 为 Account Kit 返回的 ID Token（JWT，默认）。
	// 服务端用 JWKS 公钥本地验签——官方明确：远端 tokeninfo 接口"只能用于调试目的，
	// 在商用环境需采用本地验证的方式"
	// （文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/account-verify-id-token_hms_reference-0000001050050577 ，
	// 2026-06-11 拉取）。
	CredentialIDToken CredentialType = "id_token"
	// CredentialAccessToken credential 为用户级 Access Token，
	// 调 getTokenInfo 解析出 open_id / union_id。
	CredentialAccessToken CredentialType = "access_token"
	// CredentialAuthCode credential 为 Authorization Code（5 分钟有效、一次性），
	// 先经 oauth2/v3/token 换 token，再 getTokenInfo 取 open_id / union_id。
	// 注意官方对 code 编码的提示：部分 SDK 透传服务器返回的 code（HarmonyOS SDK /
	// Web 场景），开发者需先 urlDecode 再传入；Android SDK 返回的 code 已解码。
	// 本实现按"调用方已完成必要的 urlDecode"处理，不做二次解码。
	CredentialAuthCode CredentialType = "code"
)

// 默认值。
const (
	// DefaultJWKSCacheTTL JWKS 公钥缓存时长默认值。官方未规定缓存时长（工程取值，
	// 可经 Config.JWKSCacheTTL 调整）；遇到未知 kid 时会强制刷新一次兜底，密钥
	// 轮换不依赖 TTL 到期。
	DefaultJWKSCacheTTL = 24 * time.Hour
	// DefaultWebhookTolerance webhook（关键事件通知 v2）notifyTime 容忍窗口默认值。
	// 官方未给出具体窗口数值（5 分钟是工程取值，可经 Config.WebhookTolerance 调整）。
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// 官方示例 Content-Length 约 2.7 KB，1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
	// appATExpireMargin 应用级 AT 的提前过期余量：缓存有效期 = expires_in - 余量，
	// 避免拿着临期 AT 调接口刚好撞上过期（官方最佳实践是 401 才重新申请，本实现
	// 同时做主动余量 + 401 被动刷新双保险）。
	appATExpireMargin = 5 * time.Minute
)

// 编译期断言：华为实现的合约子集（ContentAuditProvider 见 doc.go 的说明）。
var (
	_ platform.Provider        = (*Huawei)(nil)
	_ platform.LoginProvider   = (*Huawei)(nil)
	_ platform.PaymentProvider = (*Huawei)(nil)
	_ platform.WebhookVerifier = (*Huawei)(nil)
)

// Config 是华为平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（见 doc.go"凭据"小节），本包绝不直读环境变量、
// 绝不落盘。
type Config struct {
	// ClientID 应用中 OAuth 2.0 客户端 ID（凭据）的 Client ID（必填）。
	// 即华为的 App ID（官方："client id 指的是您的 APP ID"，
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/obtain-application-level-at-0000001051066052 ，
	// 2026-06-11 拉取）。同时用于 id_token 的 aud 校验与 webhook applicationId 核对。
	ClientID string
	// ClientSecret 应用中 OAuth 2.0 客户端 ID（凭据）的 Client Secret（必填）。
	// code 模式换 token 与应用级 AT（client_credentials）申请都用它。
	ClientSecret string
	// CredentialType VerifyLogin 的凭据形态，默认 CredentialIDToken。
	CredentialType CredentialType
	// RedirectURI code 模式（CredentialAuthCode）下换 token 时回传的回调地址。
	// 官方：当 grant_type 为 authorization_code 时"传入获取 Authorization Code 时，
	// 请求中配置的回调地址"——获取 code 时没带 redirect_uri 的场景（如移动端 SDK）
	// 留空即可。其他凭据形态忽略本字段。
	RedirectURI string
	// IAPPublicKey IAP 公钥（AppGallery Connect「查询支付服务信息」获取，base64
	// 编码的 X.509/PKIX DER；也兼容 PEM 封装）。支付应答验签与订阅事件通知验签
	// 必需——官方使用约束："响应体要求使用应用 RSA IAP 公钥进行验证"
	// （文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/api-order-verify-purchase-token-0000001050746113 ，
	// 2026-06-11 拉取）。仅用登录能力时可不配；未配置时 VerifyPayment 与订阅
	// webhook 验签返回错误。
	IAPPublicKey string
	// OrderSiteURL Order 服务站点（rootUrl），默认 OrderSiteChina；
	// 单测注入 httptest 地址用。
	OrderSiteURL string
	// SubscriptionSiteURL Subscription 服务站点（rootUrl），默认 SubscriptionSiteChina。
	SubscriptionSiteURL string
	// OAuthBaseURL 华为帐号 OAuth 域名，默认 DefaultOAuthBaseURL；单测注入用。
	OAuthBaseURL string
	// OAuthAPIBaseURL 华为帐号开放 API（rest.php）域名，默认 DefaultOAuthAPIBaseURL。
	OAuthAPIBaseURL string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	// 注意官方对 IAP 站点的 TLS 要求（TLS ≥ 1.2 与指定加密套件，见
	// api-common-statement 文档"加密套件"小节）——Go 默认 TLS 配置已满足。
	HTTPClient *http.Client
	// JWKSCacheTTL JWKS 公钥缓存时长，默认 DefaultJWKSCacheTTL。
	JWKSCacheTTL time.Duration
	// WebhookTolerance webhook notifyTime 容忍窗口，默认 DefaultWebhookTolerance。
	WebhookTolerance time.Duration
	// WebhookMaxBodySize webhook 回调体大小上限（字节），默认 DefaultWebhookMaxBodySize。
	WebhookMaxBodySize int64
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
}

// Huawei 是华为 HMS 平台实现，并发安全（构造后配置只读；JWKS 缓存、应用级 AT
// 缓存与去重存储自带锁）。
type Huawei struct {
	cfg Config
	hc  *httpx.Client
	// iapPublicKey 解析后的 IAP 公钥（未配置时为 nil）。
	iapPublicKey *rsa.PublicKey
	// jwks JWKS 公钥缓存（id_token 本地验签用）。
	jwks jwksCache
	// appAT 应用级 Access Token 缓存（IAP 服务端接口鉴权用）。
	appAT appATCache
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造华为平台实现。ClientID / ClientSecret 缺失、CredentialType 非法或
// IAPPublicKey 无法解析时返回错误。
func New(cfg Config) (*Huawei, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("huawei: Config.ClientID 不能为空（OAuth 2.0 客户端 ID，即 App ID）")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("huawei: Config.ClientSecret 不能为空（OAuth 2.0 客户端 Client Secret）")
	}
	switch cfg.CredentialType {
	case "":
		cfg.CredentialType = CredentialIDToken
	case CredentialIDToken, CredentialAccessToken, CredentialAuthCode:
	default:
		return nil, fmt.Errorf("huawei: Config.CredentialType 非法：%q（可选 id_token / access_token / code）", cfg.CredentialType)
	}
	if cfg.OAuthBaseURL == "" {
		cfg.OAuthBaseURL = DefaultOAuthBaseURL
	}
	if cfg.OAuthAPIBaseURL == "" {
		cfg.OAuthAPIBaseURL = DefaultOAuthAPIBaseURL
	}
	if cfg.OrderSiteURL == "" {
		cfg.OrderSiteURL = OrderSiteChina
	}
	if cfg.SubscriptionSiteURL == "" {
		cfg.SubscriptionSiteURL = SubscriptionSiteChina
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = httpx.DefaultTimeout
	}
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = DefaultJWKSCacheTTL
	}
	if cfg.WebhookTolerance <= 0 {
		cfg.WebhookTolerance = DefaultWebhookTolerance
	}
	if cfg.WebhookMaxBodySize <= 0 {
		cfg.WebhookMaxBodySize = DefaultWebhookMaxBodySize
	}

	var iapKey *rsa.PublicKey
	if cfg.IAPPublicKey != "" {
		var err error
		iapKey, err = parseIAPPublicKey(cfg.IAPPublicKey)
		if err != nil {
			return nil, fmt.Errorf("huawei: Config.IAPPublicKey 解析失败: %w", err)
		}
	}

	// 重试纪律：authorization code 是一次性凭据（官方错误码 1101/20156：code 已被
	// 消费），支付验证接口幂等性未在官方文档声明——保持 httpx 默认不重试，由上层
	// 按 errs.IsRetryable 自行决策。
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
	return &Huawei{cfg: cfg, hc: hc, iapPublicKey: iapKey, seen: seen, now: time.Now}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// huawei.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Huawei {
	h, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return h
}

// Name 实现 platform.Provider。
func (h *Huawei) Name() string { return PlatformName }

// parseIAPPublicKey 解析 IAP 公钥。AppGallery Connect 下发形态是 base64 的
// X.509/PKIX DER（官方 Java 示例用 X509EncodedKeySpec(Base64.decode(publicKey))，
// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/verifying-signature-returned-result-0000001050033088 ，
// 2026-06-11 拉取）；兼容带 PEM 头尾的封装。
func parseIAPPublicKey(key string) (*rsa.PublicKey, error) {
	if strings.Contains(key, "-----BEGIN") {
		return sign.ParseRSAPublicKeyPEM([]byte(key))
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil {
		return nil, fmt.Errorf("公钥不是合法 base64: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("公钥不是 X.509/PKIX DER 格式: %w", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥不是 RSA 类型（实际 %T）", pub)
	}
	return rsaKey, nil
}

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
