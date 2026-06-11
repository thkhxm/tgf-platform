//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：构造器 / 配置 / 能力断言 / 防重放内存去重
//2026/6/11
//***************************************************

package apple

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "apple"

// 官方 endpoint 默认值。
const (
	// DefaultJWKSURL Sign in with Apple 的 JWKS 公钥端点。
	// 文档：https://developer.apple.com/documentation/SignInWithApple/verifying-a-user
	// （2026-06-11 拉取）；本端点 2026-06-11 实抓返回 {"keys":[{kty:"RSA",kid,
	// use:"sig",alg:"RS256",n,e} ×3]}。
	DefaultJWKSURL = "https://appleid.apple.com/auth/keys"

	// DefaultAPIBaseURL App Store Server API 生产环境域名。
	// 文档：https://developer.apple.com/documentation/appstoreserverapi/get-transaction-info
	// （2026-06-11 拉取）：GET https://api.storekit.apple.com/inApps/v1/transactions/{transactionId}
	DefaultAPIBaseURL = "https://api.storekit.apple.com"

	// DefaultSandboxAPIBaseURL App Store Server API 沙箱环境域名。
	// 文档：https://developer.apple.com/documentation/appstoreserverapi
	// （2026-06-11 拉取）："Access the sandbox environment by sending requests
	// to the endpoints using the following base URL: https://api.storekit-sandbox.apple.com/"
	DefaultSandboxAPIBaseURL = "https://api.storekit-sandbox.apple.com"
)

// 默认值。
const (
	// DefaultJWKSCacheTTL JWKS 公钥缓存时长。官方未给出轮换周期，6 小时是工程
	// 取值；遇到未知 kid 时会强制刷新（带最小刷新间隔限流），密钥轮换不受影响。
	DefaultJWKSCacheTTL = 6 * time.Hour
	// DefaultAPITokenTTL App Store Server API 鉴权 JWT 的有效期。官方上限 60 分钟
	// （exp - iat ≤ 60min，文档：
	// https://developer.apple.com/documentation/appstoreserverapi/generating-json-web-tokens-for-api-requests ，
	// 2026-06-11 拉取）；本包每次请求新签一个短时效 token，5 分钟足够。
	DefaultAPITokenTTL = 5 * time.Minute
	// DefaultWebhookTolerance webhook signedDate 时间戳容忍窗口默认值。
	// 官方只说明 signedDate 是"App Store 签名该 JWS 的 UNIX 毫秒时间"
	// （https://developer.apple.com/documentation/appstoreservernotifications/responsebodyv2decodedpayload ，
	// 2026-06-11 拉取），未给出建议窗口——5 分钟是工程取值，可经
	// Config.WebhookTolerance 调整。
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// App Store 通知是小 JSON（单条 JWS），1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
)

// 编译期断言：Apple 实现的合约子集（ContentAuditProvider 不实现，见 doc.go）。
var (
	_ platform.Provider        = (*Apple)(nil)
	_ platform.LoginProvider   = (*Apple)(nil)
	_ platform.PaymentProvider = (*Apple)(nil)
	_ platform.WebhookVerifier = (*Apple)(nil)
)

// Config 是 Apple 平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（KeyID ← Platform.AppleKeyID、
// PrivateKeyP8 ← Platform.ApplePrivateKey），本包绝不直读环境变量、绝不落盘。
type Config struct {
	// ClientID Sign in with Apple 的 client_id（登录能力必填）。
	// 原生 App 流程填 App 的 bundle ID；Web 流程填 Services ID。
	// 它是 identityToken 中 aud 声明的校验值（文档：
	// https://developer.apple.com/documentation/SignInWithApple/verifying-a-user ，
	// 2026-06-11 拉取："Verify that the aud field is the developer's client_id"）。
	ClientID string

	// IssuerID App Store Connect「Users and Access → Keys」页的 Issuer ID
	// （支付能力必填），是 API 鉴权 JWT 的 iss 声明。
	// 文档：https://developer.apple.com/documentation/appstoreserverapi/generating-json-web-tokens-for-api-requests
	// （2026-06-11 拉取）。
	IssuerID string
	// KeyID App Store Connect 下载的 API 私钥的 Key ID（支付能力必填），
	// 是 API 鉴权 JWT 的 header kid。对接 tgf 配置项 Platform.AppleKeyID。
	KeyID string
	// PrivateKeyP8 App Store Connect 下载的 .p8 私钥内容（PEM 文本，
	// ECDSA P-256，支付能力必填）。对接 tgf 配置项 Platform.ApplePrivateKey
	// （启动日志已脱敏）。属凭据，严禁打日志。
	PrivateKeyP8 string
	// BundleID App 的 bundle ID（支付能力必填）。
	//   - 是 API 鉴权 JWT 的 bid 声明（文档同 IssuerID）；
	//   - 也用于核对交易/通知里的 bundleId，防串单（参 Apple 官方
	//     app-store-server-library 的 INVALID_APP_IDENTIFIER 校验）。
	BundleID string

	// NonceCheck 登录 nonce 校验钩子（官方步骤之一："Verify the nonce for the
	// authentication"，文档同 ClientID）。nonce 的期望值由业务的客户端会话产生，
	// 合约的 VerifyLogin 签名无法传入，故以钩子注入：入参是 identityToken 内
	// nonce 声明的值（无该声明时为空串），返回非 nil 即整体校验失败。
	// nil 时跳过 nonce 校验（业务未使用 nonce 的场景）。
	NonceCheck func(nonce string) error

	// JWKSURL Sign in with Apple JWKS 端点，默认 DefaultJWKSURL；单测注入用。
	JWKSURL string
	// APIBaseURL App Store Server API 生产域名，默认 DefaultAPIBaseURL；单测注入用。
	APIBaseURL string
	// SandboxAPIBaseURL App Store Server API 沙箱域名，默认 DefaultSandboxAPIBaseURL；
	// 单测注入用。
	SandboxAPIBaseURL string
	// RootCAs JWS x5c 证书链的信任锚，默认内置 Apple Root CA - G3
	// （见 jws.go）；单测注入自造测试根证书用。
	RootCAs *x509.CertPool

	// JWKSCacheTTL JWKS 公钥缓存时长，默认 DefaultJWKSCacheTTL。
	JWKSCacheTTL time.Duration
	// APITokenTTL API 鉴权 JWT 有效期，默认 DefaultAPITokenTTL（官方上限 60 分钟）。
	APITokenTTL time.Duration
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client

	// WebhookTolerance webhook signedDate 容忍窗口，默认 DefaultWebhookTolerance。
	WebhookTolerance time.Duration
	// WebhookMaxBodySize webhook 回调体大小上限（字节），默认 DefaultWebhookMaxBodySize。
	WebhookMaxBodySize int64
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
}

// Apple 是 Apple 平台实现，并发安全（构造后配置只读，JWKS 缓存与去重存储自带锁）。
type Apple struct {
	cfg Config
	hc  *httpx.Client
	// apiKey App Store Server API 鉴权 JWT 的签名私钥（PrivateKeyP8 解析产物；
	// 未配置支付凭据时为 nil）。
	apiKey *ecdsa.PrivateKey
	// jwks Sign in with Apple 公钥缓存（见 jwks.go）。
	jwks *jwksCache
	// roots JWS x5c 链信任锚（默认 Apple Root CA - G3）。
	roots *x509.CertPool
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造 Apple 平台实现。
// 至少配置一项标识/凭据（登录 ClientID、支付 IssuerID/KeyID/PrivateKeyP8/BundleID、
// 或 webhook-only 场景的 BundleID）；API 凭据三件套（IssuerID/KeyID/PrivateKeyP8）
// 配了任意一个就必须四件套（含 BundleID）配齐——半配是启动期配置错误，fail-fast。
// 只配 BundleID 不触发支付校验（webhook 验签 + bundle 核对不需要 API 凭据）。
func New(cfg Config) (*Apple, error) {
	hasAPICreds := cfg.IssuerID != "" || cfg.KeyID != "" || cfg.PrivateKeyP8 != ""
	if cfg.ClientID == "" && !hasAPICreds && cfg.BundleID == "" {
		return nil, errors.New("apple: 至少配置一组凭据——登录（ClientID）/ 支付（IssuerID/KeyID/PrivateKeyP8/BundleID）/ webhook（BundleID）")
	}
	var apiKey *ecdsa.PrivateKey
	if hasAPICreds {
		var missing []string
		if cfg.IssuerID == "" {
			missing = append(missing, "IssuerID")
		}
		if cfg.KeyID == "" {
			missing = append(missing, "KeyID")
		}
		if cfg.PrivateKeyP8 == "" {
			missing = append(missing, "PrivateKeyP8")
		}
		if cfg.BundleID == "" {
			missing = append(missing, "BundleID")
		}
		if len(missing) > 0 {
			return nil, errors.New("apple: 支付凭据不完整，缺少 " + strings.Join(missing, " / ") +
				"（App Store Server API 需要 IssuerID + KeyID + PrivateKeyP8 + BundleID 四件套）")
		}
		key, err := parseECPrivateKeyPEM([]byte(cfg.PrivateKeyP8))
		if err != nil {
			return nil, errors.New("apple: PrivateKeyP8 解析失败（应为 App Store Connect 下载的 .p8 PEM，ECDSA P-256）: " + err.Error())
		}
		apiKey = key
	}

	if cfg.JWKSURL == "" {
		cfg.JWKSURL = DefaultJWKSURL
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = DefaultAPIBaseURL
	}
	if cfg.SandboxAPIBaseURL == "" {
		cfg.SandboxAPIBaseURL = DefaultSandboxAPIBaseURL
	}
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = DefaultJWKSCacheTTL
	}
	if cfg.APITokenTTL <= 0 || cfg.APITokenTTL > time.Hour {
		// 官方上限 60 分钟（见 DefaultAPITokenTTL 注释），超限按默认收口。
		cfg.APITokenTTL = DefaultAPITokenTTL
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

	roots := cfg.RootCAs
	if roots == nil {
		var err error
		roots, err = appleRootPool()
		if err != nil {
			return nil, err
		}
	}

	// 重试纪律：Get Transaction Info / JWKS 都是只读 GET（幂等），但失败重试
	// 与否的决策权交给上层（errs.IsRetryable），httpx 保持默认不重试。
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
	a := &Apple{
		cfg:    cfg,
		hc:     hc,
		apiKey: apiKey,
		roots:  roots,
		seen:   seen,
		now:    time.Now,
	}
	a.jwks = newJWKSCache(hc, cfg.JWKSURL, cfg.JWKSCacheTTL)
	return a, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// apple.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Apple {
	a, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return a
}

// Name 实现 platform.Provider。
func (a *Apple) Name() string { return PlatformName }

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
