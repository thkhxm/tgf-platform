//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description taptap：构造器 / 配置 / 能力断言
//2026/6/11
//***************************************************

package taptap

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "taptap"

// 接口域名。
// 文档：https://developer.taptap.cn/docs/sdk/taptap-login/taptap-oauth/
// （2026-06-11 拉取）：“以下接口均为国内示例。当移动端初始化为海外时，登录即为
// 海外，以下服务端文档流程不变，将示例中的请求域名 open.tapapis.cn 更换为海外
// 域名 open.tapapis.com 即可。”
const (
	// DefaultBaseURL 国内接口域名（默认）。
	DefaultBaseURL = "https://open.tapapis.cn"
	// DefaultBaseURLOverseas 海外接口域名（移动端初始化为海外时使用，
	// 经 Config.BaseURL 显式指定）。
	DefaultBaseURLOverseas = "https://open.tapapis.com"
)

// 编译期断言：TapTap 实现的合约子集（Payment / Webhook / Audit 的 NEEDS-DOC
// 说明见 doc.go）。
var (
	_ platform.Provider      = (*TapTap)(nil)
	_ platform.LoginProvider = (*TapTap)(nil)
)

// Config 是 TapTap 平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（config.PlatformConfig 暂无 TapTap 字段，
// 建议框架侧补充 TaptapClientID 配置位，见 doc.go），本包绝不直读环境变量、
// 绝不落盘。
type Config struct {
	// ClientID TapTap 开发者中心的 Client ID（必填）。
	// 即账户接口的 client_id 请求参数，官方要求“应与约定相同”
	// （文档：https://developer.taptap.cn/docs/sdk/taptap-login/taptap-oauth/ ，
	// 2026-06-11 拉取）。
	// 注意：TapTap 服务端验证不需要控制台的 Server Secret——签算密钥 mac_key
	// 来自客户端上传的 Access Token，两者是不同的值（官方文档明确提示）。
	ClientID string
	// UseProfileAPI 是否改调 /account/profile/v1 详细信息接口。
	//   - false（默认）：调 /account/basic-info/v1（basic_info scope 即可，
	//     返回 openid / unionid，已满足 PlatformIdentity 全部字段）；
	//   - true：调 /account/profile/v1（要求移动端授权 public_profile scope，
	//     额外把 name / avatar 透传进 PlatformIdentity.Raw）。scope 不足时平台
	//     返回 insufficient_scope 业务错误，VerifyLogin 整体失败，不静默降级。
	UseProfileAPI bool
	// BaseURL 接口域名，默认 DefaultBaseURL（国内）；海外应用填
	// DefaultBaseURLOverseas；单测注入 httptest 地址用。
	// 只允许 scheme://host[:port] 形式（不能带路径/查询）——MAC 签算的 uri
	// 假设接口路径直接挂在根（与官方示例一致）。
	BaseURL string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
}

// TapTap 是 TapTap 平台实现，并发安全（构造后配置只读）。
type TapTap struct {
	cfg Config
	hc  *httpx.Client
	// host / port 是 MAC 签算用的请求域名与端口（构造期从 BaseURL 解析，
	// 端口缺省按 scheme 取 443 / 80——与官方 Node.js 示例
	// `parsedUrl.port || (https ? '443' : '80')` 一致）。
	host string
	port string
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
	// nonce 随机串生成器，默认 crypto/rand；单测注入固定值用。
	nonce func() (string, error)
}

// New 构造 TapTap 平台实现。ClientID 缺失或 BaseURL 非法时返回错误。
func New(cfg Config) (*TapTap, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("taptap: Config.ClientID 不能为空（TapTap 开发者中心的 Client ID）")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, errors.New("taptap: Config.BaseURL 非法: " + err.Error())
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("taptap: Config.BaseURL scheme 必须是 http(s): " + cfg.BaseURL)
	}
	if u.Hostname() == "" {
		return nil, errors.New("taptap: Config.BaseURL 缺少 host: " + cfg.BaseURL)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("taptap: Config.BaseURL 只允许 scheme://host[:port] 形式（MAC 签算的 uri 假设接口路径挂在根）: " + cfg.BaseURL)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = httpx.DefaultTimeout
	}
	// 重试纪律：账户信息接口是 GET 查询（幂等），但官方对 server_error 的建议是
	// “可稍等后重试、最多 3 次”——重试节奏由上层按 errs.IsRetryable 决策，
	// httpx 层保持默认不重试（与 tiktok 实现同一纪律）。
	var hc *httpx.Client
	if cfg.HTTPClient != nil {
		hc = httpx.New(httpx.WithHTTPClient(cfg.HTTPClient))
	} else {
		hc = httpx.New(httpx.WithTimeout(cfg.HTTPTimeout))
	}

	return &TapTap{
		cfg:   cfg,
		hc:    hc,
		host:  u.Hostname(),
		port:  port,
		now:   time.Now,
		nonce: func() (string, error) { return randomNonce(defaultNonceLength) },
	}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// taptap.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *TapTap {
	t, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return t
}

// Name 实现 platform.Provider。
func (t *TapTap) Name() string { return PlatformName }
