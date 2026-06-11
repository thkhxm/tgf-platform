//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description steam：构造器 / 配置 / 能力断言 / 订单状态常量
//2026/6/11
//***************************************************

package steam

import (
	"errors"
	"net/http"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "steam"

// DefaultBaseURL Steamworks Web API 的 partner（publisher key）域名。
// 文档：https://partner.steamgames.com/doc/webapi_overview（2026-06-11 拉取）——
// “If you're a publisher, then Steam also provides a partner-only Web API server
// hosted at partner.steam-api.com”；微交易接口要求 publisher key，统一默认走该域。
const DefaultBaseURL = "https://partner.steam-api.com"

// PublicBaseURL Steamworks Web API 公网域名。AuthenticateUserTicket 也可经该域
// 用普通 Web API user key 调用，但官方明确限频（“These requests are rate limited”，
// https://partner.steamgames.com/doc/webapi/ISteamUserAuth ，2026-06-11 拉取）。
// 只用 user key（无 publisher key）的项目可把 Config.BaseURL 设为本值——此时
// 微交易接口不可用（要求 publisher key）。
const PublicBaseURL = "https://api.steampowered.com"

// 微交易订单状态（QueryTxn 等响应的 status 字段取值）。
// 文档：https://partner.steamgames.com/doc/features/microtransactions/implementation
// Appendix A: Status Values（2026-06-11 拉取），逐字对应官方枚举。
const (
	// StatusInit 订单已创建但用户尚未授权。
	StatusInit = "Init"
	// StatusApproved 用户已授权（此时应调 FinalizeTxn 捕获资金）。
	StatusApproved = "Approved"
	// StatusSucceeded 订单已成功处理（唯一允许发货的状态）。
	StatusSucceeded = "Succeeded"
	// StatusFailed 订单失败或被拒绝。
	StatusFailed = "Failed"
	// StatusRefunded 订单已退款，游戏应回收商品。
	StatusRefunded = "Refunded"
	// StatusPartialRefund 购物车内一项或多项已退款，明细看各 item 的 itemstatus。
	StatusPartialRefund = "PartialRefund"
	// StatusChargedback 订单存在欺诈或争议（拒付），游戏应回收商品。
	StatusChargedback = "Chargedback"
	// StatusRefundedSuspectedFraud Valve 因疑似欺诈退款，游戏应回收商品。
	StatusRefundedSuspectedFraud = "RefundedSuspectedFraud"
	// StatusRefundedFriendlyFraud Valve 因友好欺诈退款，游戏应回收商品。
	StatusRefundedFriendlyFraud = "RefundedFriendlyFraud"
)

// IsReversedStatus 报告订单状态是否属于"已逆转"（退款/拒付）状态——官方实现指南
// 要求业务对这些状态执行商品回收（claw-back）：
// “When a transaction enters a reversed state (e.g., Refunded, PartialRefund,
// Chargedback, RefundedSuspectedFraud, or RefundedFriendlyFraud) then your backend
// should attempt to claw-back items associated with the reversed transaction”
// （https://partner.steamgames.com/doc/features/microtransactions/implementation ，
// 2026-06-11 拉取）。
func IsReversedStatus(status string) bool {
	switch status {
	case StatusRefunded, StatusPartialRefund, StatusChargedback,
		StatusRefundedSuspectedFraud, StatusRefundedFriendlyFraud:
		return true
	}
	return false
}

// 编译期断言：Steam 实现的合约子集（Webhook / Audit 不实现，见 doc.go）。
var (
	_ platform.Provider        = (*Steam)(nil)
	_ platform.LoginProvider   = (*Steam)(nil)
	_ platform.PaymentProvider = (*Steam)(nil)
)

// Config 是 Steam 平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（tgf config.PlatformConfig 待登记 Steam 字段，
// 建议命名 SteamAppID / SteamWebAPIKey，见 doc.go），本包绝不直读环境变量、绝不落盘。
type Config struct {
	// AppID 游戏的 Steam AppID（必填）。
	// AuthenticateUserTicket 与微交易接口的 appid 参数（uint32，官方参数表，
	// https://partner.steamgames.com/doc/webapi/ISteamUserAuth ，2026-06-11 拉取）。
	AppID uint32
	// WebAPIKey Steamworks Web API key（必填；凭据，严禁打日志）。
	//   - publisher key：partner.steam-api.com 全部接口可用（微交易接口要求带
	//     Microtransaction 权限的 publisher key）；
	//   - 普通 user key：仅 AuthenticateUserTicket 可用，须把 BaseURL 设为
	//     PublicBaseURL，且官方明确限频。
	// 官方安全要求：publisher key 只能在安全服务器侧使用，绝不能进客户端
	// （“this API MUST be called from a secure server, and can never be used
	// directly by clients!”，https://partner.steamgames.com/doc/webapi/ISteamUserAuth ，
	// 2026-06-11 拉取）。
	WebAPIKey string
	// Identity 客户端调 GetAuthTicketForWebApi(identity) 创建票据时传入的标识串
	// （可选）。官方：“If this identity string is passed, only tickets created with
	// that parameter will successfully authenticate.”（同上文档，2026-06-11 拉取）。
	// 建议设置为自己的服务名以防票据被其它服务复用；留空则不传该参数，此时仅
	// 创建时未带 identity 的票据能通过校验。须与客户端创建票据时的取值一致。
	Identity string
	// Sandbox 微交易是否走沙箱接口 ISteamMicroTxnSandbox（开发/测试期用，
	// 不产生真实交易；官方要求测试期使用，见 doc.go）。仅影响 PaymentProvider
	// 与 FinalizeTxn，不影响登录校验。
	Sandbox bool
	// BaseURL 接口域名，默认 DefaultBaseURL（partner.steam-api.com）；
	// 用普通 user key 时设为 PublicBaseURL；单测注入 httptest 地址用。
	BaseURL string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
}

// Steam 是 Steam 平台实现，并发安全（构造后配置只读）。
type Steam struct {
	cfg Config
	hc  *httpx.Client
}

// New 构造 Steam 平台实现。AppID / WebAPIKey 缺失时返回错误。
func New(cfg Config) (*Steam, error) {
	if cfg.AppID == 0 {
		return nil, errors.New("steam: Config.AppID 不能为 0（游戏的 Steam AppID）")
	}
	if cfg.WebAPIKey == "" {
		return nil, errors.New("steam: Config.WebAPIKey 不能为空（Steamworks Web API key）")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = httpx.DefaultTimeout
	}

	// 重试纪律：FinalizeTxn 是资金捕获，官方明确通信异常后应改用 QueryTxn /
	// GetReport 查状态而非重发（实现指南，2026-06-11 拉取）——保持 httpx 默认
	// 不重试，由上层按 errs.IsRetryable 自行决策（查询类接口幂等可重试）。
	var hc *httpx.Client
	if cfg.HTTPClient != nil {
		hc = httpx.New(httpx.WithHTTPClient(cfg.HTTPClient))
	} else {
		hc = httpx.New(httpx.WithTimeout(cfg.HTTPTimeout))
	}
	return &Steam{cfg: cfg, hc: hc}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// steam.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Steam {
	s, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return s
}

// Name 实现 platform.Provider。
func (s *Steam) Name() string { return PlatformName }

// microTxnInterface 返回微交易接口名：正式 ISteamMicroTxn / 沙箱 ISteamMicroTxnSandbox。
// 官方明确两者协议完全一致、仅接口名不同
// （https://partner.steamgames.com/doc/webapi/ISteamMicroTxnSandbox ，2026-06-11 拉取）。
func (s *Steam) microTxnInterface() string {
	if s.cfg.Sandbox {
		return "ISteamMicroTxnSandbox"
	}
	return "ISteamMicroTxn"
}
