//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description xiaomi：构造器 / 配置 / 能力断言 / 官方 signature 签名算法（HMAC-SHA1）
//2026/6/11
//***************************************************

package xiaomi

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "xiaomi"

// DefaultBaseURL 小米游戏 SDK 服务端接口域名。
// 文档：《小米游戏渠道服务器升级通知》
// https://dev.mi.com/distribute/doc/details?pId=1559（2026-06-11 拉取）——
// 官方明确 2019-02-25 起服务端接口全部改为 https：
//   - https://mis.migc.xiaomi.com/api/biz/service/queryOrder.do
//   - https://mis.migc.xiaomi.com/api/biz/service/loginvalidate
const DefaultBaseURL = "https://mis.migc.xiaomi.com"

// 默认值。
const (
	// DefaultWebhookTolerance webhook（订单支付结果通知）payTime 容忍窗口默认值。
	// 官方（《小米游戏SDK3.0接入指南》5.3.1，https://dev.mi.com/distribute/doc/details?pId=1616 ，
	// 2026-06-11 拉取）通知重试节奏为「前 10 次每分钟 1 次，10 次后每小时 1 次」，
	// 且未给出重试总时长上限——合法重试可能在支付完成数小时后到达，窗口取太小会
	// 误杀官方重试，故默认放宽到 24h，可经 Config.WebhookTolerance 调整。
	DefaultWebhookTolerance = 24 * time.Hour
	// DefaultCurrency PaymentResult.Currency 默认值。
	// 官方口径 payFee「单位为分，即 0.01 米币」（5.3.1/5.3.2，pId=1616，2026-06-11 拉取），
	// 米币与人民币兑换比例未在该文档载明（NEEDS-DOC，见 doc.go）——默认按 CNY 记账，
	// 可经 Config.Currency 覆盖。
	DefaultCurrency = "CNY"
)

// defaultPayTimeLocation payTime 默认解析时区（北京时间，UTC+8）。
// 官方未注明 payTime 时区（NEEDS-DOC，见 doc.go）；小米游戏联运是中国大陆服务，
// 默认按北京时间解析。用 FixedZone 而非 time.LoadLocation("Asia/Shanghai")，
// 避免对宿主机 tzdata 的依赖（Windows 无系统 zoneinfo 时 LoadLocation 会失败）。
var defaultPayTimeLocation = time.FixedZone("CST", 8*60*60)

// payTimeLayout payTime 字段格式：yyyy-MM-dd HH:mm:ss
// （5.3.1/5.3.2 请求参数说明，pId=1616，2026-06-11 拉取）。
const payTimeLayout = "2006-01-02 15:04:05"

// 编译期断言：小米实现的合约子集（ContentAuditProvider 见 doc.go 的 NEEDS-DOC 说明）。
var (
	_ platform.Provider        = (*Xiaomi)(nil)
	_ platform.LoginProvider   = (*Xiaomi)(nil)
	_ platform.PaymentProvider = (*Xiaomi)(nil)
	_ platform.WebhookVerifier = (*Xiaomi)(nil)
)

// Config 是小米平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（命名约定 config.Platform.XiaomiAppID /
// XiaomiAppSecret，Secret 类字段须登记 sensitiveEnvKeys 日志脱敏），
// 本包绝不直读环境变量、绝不落盘。
type Config struct {
	// AppID 小米开发者站创建游戏获得的游戏 ID（必填）。
	// 即各接口请求参数里的 appId；对接 tgf 配置项 Platform.XiaomiAppID。
	// 注意：小米后台同时下发 AppId / AppKey / AppSecret 三个值——AppKey 是
	// 客户端 SDK 初始化用的，服务端用不到，别填错（凭据种类用错是历史踩坑高发区）。
	AppID string
	// AppSecret 服务器与服务器通信签名密钥（必填）。
	// 即 signature 的 HMAC-SHA1 key（《小米游戏SDK3.0接入指南》5.3.5 / 6.2，
	// https://dev.mi.com/distribute/doc/details?pId=1616 ，2026-06-11 拉取）；
	// 对接 tgf 配置项 Platform.XiaomiAppSecret（启动日志须脱敏）。
	AppSecret string
	// BaseURL 接口域名，默认 DefaultBaseURL；单测注入 httptest 地址用。
	BaseURL string
	// Currency PaymentResult.Currency 取值，默认 DefaultCurrency（"CNY"）。
	// payFee 以"分"（0.01 米币）计，米币↔法币比例见 doc.go NEEDS-DOC。
	Currency string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
	// WebhookTolerance webhook payTime 容忍窗口，默认 DefaultWebhookTolerance（24h）。
	WebhookTolerance time.Duration
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
	// PayTimeLocation payTime 解析时区，默认北京时间（UTC+8，官方未注明时区，
	// 见 doc.go NEEDS-DOC）。
	PayTimeLocation *time.Location
}

// Xiaomi 是小米平台实现，并发安全（构造后配置只读，去重存储自带锁）。
type Xiaomi struct {
	cfg Config
	hc  *httpx.Client
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造小米平台实现。AppID / AppSecret 缺失时返回错误。
func New(cfg Config) (*Xiaomi, error) {
	if cfg.AppID == "" {
		return nil, errors.New("xiaomi: Config.AppID 不能为空（小米开发者站的游戏 AppId）")
	}
	if cfg.AppSecret == "" {
		return nil, errors.New("xiaomi: Config.AppSecret 不能为空（服务器间通信签名密钥）")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.Currency == "" {
		cfg.Currency = DefaultCurrency
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = httpx.DefaultTimeout
	}
	if cfg.WebhookTolerance <= 0 {
		cfg.WebhookTolerance = DefaultWebhookTolerance
	}
	if cfg.PayTimeLocation == nil {
		cfg.PayTimeLocation = defaultPayTimeLocation
	}

	// 重试纪律：loginvalidate（校验类 POST）与 queryOrder.do（GET 查询）虽然语义
	// 幂等，但保持 httpx 默认不重试，由上层按 errs.IsRetryable 自行决策——与
	// 同仓库其它平台实现的纪律一致。
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
	return &Xiaomi{cfg: cfg, hc: hc, seen: seen, now: time.Now}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// xiaomi.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Xiaomi {
	x, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return x
}

// Name 实现 platform.Provider。
func (x *Xiaomi) Name() string { return PlatformName }

// ---------------------------------------------------------------------------
// signature 签名算法（官方 5.3.5 + 6.2）
// ---------------------------------------------------------------------------

// buildSignSource 按官方规则生成待签名字符串。
//
// 文档：《小米游戏SDK3.0接入指南》5.3.5 signature签名方法说明
// https://dev.mi.com/distribute/doc/details?pId=1616（2026-06-11 拉取）：
//  1. 各参数按参数名字母顺序排序（不包含 signature），拼接成
//     par1=val1&par2=val2&par3=val3 ——该串即待签名字符串；
//  2. 没有值的参数不参与签名；
//  3. 参与签名的值必须是字符串原值而非 URLencoding 后的值
//     （官方示例：payTime 含空格原样、productName 用解码后的中文）。
func buildSignSource(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "signature" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(params[k])
	}
	return b.String()
}

// signParams 对参数表生成 signature。
//
// 算法：以 AppSecret 为 key 的 HMAC-SHA1，结果取小写十六进制
// （《小米游戏SDK3.0接入指南》5.3.5 第 2 条 + 6.2 服务器签名函数 Java 参考实现，
// https://dev.mi.com/distribute/doc/details?pId=1616 ，2026-06-11 拉取）。
// core/sign 只内置 HMAC-SHA256/RSA/AES 原语，小米官方算法是 HMAC-SHA1，
// 故在本包按标准库实现。
func (x *Xiaomi) signParams(params map[string]string) string {
	return hmacSHA1Hex([]byte(x.cfg.AppSecret), []byte(buildSignSource(params)))
}

// verifyParams 校验参数表中携带的 signature 是否与 AppSecret 重算结果一致
// （常量时间比较；expectedHex 大小写不敏感，非法 hex 一律失败）。
func (x *Xiaomi) verifyParams(params map[string]string, expectedHex string) bool {
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha1.New, []byte(x.cfg.AppSecret))
	mac.Write([]byte(buildSignSource(params)))
	return hmac.Equal(mac.Sum(nil), expected)
}

// hmacSHA1Hex 计算 HMAC-SHA1，返回小写十六进制串。
func hmacSHA1Hex(key, data []byte) string {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// truncate 截断非敏感诊断字段到 n 字节，防错误信息过长。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}

// ---------------------------------------------------------------------------
// 防重放去重表（单机内存版）
// ---------------------------------------------------------------------------

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
