//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description line：构造器 / 配置 / 能力断言
//2026/6/11
//***************************************************

package line

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "line"

// DefaultBaseURL LINE 开放接口域名。
// 文档：https://developers.line.biz/en/reference/line-login/#verify-id-token
// （2026-06-11 拉取），verify 接口完整地址 https://api.line.me/oauth2/v2.1/verify 。
const DefaultBaseURL = "https://api.line.me"

// 默认值。
const (
	// DefaultWebhookTolerance webhook 事件时间戳容忍窗口默认值。
	// LINE webhook 没有 header 级时间戳，窗口校验作用在事件体的 timestamp 字段
	// （毫秒，见 webhook.go）。官方未给出窗口数值——5 分钟是工程取值，可经
	// Config.WebhookTolerance 调整。
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMaxBodySize webhook 回调体大小上限默认值（1 MiB）。
	// LINE 回调是小 JSON，1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
)

// 编译期断言：LINE 实现的合约子集（Payment / Audit 见 doc.go 的 NEEDS-DOC 说明）。
var (
	_ platform.Provider        = (*Line)(nil)
	_ platform.LoginProvider   = (*Line)(nil)
	_ platform.WebhookVerifier = (*Line)(nil)
)

// Config 是 LINE 平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入（约定 config.Current().Platform.LineChannelID /
// LineChannelSecret，tgf 侧字段待登记），本包绝不直读环境变量、绝不落盘。
type Config struct {
	// ChannelID LINE Login channel 的 Channel ID（必填）。
	// 即 verify 接口请求体的 client_id——官方文档原文 "Expected channel ID."
	// （https://developers.line.biz/en/reference/line-login/#verify-id-token ，
	// 2026-06-11 拉取）。在 LINE Developers Console 的 LINE Login channel 页可见。
	ChannelID string
	// ChannelSecret webhook 验签密钥（用 VerifyWebhook 时必填，仅登录可留空）。
	// 必须是「接收 webhook 的那个 Messaging API channel」的 Channel secret——
	// LINE Login channel 与 Messaging API channel 是两种 channel，凭据各自独立，
	// 若两者不是同一 channel，这里别错填成 Login channel 的 secret（凭据种类
	// 拿错是历史踩坑高发区）。属凭据，须登记启动日志脱敏。
	ChannelSecret string
	// BaseURL 接口域名，默认 DefaultBaseURL；单测注入 httptest 地址用。
	BaseURL string
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
	// WebhookTolerance webhook 事件时间戳容忍窗口，默认 DefaultWebhookTolerance。
	WebhookTolerance time.Duration
	// WebhookMaxBodySize webhook 回调体大小上限（字节），默认 DefaultWebhookMaxBodySize。
	WebhookMaxBodySize int64
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
}

// Line 是 LINE 平台实现，并发安全（构造后配置只读，去重存储自带锁）。
type Line struct {
	cfg Config
	hc  *httpx.Client
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造 LINE 平台实现。ChannelID 缺失时返回错误；ChannelSecret 允许为空
// （仅登录场景），但此时调 VerifyWebhook 会返回配置错误。
func New(cfg Config) (*Line, error) {
	if cfg.ChannelID == "" {
		return nil, errors.New("line: Config.ChannelID 不能为空（LINE Login channel 的 Channel ID）")
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

	// 重试纪律：verify 是无副作用的只读校验（幂等），但失败多为确定性
	// （token 非法/过期），盲目重试无收益——保持 httpx 默认不重试，
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
	return &Line{cfg: cfg, hc: hc, seen: seen, now: time.Now}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// line.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Line {
	l, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return l
}

// Name 实现 platform.Provider。
func (l *Line) Name() string { return PlatformName }

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

// truncate 截断非敏感诊断字段到 n 字节，防错误信息过长。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}
