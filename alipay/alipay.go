//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：构造器 / 配置 / OpenAPI v2 网关公共请求 + RSA2 签名与应答验签
//2026/6/11
//***************************************************

package alipay

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// PlatformName 平台标识，与 platform.Provider.Name() 返回值一致。
const PlatformName = "alipay"

// DefaultGatewayURL 支付宝 OpenAPI 生产网关（固定地址）。
// 文档：https://opendocs.alipay.com/common/057k53（2026-06-11 经本机代理直连拉取
// 正文核对，原文「支付宝网关地址固定为 https://openapi.alipay.com/gateway.do」；
// 本包所有 endpoint 引注同此方式，下同）。
const DefaultGatewayURL = "https://openapi.alipay.com/gateway.do"

// SandboxGatewayURL 支付宝沙箱网关。
// 文档：https://opendocs.alipay.com/common/097pw5（2026-06-11 拉取，原文「检查
// 请求的网关地址是否正确，要求：https://openapi-sandbox.dl.alipaydev.com/gateway.do」；
// 老沙箱 openapi.alipaydev.com 已要求升级）。
const SandboxGatewayURL = "https://openapi-sandbox.dl.alipaydev.com/gateway.do"

// 默认值。
const (
	// DefaultWebhookTolerance 异步通知 notify_time 时间窗默认值。
	// 官方（https://opendocs.alipay.com/open/203/105286 ，2026-06-11 拉取）只定义
	// notify_time 为「通知的发送时间」，未给出新鲜度窗口数值——5 分钟是工程取值，
	// 可经 Config.WebhookTolerance 调整。注意支付宝对未应答 success 的通知会按
	// 递增间隔重投（间隔可达小时级）；若依赖平台重投兜底，应调大本窗口
	// （官方未明示重投是否更新 notify_time，真凭据验证时复核，见 STATUS.md）。
	DefaultWebhookTolerance = 5 * time.Minute
	// DefaultWebhookMaxBodySize 异步通知请求体大小上限默认值（1 MiB）。
	// 支付宝通知是小表单（参数表见 203/105286），1 MiB 防异常请求打爆内存。
	DefaultWebhookMaxBodySize = 1 << 20
)

// 公共请求参数固定取值。
// 文档：https://opendocs.alipay.com/apis/api_9/alipay.system.oauth.token 等各接口
// 「公共请求参数」表（2026-06-11 拉取）：format 仅支持 JSON；charset 如 utf-8；
// sign_type 推荐 RSA2（新建应用仅支持 RSA2，见 https://opendocs.alipay.com/common/057k53 ）；
// version 固定 1.0；timestamp 格式 "yyyy-MM-dd HH:mm:ss"。
const (
	formatJSON   = "JSON"
	charsetUTF8  = "utf-8"
	signTypeRSA2 = "RSA2"
	versionV1    = "1.0"
	// timeLayout 即官方 "yyyy-MM-dd HH:mm:ss" 的 Go 写法。
	timeLayout = "2006-01-02 15:04:05"
)

// bizCodeSuccess 业务响应节点的成功码（公共响应参数 code，10000 = 成功；
// 注意 alipay.system.oauth.token 的成功节点不含 code 字段，见 bizError）。
const bizCodeSuccess = "10000"

// cstZone 北京时间（UTC+8）。官方公共参数表只规定 timestamp 格式
// "yyyy-MM-dd HH:mm:ss" 未明示时区（NEEDS-DOC 细节）——按支付宝（境内服务）
// 惯例取北京时间；用 FixedZone 避免依赖系统 tzdata。
var cstZone = time.FixedZone("UTC+8", 8*3600)

// 编译期断言：支付宝实现的合约子集（AuditImage 无官方 server API，恒返回错误，
// 见 doc.go「未实现的能力」）。
var (
	_ platform.Provider             = (*Alipay)(nil)
	_ platform.LoginProvider        = (*Alipay)(nil)
	_ platform.PaymentProvider      = (*Alipay)(nil)
	_ platform.ContentAuditProvider = (*Alipay)(nil)
	_ platform.WebhookVerifier      = (*Alipay)(nil)
)

// Config 是支付宝平台实现的构造配置。
// 凭据由业务侧从 tgf 配置系统传入，本包绝不直读环境变量、绝不落盘。
type Config struct {
	// AppID 支付宝开放平台分配的应用 ID（必填，公共参数 app_id）。
	AppID string
	// AppPrivateKeyPEM 应用私钥 PEM（必填，RSA ≥2048 位，PKCS#1/PKCS#8 均可）。
	// 用于请求签名（RSA2 = SHA256WithRSA，文档 https://opendocs.alipay.com/common/057k53 ，
	// 2026-06-11 拉取）。注意是「应用私钥」，不是支付宝公钥/应用公钥。
	AppPrivateKeyPEM string
	// AlipayPublicKeyPEM 支付宝公钥 PEM（必填，开放平台后台「支付宝公钥」一栏）。
	// 用于同步应答与异步通知验签（文档 https://opendocs.alipay.com/common/02mse7 ，
	// 2026-06-11 拉取）。注意不是应用公钥——拿错验签必失败。
	AlipayPublicKeyPEM string
	// GatewayURL 网关地址，默认 DefaultGatewayURL；沙箱填 SandboxGatewayURL；
	// 单测注入 httptest 地址用。
	GatewayURL string
	// FetchUserInfo VerifyLogin 换到 access_token 后是否再调 alipay.user.info.share
	// 补取昵称/头像/省市/性别。需要用户授权 auth_user scope，未授权时平台返回
	// 业务错误（此时 VerifyLogin 整体返回错误，不静默降级）。
	FetchUserInfo bool
	// HTTPTimeout HTTP 请求超时，默认 httpx.DefaultTimeout（10s）。
	// Config.HTTPClient 非 nil 时忽略本字段（超时由注入的 client 自管）。
	HTTPTimeout time.Duration
	// HTTPClient 注入自定义 *http.Client（代理 / 自定义 TLS 时用），可空。
	HTTPClient *http.Client
	// WebhookTolerance 异步通知 notify_time 时间窗，默认 DefaultWebhookTolerance。
	WebhookTolerance time.Duration
	// WebhookMaxBodySize 异步通知请求体大小上限（字节），默认 DefaultWebhookMaxBodySize。
	WebhookMaxBodySize int64
	// WebhookSeen 防重放去重钩子：key 在 ttl 窗口内已出现过则返回 true（重放），
	// 首次出现需记录并返回 false；实现必须并发安全。nil 时用内置的单机内存实现——
	// 多实例部署必须注入共享存储实现（如 Redis SET NX + EX），否则重放可打到
	// 不同实例绕过去重。
	WebhookSeen func(key string, ttl time.Duration) bool
	// NotifyKeepSignType 异步通知验签串是否保留 sign_type 参数。
	// 官方（https://opendocs.alipay.com/common/02mse7 ，2026-06-11 拉取）：常规
	// 交易通知除去 sign、sign_type；「生活号异步通知组成的待验签串里需要保留
	// sign_type 参数」——接生活号通知时置 true。默认 false（交易通知）。
	NotifyKeepSignType bool
}

// Alipay 是支付宝平台实现，并发安全（构造后配置只读，去重存储自带锁）。
type Alipay struct {
	cfg       Config
	hc        *httpx.Client
	priv      *rsa.PrivateKey
	alipayPub *rsa.PublicKey
	// seen 防重放去重（见 Config.WebhookSeen）。
	seen func(key string, ttl time.Duration) bool
	// now 时钟，默认 time.Now；单测注入固定时钟用。
	now func() time.Time
}

// New 构造支付宝平台实现。AppID / 私钥 / 支付宝公钥缺失或非法时返回错误。
func New(cfg Config) (*Alipay, error) {
	if cfg.AppID == "" {
		return nil, errors.New("alipay: Config.AppID 不能为空（开放平台应用 ID）")
	}
	if cfg.AppPrivateKeyPEM == "" {
		return nil, errors.New("alipay: Config.AppPrivateKeyPEM 不能为空（应用私钥，RSA2 签名用）")
	}
	if cfg.AlipayPublicKeyPEM == "" {
		return nil, errors.New("alipay: Config.AlipayPublicKeyPEM 不能为空（支付宝公钥，应答/通知验签用）")
	}
	priv, err := sign.ParseRSAPrivateKeyPEM([]byte(cfg.AppPrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("alipay: 应用私钥解析失败: %w", err)
	}
	pub, err := sign.ParseRSAPublicKeyPEM([]byte(cfg.AlipayPublicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("alipay: 支付宝公钥解析失败: %w", err)
	}
	if cfg.GatewayURL == "" {
		cfg.GatewayURL = DefaultGatewayURL
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

	// 重试纪律：auth_code 是一次性凭据（消费过即作废），网络歧义失败后盲目重试
	// 会换来确定性的 isv.code-invalid——保持 httpx 默认不重试，由上层按
	// errs.IsRetryable 自行决策。
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
	return &Alipay{cfg: cfg, hc: hc, priv: priv, alipayPub: pub, seen: seen, now: time.Now}, nil
}

// MustNew 同 New，配置非法时 panic——供 rpc.NewRPCServer().WithPlatform(
// alipay.MustNew(cfg)) 这类启动期链式调用使用（启动期配置错误就该快速失败）。
func MustNew(cfg Config) *Alipay {
	a, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return a
}

// Name 实现 platform.Provider。
func (a *Alipay) Name() string { return PlatformName }

// sandbox 报告当前网关是否指向沙箱环境（域名含 alipaydev，见 SandboxGatewayURL）。
func (a *Alipay) sandbox() bool {
	return strings.Contains(a.cfg.GatewayURL, "alipaydev")
}

// publicParams 构造公共请求参数（不含 sign；取值依据见常量注释）。
func (a *Alipay) publicParams(method string) map[string]string {
	return map[string]string{
		"app_id":    a.cfg.AppID,
		"method":    method,
		"format":    formatJSON,
		"charset":   charsetUTF8,
		"sign_type": signTypeRSA2,
		"timestamp": a.now().In(cstZone).Format(timeLayout),
		"version":   versionV1,
	}
}

// signContent 按官方规则拼请求待签名串。
// 文档：https://opendocs.alipay.com/common/057k53（2026-06-11 拉取）：
//  1. 取所有请求参数（公共参数 + 业务参数）；
//  2. 排除 sign 字段、值为空（空白字符 / null）的参数、二进制数据；
//  3. 按参数名 ASCII 升序排序；
//  4. 按 key=value 用 & 拼接（值用原文，不做 URL 编码——编码只发生在发送时）。
func signContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || strings.TrimSpace(v) == "" {
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

// gatewayCommonResp 各接口业务响应节点共有的公共响应参数。
// 文档：各接口「公共响应参数」表（2026-06-11 拉取）：code 网关返回码 / msg 描述
// / sub_code 业务返回码 / sub_msg 业务返回码描述。
type gatewayCommonResp struct {
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	SubCode string `json:"sub_code"`
	SubMsg  string `json:"sub_msg"`
}

// bizError 把业务响应节点的公共错误字段映射为平台错误；成功（code == 10000，
// 或节点不含 code——alipay.system.oauth.token 的成功节点无 code 字段，见其
// 响应示例）返回 nil。错误码优先透传 sub_code（业务码），无则用 code（网关码）。
func bizError(op string, httpStatus int, c gatewayCommonResp) *errs.Error {
	if c.Code == "" || c.Code == bizCodeSuccess {
		return nil
	}
	code := c.SubCode
	if code == "" {
		code = c.Code
	}
	msg := c.SubMsg
	if msg == "" {
		msg = c.Msg
	}
	return errs.New(PlatformName, op, code, msg).
		WithHTTPStatus(httpStatus).
		WithRetryable(retryableBizCode(code))
}

// retryableBizCode 报告业务错误码是否属暂时性失败。
// 取值依据各接口「业务错误码」表的官方解决方案（2026-06-11 拉取）：
// isp.unknow-error（重试）、SYSTEM_ERROR（用同样的请求发起重试）、
// ACQ.SYSTEM_ERROR（重新发起请求）。其余（参数错、凭据错、订单不存在等）是
// 确定性失败，重试无意义。
func retryableBizCode(code string) bool {
	switch code {
	case "isp.unknow-error", "SYSTEM_ERROR", "ACQ.SYSTEM_ERROR":
		return true
	}
	return false
}

// respNodeKey 由接口名推导业务响应节点 key：method 的 "." 换 "_" 后缀 "_response"
// （各接口响应示例确认，如 alipay.system.oauth.token → alipay_system_oauth_token_response）。
func respNodeKey(method string) string {
	return strings.ReplaceAll(method, ".", "_") + "_response"
}

// errorResponseKey 网关级错误的响应节点（公共错误，如签名错、app_id 非法）。
const errorResponseKey = "error_response"

// callGateway 完成一次 OpenAPI v2 网关调用的全部公共流程：
// 拼公共参数 → RSA2 签名 → POST 网关 → 解析顶层 JSON → 业务节点验签 → 返回节点原文。
//
// 参数摆放按官方要求（https://opendocs.alipay.com/common/057k53 ，2026-06-11 拉取，
// 原文「请将参数拆分两个部分，对于业务参数（例如 biz_content）部分请设置在 HTTP
// body 中，对于其他平台参数（特别是 charset）请设置在 URL 的 query 中」）：
// 公共参数 + sign 进 query，业务参数（biz_content / grant_type / auth_token 等）
// 进 x-www-form-urlencoded body（multipart 仅文件上传类接口需要，本包无此类接口）。
// 签名覆盖 query + body 的全部参数。
//
// 应答验签按官方规则（https://opendocs.alipay.com/common/02mse7 ，2026-06-11 拉取）：
// 只对 xxx_response 节点的原始 JSON 值（含首尾 {}、含双引号）验签——本实现用
// json.RawMessage 取应答原文切片，绝不反序列化再序列化（字段顺序/空白差异会让
// 签名永远对不上）。
func (a *Alipay) callGateway(ctx context.Context, op, method string, bizParams map[string]string) (json.RawMessage, int, error) {
	pub := a.publicParams(method)
	all := make(map[string]string, len(pub)+len(bizParams))
	for k, v := range pub {
		all[k] = v
	}
	for k, v := range bizParams {
		all[k] = v
	}
	sig, err := sign.RSASHA256SignBase64(a.priv, []byte(signContent(all)))
	if err != nil {
		return nil, 0, errs.Wrap(PlatformName, op, err)
	}

	query := url.Values{}
	for k, v := range pub {
		if v != "" {
			query.Set(k, v)
		}
	}
	query.Set("sign", sig)
	form := url.Values{}
	for k, v := range bizParams {
		if v != "" {
			form.Set(k, v)
		}
	}

	gatewayURL := a.cfg.GatewayURL + "?" + query.Encode()
	resp, err := a.hc.PostForm(ctx, gatewayURL, form, nil)
	if err != nil {
		// 传输层失败（网络错误/超时）——标记可重试；一次性凭据（auth_code）场景
		// 是否真重试由上层决策。
		return nil, 0, errs.Wrap(PlatformName, op, err).WithRetryable(true)
	}

	var top map[string]json.RawMessage
	if err := resp.JSON(&top); err != nil {
		return nil, resp.StatusCode, errs.Wrap(PlatformName, op, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	// 网关级错误（error_response）：签名错、app_id 非法、method 不存在等。
	// 失败路径不授予任何权益，且官方验签文档只规定对 xxx_response 节点验签，
	// 故此处直接透传错误不验签。
	if raw, ok := top[errorResponseKey]; ok {
		var e gatewayCommonResp
		_ = json.Unmarshal(raw, &e)
		code := e.SubCode
		if code == "" {
			code = e.Code
		}
		msg := e.SubMsg
		if msg == "" {
			msg = e.Msg
		}
		return nil, resp.StatusCode, errs.New(PlatformName, op, code, msg).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableBizCode(code) || retryableStatus(resp.StatusCode))
	}

	nodeKey := respNodeKey(method)
	node, ok := top[nodeKey]
	if !ok {
		return nil, resp.StatusCode, errs.New(PlatformName, op, "",
			"应答缺少 "+nodeKey+" 节点: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	// 业务节点必须带签名且验签通过——拒绝信任未签名应答（防中间人篡改）。
	var sigB64 string
	if raw, ok := top["sign"]; ok {
		_ = json.Unmarshal(raw, &sigB64)
	}
	if sigB64 == "" {
		return nil, resp.StatusCode, errs.New(PlatformName, op, "",
			"应答缺少 sign 字段，拒绝信任: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}
	if err := a.verifyResponseSign(node, sigB64); err != nil {
		return nil, resp.StatusCode, errs.New(PlatformName, op, "",
			"应答验签失败（支付宝公钥不符或报文被篡改）").
			WithHTTPStatus(resp.StatusCode).
			WithCause(err)
	}
	return node, resp.StatusCode, nil
}

// verifyResponseSign 用支付宝公钥校验业务响应节点签名（RSA2 / SHA256WithRSA）。
// 待验签内容是节点的原始 JSON 串（含首尾 {} 与双引号，官方 02mse7 明确）。
// 官方另提示：字符串含 http:// 的正斜杠时签名可能按转义形态计算——「建议验签
// 不通过时将正斜杠转义一次后再做一次验签」，故失败后按转义/反转义两个变体重验。
func (a *Alipay) verifyResponseSign(node []byte, sigB64 string) error {
	err := sign.RSASHA256VerifyBase64(a.alipayPub, node, sigB64)
	if err == nil {
		return nil
	}
	// 变体一：把 / 转义成 \/ 再验（官方建议的兜底）。
	escaped := bytes.ReplaceAll(node, []byte(`/`), []byte(`\/`))
	if !bytes.Equal(escaped, node) {
		if sign.RSASHA256VerifyBase64(a.alipayPub, escaped, sigB64) == nil {
			return nil
		}
	}
	// 变体二：把 \/ 反转义成 / 再验（对称兜底：上游可能已做过一次转义）。
	unescaped := bytes.ReplaceAll(node, []byte(`\/`), []byte(`/`))
	if !bytes.Equal(unescaped, node) {
		if sign.RSASHA256VerifyBase64(a.alipayPub, unescaped, sigB64) == nil {
			return nil
		}
	}
	return err
}

// flexString 容错字符串：官方字段表声明 String 且响应示例带引号（如
// alipay.system.oauth.token 的 expires_in 示例 "3600"），但部分接口/版本实际
// 返回 JSON number——两种形态都接受，数字原样转为字符串。
type flexString string

// UnmarshalJSON 实现 json.Unmarshaler。
func (f *flexString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*f = ""
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	*f = flexString(data)
	return nil
}

// yuanToFen 把官方金额串（人民币元，最多两位小数，如 "88.88"）换算为「分」。
// 单位纪律（合约 PaymentReceipt.Amount 注释 + 实战教训）：支付宝接口金额单位是
// 「元」（trade.query total_amount 描述「单位为元，两位小数」，2026-06-11 拉取），
// 合约单位是最小货币单位「分」——必须精确换算，用十进制字符串运算，绝不过 float。
func yuanToFen(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("金额为空")
	}
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	intPart, fracPart, hasDot := strings.Cut(s, ".")
	if intPart == "" {
		intPart = "0"
	}
	if hasDot && fracPart == "" {
		return 0, fmt.Errorf("金额格式非法: %q", s)
	}
	if len(fracPart) > 2 {
		return 0, fmt.Errorf("金额小数位超过两位: %q", s)
	}
	for len(fracPart) < 2 {
		fracPart += "0"
	}
	yuan, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("金额整数部分非法: %q", s)
	}
	fen, err := strconv.ParseInt(fracPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("金额小数部分非法: %q", s)
	}
	if yuan > ((1<<63-1)-fen)/100 {
		return 0, fmt.Errorf("金额溢出: %q", s)
	}
	total := yuan*100 + fen
	if neg {
		total = -total
	}
	return total, nil
}

// parseAlipayTime 解析官方 "yyyy-MM-dd HH:mm:ss" 时间串（按北京时间，见 cstZone）。
func parseAlipayTime(s string) (time.Time, error) {
	return time.ParseInLocation(timeLayout, s, cstZone)
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
