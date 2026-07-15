//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/httpx：带超时 / 重试 / 上下文的 HTTP client 封装——平台 API 调用统一出口
//2026/6/11
//***************************************************

// Package httpx 是平台实现调用第三方 API 的统一 HTTP 出口：
//   - 超时：client 级默认超时 + 每请求 context 双层控制；
//   - 重试：可选的指数退避重试（默认**关闭**——支付类非幂等接口盲目重试
//     可能造成重复下单，必须由平台实现按接口幂等性显式开启，见 WithRetry）；
//   - 解析：Response.JSON / DecodeJSON 带上下文信息的反序列化 helper；
//   - 防御：响应体大小上限（默认 10 MiB），防异常应答打爆内存。
//
// 本包仅依赖标准库（core 模块依赖隔离原则）。
//
// 注意：本包不预设任何平台的 endpoint / 鉴权头格式——这些必须由平台实现
// 按官方文档构造并在代码注释附文档链接 + 拉取日期（全局规则 §2.8）。
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 默认值。
const (
	// DefaultTimeout 默认请求超时。
	DefaultTimeout = 10 * time.Second
	// DefaultMaxBodySize 默认响应体大小上限（10 MiB）。
	DefaultMaxBodySize = 10 << 20
	// maxBackoff 单次重试退避上限，防指数膨胀。
	maxBackoff = 10 * time.Second
)

// Client 是带超时 / 重试 / 默认 header 的 HTTP 客户端封装。
// 并发安全（配置在 New 后只读）；建议每个平台实现持有一个实例复用连接池。
type Client struct {
	hc          *http.Client
	maxRetries  int                              // 首次之外最多再试几次；0 = 不重试
	retryWait   time.Duration                    // 退避基准：第 n 次重试等待 retryWait << (n-1)，上限 maxBackoff
	maxBodySize int64                            // 响应体大小上限（字节）
	headers     http.Header                      // client 级默认 header（可被每请求 header 覆盖）
	retryOn     func(status int, err error) bool // 重试判定；默认网络错误 / 429 / 5xx
}

// Option 配置 Client。
type Option func(*Client)

// New 创建 Client。默认：10s 超时、不重试、响应体上限 10 MiB。
func New(opts ...Option) *Client {
	c := &Client{
		hc:          &http.Client{Timeout: DefaultTimeout},
		maxRetries:  0,
		retryWait:   200 * time.Millisecond,
		maxBodySize: DefaultMaxBodySize,
		headers:     http.Header{},
		retryOn:     defaultRetryOn,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithTimeout 设置 client 级请求超时（含连接 + 读完响应体）。
// 每请求还可叠加更短的 context 超时。
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.hc.Timeout = d }
}

// WithHTTPClient 注入自定义 *http.Client（自定义 Transport / 代理 / TLS 时用）。
// 注意会覆盖 WithTimeout 设置的超时，两者按传入顺序生效。
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.hc = hc
		}
	}
}

// WithRetry 开启重试：失败后最多再试 maxRetries 次，第 n 次重试前等待
// baseWait << (n-1)（指数退避，单次上限 10s，等待期间响应 ctx 取消）。
//
// 幂等性纪律（硬要求）：只对幂等接口开启（GET 查询、平台明确支持幂等键的
// 接口）。对"下单/扣款"类非幂等 POST 开重试可能造成重复交易——这正是
// 默认不重试的原因。
func WithRetry(maxRetries int, baseWait time.Duration) Option {
	return func(c *Client) {
		if maxRetries < 0 {
			maxRetries = 0
		}
		if baseWait <= 0 {
			baseWait = 200 * time.Millisecond
		}
		c.maxRetries = maxRetries
		c.retryWait = baseWait
	}
}

// WithMaxBodySize 设置响应体大小上限（字节），超限返回错误。
func WithMaxBodySize(n int64) Option {
	return func(c *Client) {
		if n > 0 {
			c.maxBodySize = n
		}
	}
}

// WithDefaultHeader 追加 client 级默认 header（如 User-Agent、平台公共头）。
// 与每请求 header 同名时，以每请求 header 为准。
func WithDefaultHeader(key, value string) Option {
	return func(c *Client) { c.headers.Set(key, value) }
}

// WithRetryOn 自定义重试判定（status 为响应状态码，请求未完成时为 0 且 err 非 nil）。
// 默认判定见 defaultRetryOn：网络错误 / 429 / 5xx。
func WithRetryOn(f func(status int, err error) bool) Option {
	return func(c *Client) {
		if f != nil {
			c.retryOn = f
		}
	}
}

// defaultRetryOn 默认重试判定：网络错误、429（限频）、5xx（服务端暂时性故障）。
// 4xx（除 429）是确定性失败，重试无意义。
func defaultRetryOn(status int, err error) bool {
	if err != nil {
		return true
	}
	return status == http.StatusTooManyRequests || status >= 500
}

// Response 是读完响应体后的快照（Body 已全量读入并关闭原始连接）。
type Response struct {
	// StatusCode HTTP 状态码。
	StatusCode int
	// Header 响应头。
	Header http.Header
	// Body 响应体字节（已按 maxBodySize 限制读入）。
	Body []byte
}

// OK 报告状态码是否为 2xx。
// 注意：HTTP 2xx 不等于平台业务成功——多数平台在 200 应答体内携带业务错误码，
// 平台实现必须再解析应答体判定（实战教训：不要只看 HTTP 状态码）。
func (r *Response) OK() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// String 返回原始响应体的字符串形式。
//
// 兼容性说明：该方法保留原有行为，供确实需要消费响应体的调用方使用；响应体
// 可能包含 access_token、session_key 等凭据，严禁把返回值拼入错误或日志。
// 需要诊断信息时使用 SafeSummary。
func (r *Response) String() string {
	return string(r.Body)
}

// SafeSummary 返回不含响应体原文的诊断摘要。
//
// Content-Type 只输出有限的安全类别，不回显远端提供的 type、subtype 或参数；长度
// 使用实际读入的 Body 字节数，不信任远端 Content-Length。该摘要可安全用于错误
// 和日志，但仍不应追加 Header 或 Body 原文。
func (r *Response) SafeSummary() string {
	if r == nil {
		return `status=0 content_type="unknown" body_bytes=0`
	}
	return fmt.Sprintf("status=%d content_type=%q %s", r.StatusCode, safeContentType(r.Header), SafeBodySummary(r.Body))
}

// SafeBodySummary 返回不含 body 原文的长度摘要，适合解析 incoming webhook、
// JWT payload 或其他不带 HTTP Response 元数据的非受信载荷时使用。
func SafeBodySummary(body []byte) string {
	return fmt.Sprintf("body_bytes=%d", len(body))
}

// JSON 把响应体反序列化到 v（v 须为指针）。
func (r *Response) JSON(v any) error {
	return DecodeJSON(r.Body, v)
}

// DecodeJSON 反序列化 JSON。已知安全的标准错误保留 Unwrap 链供 errors.As
// 使用；未知错误不保留原始 cause。错误文本只包含安全的错误分类/偏移与 body
// 长度，不包含原文或自定义 UnmarshalJSON 错误可能回显的凭据。
func DecodeJSON(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		detail, safeCause := classifyJSONError(err)
		return &decodeJSONError{
			cause:      safeCause,
			matchCause: err,
			detail:     detail,
			bodyBytes:  len(data),
		}
	}
	return nil
}

// decodeJSONError 安全展示解析失败，并仅保留经过分类或清洗的 cause。
type decodeJSONError struct {
	cause      error
	matchCause error
	detail     string
	bodyBytes  int
}

func (e *decodeJSONError) Error() string {
	return fmt.Sprintf("httpx: JSON 解析失败（%s，body_bytes=%d）", e.detail, e.bodyBytes)
}

func (e *decodeJSONError) Unwrap() error {
	return e.cause
}

// Is 保留 DecodeJSON 原先通过 %w 提供的 sentinel 匹配语义。matchCause 只参与
// errors.Is 判定，不经 Unwrap 或 As 暴露，避免未知自定义错误回显原始载荷。
func (e *decodeJSONError) Is(target error) bool {
	return errors.Is(e.matchCause, target)
}

func classifyJSONError(err error) (detail string, safeCause error) {
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		// SyntaxError.Error may echo the invalid input character. Preserve the
		// public error type and offset for errors.As without retaining its message.
		safeSyntaxErr := &json.SyntaxError{Offset: syntaxErr.Offset}
		return fmt.Sprintf("syntax_error_at=%d", syntaxErr.Offset), safeSyntaxErr
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		detail := fmt.Sprintf("type_error_at=%d target=%s", typeErr.Offset, typeErr.Type)
		if typeErr.Field != "" {
			detail += fmt.Sprintf(" field=%q", typeErr.Field)
		}
		// UnmarshalTypeError.Value 对 number 会带原始数值；只保留首个类型词，
		// 再构造安全副本放入错误链，确保 errors.As 可用但链内无载荷原文。
		safeTypeErr := *typeErr
		valueFields := strings.Fields(typeErr.Value)
		if len(valueFields) == 0 {
			safeTypeErr.Value = "unknown"
		} else {
			safeTypeErr.Value = valueFields[0]
		}
		return detail, &safeTypeErr
	}
	// 自定义 UnmarshalJSON 错误可能直接把 data 拼进 Error()；未知 cause 仅记录
	// 静态 Go 类型，不把原错误对象挂入 Unwrap 链。
	return fmt.Sprintf("cause_type=%T", err), nil
}

func safeContentType(header http.Header) string {
	if header == nil || strings.TrimSpace(header.Get("Content-Type")) == "" {
		return "unknown"
	}
	mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		return "invalid"
	}
	mediaType = strings.ToLower(mediaType)
	typeAndSubtype := strings.SplitN(mediaType, "/", 2)
	if len(typeAndSubtype) != 2 || typeAndSubtype[0] == "" || typeAndSubtype[1] == "" {
		return "invalid"
	}
	topLevel, subtype := typeAndSubtype[0], typeAndSubtype[1]

	switch {
	case subtype == "json" || strings.HasSuffix(subtype, "+json"):
		return "json"
	case mediaType == "text/html" || mediaType == "application/xhtml+xml":
		return "html"
	case subtype == "xml" || strings.HasSuffix(subtype, "+xml"):
		return "xml"
	case topLevel == "text":
		return "text"
	case topLevel == "image", topLevel == "audio", topLevel == "video",
		topLevel == "font", topLevel == "model", mediaType == "application/octet-stream":
		return "binary"
	default:
		return "other"
	}
}

// Get 发送 GET 请求。query 追加到 rawURL 已有查询参数之后（同名共存）；
// query / header 可为 nil。
func (c *Client) Get(ctx context.Context, rawURL string, query url.Values, header http.Header) (*Response, error) {
	u, err := mergeQuery(rawURL, query)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, http.MethodGet, u, nil, header)
}

// PostJSON 发送 POST 请求，Content-Type: application/json。
// body 为 []byte / json.RawMessage 时直接使用，否则 json.Marshal。
func (c *Client) PostJSON(ctx context.Context, rawURL string, body any, header http.Header) (*Response, error) {
	var payload []byte
	switch b := body.(type) {
	case nil:
		payload = nil
	case []byte:
		payload = b
	case json.RawMessage:
		payload = b
	default:
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("httpx: 请求体 JSON 序列化失败: %w", err)
		}
	}
	header = cloneHeader(header)
	header.Set("Content-Type", "application/json")
	return c.Do(ctx, http.MethodPost, rawURL, payload, header)
}

// PostForm 发送 POST 表单请求，Content-Type: application/x-www-form-urlencoded。
func (c *Client) PostForm(ctx context.Context, rawURL string, form url.Values, header http.Header) (*Response, error) {
	header = cloneHeader(header)
	header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.Do(ctx, http.MethodPost, rawURL, []byte(form.Encode()), header)
}

// Do 发送任意方法的请求（body 可为 nil），按配置执行重试与退避。
//
// 返回约定：
//   - 传输成功（拿到 HTTP 应答，无论状态码）→ (*Response, nil)，状态码语义由
//     调用方判定（非 2xx 不视为 error，平台业务错误通常携带在应答体里）；
//   - 传输失败且重试耗尽 → (nil, error)；
//   - 重试链中"最后一次尝试"的结果即最终返回值。
func (c *Client) Do(ctx context.Context, method, rawURL string, body []byte, header http.Header) (*Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		resp    *Response
		lastErr error
	)
	for attempt := 0; ; attempt++ {
		resp, lastErr = c.doOnce(ctx, method, rawURL, body, header)
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		// 成功且不满足重试条件 → 直接返回
		if !c.retryOn(status, lastErr) {
			return resp, lastErr
		}
		// 重试次数耗尽 → 返回最后一次结果
		if attempt >= c.maxRetries {
			return resp, lastErr
		}
		// 指数退避，等待期间响应 ctx 取消
		wait := c.retryWait << attempt
		if wait > maxBackoff {
			wait = maxBackoff
		}
		if err := sleepCtx(ctx, wait); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("httpx: 重试等待被取消: %w（上一次错误: %v）", err, lastErr)
			}
			return resp, nil
		}
	}
}

// doOnce 单次请求：构造 → 发送 → 限量读体 → 关闭连接。
func (c *Client) doOnce(ctx context.Context, method, rawURL string, body []byte, header http.Header) (*Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("httpx: 构造请求失败: %w", err)
	}
	// client 级默认 header 先铺底，每请求 header 覆盖同名项
	for k, vs := range c.headers {
		req.Header[k] = append([]string(nil), vs...)
	}
	for k, vs := range header {
		req.Header[k] = append([]string(nil), vs...)
	}
	httpResp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpx: %s %s 请求失败: %w", method, rawURL, err)
	}
	defer httpResp.Body.Close()
	// 多读 1 字节用于精确判定"恰好超限"
	data, err := io.ReadAll(io.LimitReader(httpResp.Body, c.maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("httpx: 读取响应体失败: %w", err)
	}
	if int64(len(data)) > c.maxBodySize {
		return nil, fmt.Errorf("httpx: 响应体超过上限 %d 字节", c.maxBodySize)
	}
	return &Response{
		StatusCode: httpResp.StatusCode,
		Header:     httpResp.Header,
		Body:       data,
	}, nil
}

// mergeQuery 把 query 合并进 rawURL 已有的查询串（同名参数共存）。
func mergeQuery(rawURL string, query url.Values) (string, error) {
	if len(query) == 0 {
		return rawURL, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("httpx: URL 非法 %q: %w", rawURL, err)
	}
	q := u.Query()
	for k, vs := range query {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// cloneHeader 复制 header（nil 安全），避免修改调用方传入的 map。
func cloneHeader(h http.Header) http.Header {
	out := http.Header{}
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// sleepCtx 可被 ctx 取消的休眠。
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// JoinURL 拼接 base 与 path（处理斜杠重复/缺失），适合平台实现拼 endpoint。
func JoinURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}
