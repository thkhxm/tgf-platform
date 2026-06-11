//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/errs：平台调用统一错误类型——平台错误码透传 + 可重试标记
//2026/6/11
//***************************************************

// Package errs 提供各平台实现共用的统一错误类型。
//
// 设计目标：
//   - 平台错误码透传：各平台返回的业务错误码（数字或字符串）统一以 string 承载，
//     调用方用 CodeOf 取回原始码做分支判断（如微信 jscode2session 的 40029 invalid code）；
//   - 可重试标记：网络抖动 / 5xx / 平台限频等暂时性错误标记 Retryable=true，
//     上层据此决定是否重试，避免对确定性失败（参数错、凭据无效、验签失败）做无意义重试；
//   - 标准 error 链：实现 Unwrap，兼容 errors.Is / errors.As。
//
// 本包仅依赖标准库（core 模块依赖隔离原则）。
package errs

import (
	"errors"
	"fmt"
)

// Error 是平台调用的统一错误。
//
// 平台实现把第三方 API 的失败应答 / 传输层错误包装成 *Error 返回，
// 业务侧用 errors.As / AsPlatformError 取回结构化信息。
type Error struct {
	// Platform 平台标识（与 platform.Provider.Name() 一致，如 "tiktok" / "wechat"）。
	Platform string
	// Op 出错的操作，建议用平台 API 名（如 "code2session" / "query_order"）。
	Op string
	// Code 平台返回的原始错误码，数字码转十进制字符串后透传。
	// 空串表示该错误不携带平台错误码（如传输层错误、解析错误）。
	Code string
	// Message 错误描述，优先用平台返回的原始描述。
	Message string
	// HTTPStatus 平台应答的 HTTP 状态码；0 表示请求未完成（如网络错误）。
	HTTPStatus int
	// Retryable 是否为暂时性错误，可安全重试。
	// 约定：网络错误 / 5xx / 平台限频（429 或平台限频码）置 true；
	// 参数错误、凭据无效、验签失败等确定性失败置 false。
	Retryable bool
	// Err 底层错误（网络错误、JSON 解析错误等），经 Unwrap 暴露给 errors.Is/As。
	Err error
}

// New 构造一个携带平台错误码的错误（Retryable 默认 false，确定性失败是常态）。
func New(platform, op, code, message string) *Error {
	return &Error{Platform: platform, Op: op, Code: code, Message: message}
}

// Wrap 把底层错误（网络/解析等）包装为平台错误（不携带平台码）。
// err 为 nil 时返回 nil（*Error 类型的 nil）。
//
// typed-nil 陷阱提示：返回类型是 *Error——判空请直接对 Wrap 的返回值判 nil，
// 不要先赋给 error 接口变量再判（接口包住 nil 指针后 != nil）。
// 推荐用法是在错误分支内联使用：err 必然非 nil，不触碰该陷阱。
func Wrap(platform, op string, err error) *Error {
	if err == nil {
		return nil
	}
	return &Error{Platform: platform, Op: op, Err: err}
}

// WithHTTPStatus 链式设置 HTTP 状态码，返回自身。
func (e *Error) WithHTTPStatus(status int) *Error {
	e.HTTPStatus = status
	return e
}

// WithRetryable 链式设置可重试标记，返回自身。
func (e *Error) WithRetryable(retryable bool) *Error {
	e.Retryable = retryable
	return e
}

// WithCause 链式设置底层错误，返回自身。
func (e *Error) WithCause(err error) *Error {
	e.Err = err
	return e
}

// Error 实现 error 接口。
// 格式：platform <平台>: <操作>: code=<码>: <描述> (http <状态>): <底层错误>
// （各段仅在有值时输出）。
func (e *Error) Error() string {
	msg := "platform " + e.Platform + ": " + e.Op
	if e.Code != "" {
		msg += ": code=" + e.Code
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.HTTPStatus != 0 {
		msg += fmt.Sprintf(" (http %d)", e.HTTPStatus)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap 暴露底层错误，支持 errors.Is / errors.As 沿链匹配。
func (e *Error) Unwrap() error { return e.Err }

// AsPlatformError 从错误链中取回 *Error；第二个返回值表示是否命中。
func AsPlatformError(err error) (*Error, bool) {
	var pe *Error
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

// IsRetryable 报告错误链中是否存在标记为可重试的平台错误。
// 非平台错误（链上没有 *Error）一律返回 false——未知错误不盲目重试。
func IsRetryable(err error) bool {
	if pe, ok := AsPlatformError(err); ok {
		return pe.Retryable
	}
	return false
}

// CodeOf 从错误链中取回平台原始错误码；链上没有平台错误或无码时返回空串。
func CodeOf(err error) string {
	if pe, ok := AsPlatformError(err); ok {
		return pe.Code
	}
	return ""
}
