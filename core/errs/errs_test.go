//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/errs 单测：错误格式 / Unwrap 链 / 可重试判定 / 错误码透传
//2026/6/11
//***************************************************

package errs

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestErrorFormat(t *testing.T) {
	e := New("tiktok", "code2session", "40029", "invalid code").
		WithHTTPStatus(200).
		WithCause(io.ErrUnexpectedEOF)
	got := e.Error()
	for _, want := range []string{"tiktok", "code2session", "code=40029", "invalid code", "http 200", io.ErrUnexpectedEOF.Error()} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q，缺少片段 %q", got, want)
		}
	}
}

func TestErrorFormatMinimal(t *testing.T) {
	// 仅平台 + 操作，可选段全空时不应输出残缺片段
	got := New("wechat", "msg_sec_check", "", "").Error()
	if strings.Contains(got, "code=") || strings.Contains(got, "http") {
		t.Errorf("Error() = %q，不应包含空字段片段", got)
	}
}

func TestWrapAndUnwrapChain(t *testing.T) {
	base := io.EOF
	e := Wrap("tiktok", "query_order", base)
	// 再包一层标准库 wrap，验证沿链匹配
	outer := fmt.Errorf("调用失败: %w", e)
	if !errors.Is(outer, io.EOF) {
		t.Error("errors.Is 应沿链匹配到底层 io.EOF")
	}
	pe, ok := AsPlatformError(outer)
	if !ok {
		t.Fatal("AsPlatformError 应沿链命中 *Error")
	}
	if pe.Platform != "tiktok" || pe.Op != "query_order" {
		t.Errorf("取回的平台错误字段不符: %+v", pe)
	}
}

func TestWrapNil(t *testing.T) {
	if Wrap("tiktok", "op", nil) != nil {
		t.Error("Wrap(nil) 应返回 nil")
	}
}

func TestIsRetryable(t *testing.T) {
	retryable := New("tiktok", "query_order", "", "限频").WithRetryable(true)
	wrapped := fmt.Errorf("外层: %w", retryable)
	if !IsRetryable(wrapped) {
		t.Error("可重试错误经标准库包装后仍应判定为可重试")
	}
	if IsRetryable(New("tiktok", "code2session", "40029", "invalid code")) {
		t.Error("默认（确定性失败）不应判定为可重试")
	}
	if IsRetryable(io.EOF) {
		t.Error("非平台错误不应判定为可重试")
	}
	if IsRetryable(nil) {
		t.Error("nil 不应判定为可重试")
	}
}

func TestCodeOf(t *testing.T) {
	e := New("wechat", "jscode2session", "40163", "code been used")
	if got := CodeOf(fmt.Errorf("w: %w", e)); got != "40163" {
		t.Errorf("CodeOf = %q, want 40163", got)
	}
	if got := CodeOf(io.EOF); got != "" {
		t.Errorf("非平台错误 CodeOf 应为空串，got %q", got)
	}
	if got := CodeOf(nil); got != "" {
		t.Errorf("nil 的 CodeOf 应为空串，got %q", got)
	}
}
