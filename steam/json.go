//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description steam：Web API 应答的弹性 JSON 解析 helper
//2026/6/11
//***************************************************

package steam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// Steamworks Web API 的 JSON 格式约定（官方正文，
// https://partner.steamgames.com/doc/webapi_overview/responses ，2026-06-11 拉取）：
//   - 默认即返回 JSON（“By default, all responses are returned JSON encoded”）；
//   - “64 bit numbers are returned as a string”——orderid / transid / steamid 等
//     64 位字段是字符串，itemid / qty / amount / vat 等 32 位内字段是数字
//     （GetReport v5 官方 JSON 示例确证，
//     https://partner.steamgames.com/doc/webapi/ISteamMicroTxn ，2026-06-11 拉取）。
//
// 为防协议在数字/字符串形态上的历史歧义（FinalizeTxn v2 change history：
// “Changed to string formatted 64 bit numbers”），本文件提供两种形态都容忍的
// 弹性类型——宽进严出：解析宽松，业务判定仍以解析后的精确值为准。

// flexString 兼容 JSON 字符串与数字两种形态的字符串字段（errorcode / orderid 等）。
type flexString string

// UnmarshalJSON 实现 json.Unmarshaler：字符串原样取值，数字/布尔保留字面量。
func (f *flexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	*f = flexString(b)
	return nil
}

// flexInt64 兼容 JSON 数字与字符串两种形态的整数字段（amount / vat / qty 等）。
type flexInt64 int64

// UnmarshalJSON 实现 json.Unmarshaler。
func (f *flexInt64) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = 0
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		b = []byte(s)
	}
	if len(b) == 0 {
		*f = 0
		return nil
	}
	v, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("steam: 整数字段解析失败 %q: %w", b, err)
	}
	*f = flexInt64(v)
	return nil
}

// webAPIError 是 Web API 业务失败时 response.error 块的结构。
// 字段名来自官方正文（ISteamMicroTxn 各方法响应说明 + InitTxn Failure 示例：
// error{errorcode, errordesc}，https://partner.steamgames.com/doc/webapi/ISteamMicroTxn ，
// 2026-06-11 拉取）。errorcode 取值见
// https://partner.steamgames.com/doc/features/microtransactions/implementation
// Appendix B: Error Codes（2026-06-11 拉取）。
type webAPIError struct {
	ErrorCode flexString `json:"errorcode"`
	ErrorDesc string     `json:"errordesc"`
}

// rawToString 把 json.RawMessage 转为字符串：JSON 字符串去引号，数字/布尔保留
// 字面量，对象/数组保留原始 JSON 文本（透传进 Raw map 用）。
func rawToString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return string(raw)
}

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 官方状态码语义（https://partner.steamgames.com/doc/webapi_overview/responses ，
// 2026-06-11 拉取）：401/403 = key 错误且 “Retrying will not help”；429 = 限频；
// 500 = “please try again”；503 = “Please wait and try again later”。
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// httpStatusHint 给非 2xx 状态码补充排障提示（语义来自官方状态码表，同上文档）。
func httpStatusHint(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "HTTP 400（必填参数缺失或非法）"
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("HTTP %d（Web API key 无效或无权限，官方明确重试无用——核对 key 种类：微交易需带 Microtransaction 权限的 publisher key）", status)
	case http.StatusTooManyRequests:
		return "HTTP 429（被限频）"
	default:
		return fmt.Sprintf("HTTP 状态异常 %d", status)
	}
}

// truncate 截断非敏感诊断字段到 n 字节，防错误信息过长。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}
