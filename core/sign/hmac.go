//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/sign：HMAC-SHA256 / SHA256 / 常量时间比较——平台回调验签常用原语
//2026/6/11
//***************************************************

// Package sign 提供平台签名 / 验签 / 加解密的通用原语：
//   - HMAC-SHA256（多数平台 webhook 验签）；
//   - RSA-SHA256 签名 / 验签（PKCS#1 v1.5，微信支付 v3 等）；
//   - AES-GCM / AES-CBC-PKCS#7 加解密（回调密文解密、小程序数据解密）；
//   - 常量时间比较（验签比较的硬要求，防时序侧信道）。
//
// 本包仅依赖标准库（core 模块依赖隔离原则）。
//
// 注意：本包只提供算法原语，**不预设任何平台的签名串拼接规则**——
// 待签名串如何拼（字段排序、分隔符、时间戳位置）必须由平台实现按
// 各自官方文档构造（全局规则 §2.8：不许凭记忆写协议细节）。
package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// HMACSHA256 计算 HMAC-SHA256，返回 32 字节原始摘要。
func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMACSHA256Hex 计算 HMAC-SHA256，返回小写十六进制串。
func HMACSHA256Hex(key, data []byte) string {
	return hex.EncodeToString(HMACSHA256(key, data))
}

// HMACSHA256Base64 计算 HMAC-SHA256，返回标准 base64 串。
func HMACSHA256Base64(key, data []byte) string {
	return base64.StdEncoding.EncodeToString(HMACSHA256(key, data))
}

// VerifyHMACSHA256 用常量时间比较校验 HMAC-SHA256（expected 为原始字节摘要）。
func VerifyHMACSHA256(key, data, expected []byte) bool {
	return hmac.Equal(HMACSHA256(key, data), expected)
}

// VerifyHMACSHA256Hex 校验十六进制形式的 HMAC-SHA256（大小写不敏感）。
// expectedHex 非法（非 hex）时返回 false。
func VerifyHMACSHA256Hex(key, data []byte, expectedHex string) bool {
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return false
	}
	return VerifyHMACSHA256(key, data, expected)
}

// SHA256Hex 计算 SHA-256，返回小写十六进制串。
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual 常量时间比较两段字节是否相等。
// 长度不同立即返回 false（长度本身不属于需要保护的秘密）。
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeEqualString 常量时间比较两个字符串是否相等。
func ConstantTimeEqualString(a, b string) bool {
	return ConstantTimeEqual([]byte(a), []byte(b))
}
