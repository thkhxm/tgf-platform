//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description taptap：MAC Token 签算——HMAC-SHA1 Authorization 头构造
//2026/6/11
//***************************************************

package taptap

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TapTap MAC Token 官方协议指定 HMAC-SHA1（见下方文档注释），非本实现选型
	"encoding/base64"
)

// MAC Token 签算协议
// 文档：https://developer.taptap.cn/docs/sdk/taptap-login/taptap-oauth/
// （2026-06-11 拉取，快照 .docs/taptap-oauth.html）：
//
//  1. 待签名字符串（每个字段之间用 \n 分隔，末尾是两个 \n）：
//     {timestamp}\n{nonce}\n{method}\n{uri}\n{host}\n{port}\n\n
//     - timestamp：当前时间戳（秒级）
//     - nonce：随机字符串
//     - method：HTTP 请求方法（如 GET、POST）
//     - uri：请求路径（包含 query string，如 /account/profile/v1?client_id=xxx）
//     - host：请求域名（如 open.tapapis.cn）
//     - port：端口号（HTTPS 为 443）
//  2. mac = Base64( HMAC-SHA1(待签名字符串, mac_key) )
//  3. Authorization 头：MAC id="{kid}",ts="{timestamp}",nonce="{nonce}",mac="{mac}"
//
// 签算所需的 kid 与 mac_key 均来自客户端 SDK 登录后返回的 Access Token；
// mac_key 与开发者控制台的 Server Secret 是不同的值（官方文档明确提示）。
//
// 注：core/sign 只提供 HMAC-SHA256 / RSA / AES 原语；HMAC-SHA1 是 TapTap
// 专有协议细节，留在本平台模块内用标准库实现，不上提 core。

// defaultNonceLength 随机 nonce 长度。官方只要求“随机字符串”（示例用 5 位），
// 16 位字母数字是工程取值，熵足够防 nonce 撞车。
const defaultNonceLength = 16

// nonceChars nonce 字符集（大小写字母 + 数字，与官方示例代码的字符集一致）。
const nonceChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// buildSigningString 构造 MAC Token 待签名字符串（格式见上方协议注释，
// 与官方 Node.js 示例 buildSigningString 逐字符一致）。
func buildSigningString(ts, nonce, method, uri, host, port string) string {
	return ts + "\n" + nonce + "\n" + method + "\n" + uri + "\n" + host + "\n" + port + "\n\n"
}

// macSign 对待签名字符串做 HMAC-SHA1 签算并 Base64 编码（标准编码，
// 与官方示例 crypto.createHmac('sha1', key).digest('base64') 一致）。
func macSign(signingString, macKey string) string {
	h := hmac.New(sha1.New, []byte(macKey))
	h.Write([]byte(signingString))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// buildAuthorization 构造 Authorization 头的值（格式见上方协议注释）。
func buildAuthorization(kid, ts, nonce, mac string) string {
	return `MAC id="` + kid + `",ts="` + ts + `",nonce="` + nonce + `",mac="` + mac + `"`
}

// randomNonce 用 crypto/rand 生成 length 位随机字母数字串。
// 注：对 62 字符集做 byte % 62 存在轻微取模偏差，但 nonce 只需“不可预测且
// 不撞车”，不承担密钥职责（官方示例同样未做无偏采样），16 位长度下熵充足。
func randomNonce(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = nonceChars[int(b)%len(nonceChars)]
	}
	return string(out), nil
}
