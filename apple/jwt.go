//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：JWT/JWS 通用小工具——compact 拆分 / base64url / ES256 签名验签 / EC 私钥解析
//2026/6/11
//***************************************************

package apple

// 本文件的 ES256（ECDSA P-256 + SHA-256，JWS 签名为 R||S 各 32 字节定长拼接，
// 见 RFC 7518 §3.4）与 EC 私钥解析是 core/sign 目前缺失的能力（core 只有
// HMAC / RSA / AES），先在本包内用标准库实现，后续建议上提到 core/sign
// 供其它平台复用（见 doc.go「ES256 说明」）。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// splitCompact 把 JWS/JWT compact 序列化（header.payload.signature，各段
// base64url 无填充）拆成三段原始字符串。
func splitCompact(token string) (header, payload, signature string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("compact 序列化应为 3 段，实际 %d 段", len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}

// b64uDecode 解码 base64url（无填充，RFC 7515 §2）。
func b64uDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// b64uEncode 编码 base64url（无填充）。
func b64uEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// signES256JWT 用 ECDSA P-256 私钥按 ES256 签发 JWT。
// header / claims 任意可 JSON 序列化的结构；返回 compact 序列化串。
func signES256JWT(priv *ecdsa.PrivateKey, header, claims any) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("JWT header 序列化失败: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("JWT claims 序列化失败: %w", err)
	}
	signingInput := b64uEncode(hb) + "." + b64uEncode(cb)
	sig, err := es256Sign(priv, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64uEncode(sig), nil
}

// es256Sign 对 data 做 SHA-256 摘要后 ECDSA P-256 签名，返回 JWS 形态的
// R||S 定长 64 字节签名（RFC 7518 §3.4：各 32 字节大端，左零填充）。
func es256Sign(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("ES256 要求 P-256 曲线私钥")
	}
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA 签名失败: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// es256Verify 校验 ES256（JWS R||S 定长 64 字节）签名；验签通过返回 true。
func es256Verify(pub *ecdsa.PublicKey, data, sig []byte) bool {
	if pub == nil || pub.Curve != elliptic.P256() || len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256(data)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// parseECPrivateKeyPEM 解析 PEM 编码的 ECDSA 私钥，自适应 PKCS#8
// （BEGIN PRIVATE KEY，App Store Connect 下载的 .p8 即此格式）与 SEC1
// （BEGIN EC PRIVATE KEY）两种封装。
func parseECPrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("私钥 PEM 解码失败（未找到 PEM block）")
	}
	// 先按 PKCS#8（.p8 文件的封装）尝试
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 私钥不是 ECDSA 类型（实际 %T）", key)
		}
		return ecKey, nil
	}
	// 再按 SEC1（BEGIN EC PRIVATE KEY）尝试
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("私钥既不是 PKCS#8 也不是 SEC1 EC 格式: %w", err)
	}
	return key, nil
}

// decodeSegmentJSON 把 compact 的一段（base64url）解码并反序列化到 v。
func decodeSegmentJSON(segment string, v any) error {
	raw, err := b64uDecode(segment)
	if err != nil {
		return fmt.Errorf("base64url 解码失败: %w", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("JSON 解析失败: %w", err)
	}
	return nil
}
