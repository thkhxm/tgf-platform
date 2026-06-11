//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/sign：RSA-SHA256 签名 / 验签 + PEM 解析（PKCS#1 / PKCS#8 / PKIX 自适应）
//2026/6/11
//***************************************************

package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// RSASHA256Sign 用 RSA 私钥对 data 做 SHA-256 摘要后 PKCS#1 v1.5 签名，返回原始签名字节。
func RSASHA256Sign(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
}

// RSASHA256SignBase64 同 RSASHA256Sign，返回标准 base64 串（平台接口常用形态）。
func RSASHA256SignBase64(priv *rsa.PrivateKey, data []byte) (string, error) {
	sig, err := RSASHA256Sign(priv, data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// RSASHA256Verify 校验 RSA-SHA256（PKCS#1 v1.5）签名；验签通过返回 nil。
func RSASHA256Verify(pub *rsa.PublicKey, data, sig []byte) error {
	digest := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// RSASHA256VerifyBase64 校验标准 base64 形式的 RSA-SHA256 签名；验签通过返回 nil。
func RSASHA256VerifyBase64(pub *rsa.PublicKey, data []byte, sigBase64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return fmt.Errorf("sign: 签名不是合法 base64: %w", err)
	}
	return RSASHA256Verify(pub, data, sig)
}

// ParseRSAPrivateKeyPEM 解析 PEM 编码的 RSA 私钥，自适应 PKCS#8 与 PKCS#1 两种封装
// （平台下发的商户私钥两种格式都常见）。
func ParseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("sign: 私钥 PEM 解码失败（未找到 PEM block）")
	}
	// 先按 PKCS#8（BEGIN PRIVATE KEY）尝试
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("sign: PKCS#8 私钥不是 RSA 类型（实际 %T）", key)
		}
		return rsaKey, nil
	}
	// 再按 PKCS#1（BEGIN RSA PRIVATE KEY）尝试
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sign: 私钥既不是 PKCS#8 也不是 PKCS#1 RSA 格式: %w", err)
	}
	return key, nil
}

// ParseRSAPublicKeyPEM 解析 PEM 编码的 RSA 公钥，自适应 PKIX（BEGIN PUBLIC KEY）
// 与 PKCS#1（BEGIN RSA PUBLIC KEY）两种封装。
func ParseRSAPublicKeyPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("sign: 公钥 PEM 解码失败（未找到 PEM block）")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("sign: PKIX 公钥不是 RSA 类型（实际 %T）", key)
		}
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sign: 公钥既不是 PKIX 也不是 PKCS#1 RSA 格式: %w", err)
	}
	return key, nil
}

// ParseCertificatePEM 解析 PEM 编码的 X.509 证书（平台证书验签场景：
// 平台下发证书，验签时取证书内公钥）。
func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("sign: 证书 PEM 解码失败（未找到 PEM block）")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sign: X.509 证书解析失败: %w", err)
	}
	return cert, nil
}

// RSAPublicKeyFromCertPEM 从 PEM 证书中提取 RSA 公钥（解析证书 + 类型断言的便捷组合）。
func RSAPublicKeyFromCertPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	cert, err := ParseCertificatePEM(pemBytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("sign: 证书公钥不是 RSA 类型（实际 %T）", cert.PublicKey)
	}
	return pub, nil
}
