//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：App Store JWS（x5c 证书链）验签——交易信息与服务器通知共用
//2026/6/11
//***************************************************

package apple

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// App Store 签名的 JWS（signedTransactionInfo / signedPayload / signedRenewalInfo）
// 的验签规则来源：
//
//   - 文档：https://developer.apple.com/documentation/appstoreserverapi/jwsdecodedheader
//     （2026-06-11 拉取）——header 含 alg 与 x5c；x5c 链按序是「叶子证书（含验签
//     公钥）→ Apple 中间证书 → Apple 根证书」；
//   - 文档：https://developer.apple.com/documentation/appstoreserverapi/jwstransaction
//     （2026-06-11 拉取）——JWS Compact 序列化（header.payload.signature）；
//   - 根证书：Apple Root CA - G3，从 https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
//     下载（2026-06-11 拉取，DER 嵌入下方常量）；
//   - 链路校验细节（链长 / 扩展 OID / 以 signedDate 作为证书有效期校验时点）
//     对照 Apple 官方开源验签实现 app-store-server-library-node 的
//     jws_verification.ts（https://github.com/apple/app-store-server-library-node ，
//     main 分支 2026-06-11 拉取）：
//     x5c 链长必须为 3；叶子证书必须含扩展 OID 1.2.840.113635.100.6.11.1；
//     中间证书必须含扩展 OID 1.2.840.113635.100.6.2.1 且为 CA。

// appleRootCAG3Base64 是 Apple Root CA - G3 证书（DER）的 base64。
// 来源：https://www.apple.com/certificateauthority/AppleRootCA-G3.cer（2026-06-11 拉取）。
// 主题 "Apple Root CA - G3"，ECDSA P-384，有效期 2014-04-30 ～ 2039-04-30。
const appleRootCAG3Base64 = `
MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9v
dCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UE
CgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2
WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqG
SM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxE
tX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNC
MEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3m
eoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkL
F1vLUagM6BgD56KyKA==
`

// Apple 链路校验要求的扩展 OID（来源见文件头注释的官方库对照）。
var (
	// oidAppleLeafCert 叶子证书必须携带的 Apple 扩展。
	oidAppleLeafCert = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	// oidAppleIntermediateCert 中间证书必须携带的 Apple 扩展。
	oidAppleIntermediateCert = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
)

// appleRootPool 构造内置 Apple Root CA - G3 信任池。
func appleRootPool() (*x509.CertPool, error) {
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(appleRootCAG3Base64), "\n", ""))
	if err != nil {
		return nil, errors.New("apple: 内置 Apple Root CA - G3 base64 损坏: " + err.Error())
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("apple: 内置 Apple Root CA - G3 解析失败: " + err.Error())
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

// jwsHeader 是 App Store JWS 的 JOSE header。
// 文档：https://developer.apple.com/documentation/appstoreserverapi/jwsdecodedheader
// （2026-06-11 拉取）：alg 签名算法；x5c 对应签名密钥的 X.509 证书链。
type jwsHeader struct {
	Alg string   `json:"alg"`
	X5c []string `json:"x5c"`
}

// signedDateProbe 只为提取 payload 中的 signedDate（UNIX 毫秒）——证书有效期
// 校验以它为时点（对照官方库 offline 模式的 effectiveDate 语义；老交易的签名
// 证书可能已过期，但在签名时点是有效的）。
type signedDateProbe struct {
	SignedDate int64 `json:"signedDate"`
}

// verifyAppleJWS 校验一条 App Store 签名的 JWS（compact 序列化），
// 返回验签通过后的 payload 原始字节。校验项：
//
//  1. alg 必须是 ES256（App Store 固定使用 ES256 签名）；
//  2. x5c 链长必须为 3（叶子 / 中间 / 根）；
//  3. 叶子与中间证书必须携带 Apple 专属扩展 OID（防任意 Apple 签发证书冒用）；
//  4. 证书链锚定信任池（默认内置 Apple Root CA - G3）校验，有效期校验时点
//     取 payload.signedDate（缺失时取当前时间）；
//  5. 用叶子证书内的 ECDSA P-256 公钥校验 JWS 签名。
//
// 规则来源见文件头注释（官方文档 + Apple 官方库对照，2026-06-11 拉取）。
func (a *Apple) verifyAppleJWS(compact string) ([]byte, error) {
	headerSeg, payloadSeg, sigSeg, err := splitCompact(compact)
	if err != nil {
		return nil, fmt.Errorf("JWS 格式非法: %w", err)
	}
	var header jwsHeader
	if err := decodeSegmentJSON(headerSeg, &header); err != nil {
		return nil, fmt.Errorf("JWS header 解析失败: %w", err)
	}
	if !strings.EqualFold(header.Alg, "ES256") {
		return nil, fmt.Errorf("JWS alg=%q 非法（App Store 固定使用 ES256）", header.Alg)
	}
	if len(header.X5c) != 3 {
		return nil, fmt.Errorf("JWS x5c 链长 %d 非法（应为 3：叶子/中间/根）", len(header.X5c))
	}
	certs := make([]*x509.Certificate, 0, 3)
	for i, c := range header.X5c {
		// x5c 元素是标准 base64（带填充，RFC 7515 §4.1.6），不是 base64url。
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d] base64 解码失败: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d] 证书解析失败: %w", i, err)
		}
		certs = append(certs, cert)
	}
	leaf, intermediate := certs[0], certs[1]

	// Apple 专属扩展 OID 检查（对照官方库 jws_verification.ts）。
	if !hasExtension(leaf, oidAppleLeafCert) {
		return nil, errors.New("叶子证书缺少 Apple 扩展 OID 1.2.840.113635.100.6.11.1")
	}
	if !hasExtension(intermediate, oidAppleIntermediateCert) {
		return nil, errors.New("中间证书缺少 Apple 扩展 OID 1.2.840.113635.100.6.2.1")
	}

	// 证书有效期校验时点：payload.signedDate（UNIX 毫秒；解析失败或缺失用当前时间）。
	verifyAt := a.now()
	payloadRaw, err := b64uDecode(payloadSeg)
	if err != nil {
		return nil, fmt.Errorf("JWS payload base64url 解码失败: %w", err)
	}
	var probe signedDateProbe
	if err := json.Unmarshal(payloadRaw, &probe); err == nil && probe.SignedDate > 0 {
		verifyAt = time.UnixMilli(probe.SignedDate)
	}

	// 链路校验：叶子 → 中间 → 信任池根。
	interPool := x509.NewCertPool()
	interPool.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         a.roots,
		Intermediates: interPool,
		CurrentTime:   verifyAt,
		// 叶子证书的 EKU 是 Apple 自定义用途，标准 EKU 列表对不上，放开为 Any
		// （信任锚 + 专属扩展 OID 已保证证书身份）。
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("x5c 证书链校验失败: %w", err)
	}

	// 叶子公钥验签（ES256）。
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("叶子证书公钥不是 ECDSA 类型（实际 %T）", leaf.PublicKey)
	}
	sigRaw, err := b64uDecode(sigSeg)
	if err != nil {
		return nil, fmt.Errorf("JWS 签名段 base64url 解码失败: %w", err)
	}
	if !es256Verify(pub, []byte(headerSeg+"."+payloadSeg), sigRaw) {
		return nil, errors.New("JWS 签名校验失败（payload 被篡改或签名伪造）")
	}
	return payloadRaw, nil
}

// hasExtension 报告证书是否携带指定 OID 的扩展。
func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}
