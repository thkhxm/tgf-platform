//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description core/sign 单测：HMAC（RFC 4231 标准向量）/ RSA 签验 / PEM 解析 / AES / 常量时间比较
//2026/6/11
//***************************************************

package sign

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestHMACSHA256Vector 使用 RFC 4231 Test Case 2 标准测试向量
// （https://www.rfc-editor.org/rfc/rfc4231#section-4.3）。
func TestHMACSHA256Vector(t *testing.T) {
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")
	const wantHex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

	if got := HMACSHA256Hex(key, data); got != wantHex {
		t.Errorf("HMACSHA256Hex = %s, want %s", got, wantHex)
	}
	raw, _ := hex.DecodeString(wantHex)
	if got := HMACSHA256Base64(key, data); got != base64.StdEncoding.EncodeToString(raw) {
		t.Errorf("HMACSHA256Base64 与标准向量不一致: %s", got)
	}
}

func TestVerifyHMACSHA256(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("payload")
	mac := HMACSHA256(key, data)

	if !VerifyHMACSHA256(key, data, mac) {
		t.Error("正确摘要应通过校验")
	}
	if VerifyHMACSHA256(key, []byte("tampered"), mac) {
		t.Error("数据被篡改应校验失败")
	}
	if VerifyHMACSHA256([]byte("wrong-key"), data, mac) {
		t.Error("密钥错误应校验失败")
	}

	hexMac := HMACSHA256Hex(key, data)
	if !VerifyHMACSHA256Hex(key, data, hexMac) {
		t.Error("hex 形式正确摘要应通过校验")
	}
	if !VerifyHMACSHA256Hex(key, data, strings.ToUpper(hexMac)) {
		t.Error("大写 hex 也应通过校验（大小写不敏感）")
	}
	if VerifyHMACSHA256Hex(key, data, "zz-not-hex") {
		t.Error("非法 hex 应校验失败而非 panic")
	}
}

func TestSHA256Hex(t *testing.T) {
	// FIPS 180-4 已知向量：SHA-256("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := SHA256Hex([]byte("abc")); got != want {
		t.Errorf("SHA256Hex(abc) = %s, want %s", got, want)
	}
}

func TestRSASignVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	data := []byte("待签名内容")

	sig, err := RSASHA256Sign(priv, data)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if err := RSASHA256Verify(&priv.PublicKey, data, sig); err != nil {
		t.Errorf("正确签名应验签通过: %v", err)
	}
	if err := RSASHA256Verify(&priv.PublicKey, []byte("被篡改的内容"), sig); err == nil {
		t.Error("数据被篡改应验签失败")
	}

	sigB64, err := RSASHA256SignBase64(priv, data)
	if err != nil {
		t.Fatalf("base64 签名失败: %v", err)
	}
	if err := RSASHA256VerifyBase64(&priv.PublicKey, data, sigB64); err != nil {
		t.Errorf("base64 正确签名应验签通过: %v", err)
	}
	if err := RSASHA256VerifyBase64(&priv.PublicKey, data, "!!!不是base64!!!"); err == nil {
		t.Error("非法 base64 应返回错误")
	}
}

func TestParseRSAPrivateKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}

	// PKCS#8 封装
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("PKCS#8 编码失败: %v", err)
	}
	pemPKCS8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	got, err := ParseRSAPrivateKeyPEM(pemPKCS8)
	if err != nil {
		t.Fatalf("解析 PKCS#8 私钥失败: %v", err)
	}
	if !got.Equal(priv) {
		t.Error("PKCS#8 解析结果与原私钥不一致")
	}

	// PKCS#1 封装
	pemPKCS1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	got, err = ParseRSAPrivateKeyPEM(pemPKCS1)
	if err != nil {
		t.Fatalf("解析 PKCS#1 私钥失败: %v", err)
	}
	if !got.Equal(priv) {
		t.Error("PKCS#1 解析结果与原私钥不一致")
	}

	// 非 PEM 内容
	if _, err := ParseRSAPrivateKeyPEM([]byte("not pem")); err == nil {
		t.Error("非 PEM 内容应返回错误")
	}
}

func TestParseRSAPublicKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	pub := &priv.PublicKey

	// PKIX 封装
	pkix1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("PKIX 编码失败: %v", err)
	}
	got, err := ParseRSAPublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix1}))
	if err != nil {
		t.Fatalf("解析 PKIX 公钥失败: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("PKIX 解析结果与原公钥不一致")
	}

	// PKCS#1 封装
	got, err = ParseRSAPublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pub)}))
	if err != nil {
		t.Fatalf("解析 PKCS#1 公钥失败: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("PKCS#1 解析结果与原公钥不一致")
	}
}

func TestRSAPublicKeyFromCertPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tgf-platform-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("生成自签证书失败: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	if cert.Subject.CommonName != "tgf-platform-test" {
		t.Errorf("证书 CN 不符: %s", cert.Subject.CommonName)
	}
	pub, err := RSAPublicKeyFromCertPEM(certPEM)
	if err != nil {
		t.Fatalf("从证书提取公钥失败: %v", err)
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Error("证书内公钥与原公钥不一致")
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32) // AES-256
	nonce := bytes.Repeat([]byte("n"), 12)
	aad := []byte("associated-data")
	plain := []byte("机密内容 secret")

	ct, err := AESGCMEncrypt(key, nonce, plain, aad)
	if err != nil {
		t.Fatalf("GCM 加密失败: %v", err)
	}
	got, err := AESGCMDecrypt(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("GCM 解密失败: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("GCM 解密结果不一致: %q", got)
	}

	// 密文被篡改 → 认证失败
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0xff
	if _, err := AESGCMDecrypt(key, nonce, tampered, aad); err == nil {
		t.Error("密文被篡改应解密失败")
	}
	// aad 不匹配 → 认证失败
	if _, err := AESGCMDecrypt(key, nonce, ct, []byte("other-aad")); err == nil {
		t.Error("aad 不匹配应解密失败")
	}
	// nonce 长度非法
	if _, err := AESGCMEncrypt(key, []byte("short"), plain, nil); err == nil {
		t.Error("非法 nonce 长度应返回错误")
	}
	// 密钥长度非法
	if _, err := AESGCMEncrypt([]byte("bad-len"), nonce, plain, nil); err == nil {
		t.Error("非法密钥长度应返回错误")
	}
}

func TestAESCBCRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 16) // AES-128
	iv := bytes.Repeat([]byte("i"), 16)

	for _, plain := range [][]byte{
		[]byte(""),                    // 空明文 → 填满整块
		[]byte("short"),               // 不足一块
		bytes.Repeat([]byte("x"), 16), // 恰好整块 → 追加整块填充
		[]byte("中文明文跨多块的情况确保覆盖到位"), // 多块
	} {
		ct, err := AESCBCEncryptPKCS7(key, iv, plain)
		if err != nil {
			t.Fatalf("CBC 加密失败（明文 %q）: %v", plain, err)
		}
		if len(ct)%16 != 0 {
			t.Errorf("CBC 密文长度应为块整数倍，got %d", len(ct))
		}
		got, err := AESCBCDecryptPKCS7(key, iv, ct)
		if err != nil {
			t.Fatalf("CBC 解密失败（明文 %q）: %v", plain, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("CBC 解密结果不一致: got %q want %q", got, plain)
		}
	}

	// 注意：不断言"错误密钥必定解密失败"——CBC 无认证，错误密钥解出的
	// 随机末字节有约 1/255 概率恰好构成合法 PKCS#7 填充，硬断言会偶发 flaky。
	// 这正是 AESCBCDecryptPKCS7 注释要求"密文之外必须另有签名/MAC 保护"的原因。

	// 密文长度非块整数倍
	if _, err := AESCBCDecryptPKCS7(key, iv, []byte("bad")); err == nil {
		t.Error("非块整数倍密文应返回错误")
	}
	// iv 长度非法
	if _, err := AESCBCEncryptPKCS7(key, []byte("short-iv"), []byte("data")); err == nil {
		t.Error("非法 iv 长度应返回错误")
	}
}

func TestPKCS7Unpad(t *testing.T) {
	// 直接覆盖内部填充校验的恶意输入
	for name, data := range map[string][]byte{
		"填充值为 0":  append(bytes.Repeat([]byte{1}, 15), 0),
		"填充值超块长":  append(bytes.Repeat([]byte{1}, 15), 17),
		"填充内容不一致": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 2, 3},
		"空数据":     {},
	} {
		if _, err := pkcs7Unpad(data, 16); err == nil {
			t.Errorf("%s：应返回错误", name)
		}
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual([]byte("abc"), []byte("abc")) {
		t.Error("相等字节应返回 true")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("abd")) {
		t.Error("不等字节应返回 false")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("ab")) {
		t.Error("长度不同应返回 false")
	}
	if !ConstantTimeEqualString("", "") {
		t.Error("两个空串应返回 true")
	}
	if !ConstantTimeEqualString("token", "token") {
		t.Error("相等字符串应返回 true")
	}
	if ConstantTimeEqualString("token", "Token") {
		t.Error("大小写不同应返回 false")
	}
}
