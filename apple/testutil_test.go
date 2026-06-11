//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：单测共用工具——测试证书链 / JWS / identityToken / JWKS 构造
//2026/6/11
//***************************************************

package apple

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/sign"
)

// testChain 是一条自造的「测试根 → 中间 → 叶子」证书链（带 Apple 专属扩展 OID），
// 用于在单测中模拟 App Store 的 x5c 签名链。
type testChain struct {
	pool    *x509.CertPool // 含测试根的信任池（注入 Config.RootCAs）
	leafKey *ecdsa.PrivateKey
	x5c     []string // [叶子, 中间, 根] 的 DER 标准 base64
}

// newTestChain 构造测试证书链。withOIDs=false 时不带 Apple 专属扩展
// （用于验证 OID 检查生效）。
func newTestChain(t *testing.T, withOIDs bool) *testChain {
	t.Helper()
	now := time.Now()

	rootKey := genECKey(t)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Apple Root CA"},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("创建测试根证书失败: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	interKey := genECKey(t)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Apple Intermediate CA"},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if withOIDs {
		interTmpl.ExtraExtensions = []pkix.Extension{{Id: oidAppleIntermediateCert, Value: []byte{0x05, 0x00}}}
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("创建测试中间证书失败: %v", err)
	}
	interCert, _ := x509.ParseCertificate(interDER)

	leafKey := genECKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test StoreKit Signing"},
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if withOIDs {
		leafTmpl.ExtraExtensions = []pkix.Extension{{Id: oidAppleLeafCert, Value: []byte{0x05, 0x00}}}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("创建测试叶子证书失败: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return &testChain{
		pool:    pool,
		leafKey: leafKey,
		x5c: []string{
			base64.StdEncoding.EncodeToString(leafDER),
			base64.StdEncoding.EncodeToString(interDER),
			base64.StdEncoding.EncodeToString(rootDER),
		},
	}
}

// signJWS 用链上叶子私钥签一条 App Store 形态的 x5c JWS（payload 任意可序列化值）。
func (c *testChain) signJWS(t *testing.T, payload any) string {
	t.Helper()
	header := map[string]any{"alg": "ES256", "x5c": c.x5c}
	hb, _ := json.Marshal(header)
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("payload 序列化失败: %v", err)
	}
	signingInput := b64uEncode(hb) + "." + b64uEncode(pb)
	sig, err := es256Sign(c.leafKey, []byte(signingInput))
	if err != nil {
		t.Fatalf("ES256 签名失败: %v", err)
	}
	return signingInput + "." + b64uEncode(sig)
}

// genECKey 生成 ECDSA P-256 私钥。
func genECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 EC 私钥失败: %v", err)
	}
	return key
}

// p8PEM 把 EC 私钥编码为 PKCS#8 PEM（模拟 App Store Connect 下载的 .p8）。
func p8PEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("PKCS#8 编码失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// rsaJWKS 构造含一把 RSA 公钥的 JWKS JSON（kid 固定可指定）。
func rsaJWKS(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	e := big.NewInt(int64(pub.E))
	doc := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64uEncode(pub.N.Bytes()),
		"e": b64uEncode(e.Bytes()),
	}}}
	b, _ := json.Marshal(doc)
	return b
}

// ecJWKS 构造含一把 EC P-256 公钥的 JWKS JSON。
func ecJWKS(t *testing.T, kid string, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	// P-256 坐标定长 32 字节（FillBytes 左零填充，防止高位为零时长度缩水）。
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	doc := map[string]any{"keys": []map[string]string{{
		"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256",
		"crv": "P-256", "x": b64uEncode(xb), "y": b64uEncode(yb),
	}}}
	b, _ := json.Marshal(doc)
	return b
}

// makeIDTokenRS256 用 RSA 私钥签一个 RS256 identityToken。
func makeIDTokenRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("claims 序列化失败: %v", err)
	}
	signingInput := b64uEncode(hb) + "." + b64uEncode(cb)
	sig, err := sign.RSASHA256Sign(key, []byte(signingInput))
	if err != nil {
		t.Fatalf("RS256 签名失败: %v", err)
	}
	return signingInput + "." + b64uEncode(sig)
}

// makeIDTokenES256 用 EC 私钥签一个 ES256 identityToken。
func makeIDTokenES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"}
	token, err := signES256JWT(key, header, claims)
	if err != nil {
		t.Fatalf("ES256 JWT 签发失败: %v", err)
	}
	return token
}

// baseClaims 构造一组合法的 identityToken 声明（按需覆盖）。
func baseClaims(clientID string, override map[string]any) map[string]any {
	claims := map[string]any{
		"iss":            appleIssuer,
		"aud":            clientID,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"sub":            "001234.abcdef0123456789",
		"email":          "user@privaterelay.appleid.com",
		"email_verified": true,
		"auth_time":      time.Now().Unix(),
	}
	for k, v := range override {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	return claims
}
