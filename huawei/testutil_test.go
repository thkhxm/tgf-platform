//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：单测共享工具——测试 RSA 密钥 / JWT 签发 / JWKS mock server / IAP 数据签名
//2026/6/11
//***************************************************

package huawei

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// testKeyOnce 测试 RSA 密钥按进程生成一次（2048 位生成有成本，全部用例共享）。
var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		var err error
		testKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("生成测试 RSA 密钥失败: %v", err)
		}
	})
	return testKey
}

// testIAPPublicKeyB64 返回测试公钥的 base64 PKIX DER（AppGallery Connect 下发形态）。
func testIAPPublicKeyB64(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&testRSAKey(t).PublicKey)
	if err != nil {
		t.Fatalf("公钥编码失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// signJWT 用测试私钥签发 JWT（alg = RS256 / PS256；其他取值只编码不验证，
// 供"拒绝未知算法"用例构造恶意 token）。
func signJWT(t *testing.T, kid, alg string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": alg, "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signed))

	var (
		sig []byte
		err error
	)
	switch alg {
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, testRSAKey(t), crypto.SHA256, digest[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	default: // RS256 及"未知算法"用例统一 PKCS#1 v1.5 签（后者在 alg 校验就该被拒）
		sig, err = rsa.SignPKCS1v15(rand.Reader, testRSAKey(t), crypto.SHA256, digest[:])
	}
	if err != nil {
		t.Fatalf("签发测试 JWT 失败: %v", err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksHandler 构造 OIDC 发现 + JWKS 两个端点的 handler。
// kids 是当前对外公布的 kid 列表（同一把测试公钥可挂多个 kid，模拟轮换）。
type jwksHandler struct {
	mu   sync.Mutex
	kids []string
}

func (j *jwksHandler) setKids(kids ...string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.kids = kids
}

// register 把 /.well-known/openid-configuration 与 /certs 挂到 mux 上；
// jwks_uri 指向同一 server 的 /certs（baseURL 延迟到请求时从 Host 取）。
func (j *jwksHandler) register(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   idTokenIssuer,
			"jwks_uri": "http://" + r.Host + "/certs",
		})
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		pub := &testRSAKey(t).PublicKey
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}) // 65537
		j.mu.Lock()
		kids := append([]string(nil), j.kids...)
		j.mu.Unlock()
		keys := make([]map[string]string, 0, len(kids))
		for _, kid := range kids {
			keys = append(keys, map[string]string{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
}

// signIAPData 用测试私钥对 IAP 购买数据签名（algorithm 同 verifyIAPSignature 语义）。
func signIAPData(t *testing.T, content, algorithm string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(content))
	var (
		sig []byte
		err error
	)
	if algorithm == "SHA256WithRSA/PSS" {
		sig, err = rsa.SignPSS(rand.Reader, testRSAKey(t), crypto.SHA256, digest[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	} else {
		sig, err = rsa.SignPKCS1v15(rand.Reader, testRSAKey(t), crypto.SHA256, digest[:])
	}
	if err != nil {
		t.Fatalf("IAP 数据签名失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// newTestServer 起一个 httptest server 并注册 t.Cleanup。
func newTestServer(t *testing.T, mux *http.ServeMux) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
