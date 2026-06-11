//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：单测共享工具——RSA 测试密钥 / JWKS mock server / JWT 构造
//2026/6/11
//***************************************************

package google

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/thkhxm/tgf-platform/core/sign"
)

// testRSAKey 生成 2048 位 RSA 测试密钥。
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 测试密钥失败: %v", err)
	}
	return priv
}

// jwkOf 把 RSA 公钥编码为 JWKS 应答里的单把 JWK（形态按 2026-06-11 实抓的
// https://www.googleapis.com/oauth2/v3/certs ）。
func jwkOf(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// newJWKSServer 起一个 JWKS mock server；hits 记请求次数（缓存行为断言用）。
func newJWKSServer(t *testing.T, keys []map[string]any) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// makeJWT 构造 RS256 签名的 JWT（header / claims 任意拼，覆盖篡改类用例）。
func makeJWT(t *testing.T, priv *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hj, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("序列化 JWT header 失败: %v", err)
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("序列化 JWT claims 失败: %v", err)
	}
	input := base64.RawURLEncoding.EncodeToString(hj) + "." + base64.RawURLEncoding.EncodeToString(cj)
	sig, err := sign.RSASHA256Sign(priv, []byte(input))
	if err != nil {
		t.Fatalf("签名 JWT 失败: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// tamperJWTClaims 替换 JWT 的 claims 段但保留原签名（签名比对失败用例）。
func tamperJWTClaims(t *testing.T, token string, claims map[string]any) string {
	t.Helper()
	cj, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("序列化篡改 claims 失败: %v", err)
	}
	parts := splitJWT(t, token)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(cj) + "." + parts[2]
}

// splitJWT 拆 JWT 三段。
func splitJWT(t *testing.T, token string) [3]string {
	t.Helper()
	var out [3]string
	n := 0
	start := 0
	for i := 0; i < len(token) && n < 2; i++ {
		if token[i] == '.' {
			out[n] = token[start:i]
			start = i + 1
			n++
		}
	}
	out[2] = token[start:]
	if n != 2 {
		t.Fatalf("token 不是三段式 JWT: %s", token)
	}
	return out
}
