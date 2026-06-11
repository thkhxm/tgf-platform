//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：LoginProvider 单测——JWKS mock + identityToken 各失败路径
//2026/6/11
//***************************************************

package apple

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testClientID = "com.test.app"

// jwksServer 起一个可热替换应答的 JWKS mock。
type jwksServer struct {
	mu   sync.Mutex
	body []byte
	code int
	srv  *httptest.Server
	hits int
}

func newJWKSServer(t *testing.T, body []byte) *jwksServer {
	t.Helper()
	s := &jwksServer{body: body, code: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits++
		w.WriteHeader(s.code)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *jwksServer) set(body []byte, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
	s.code = code
}

// newLoginApple 构造指向 mock JWKS 的登录用实例。
func newLoginApple(t *testing.T, jwksURL string, opts ...func(*Config)) *Apple {
	t.Helper()
	cfg := Config{ClientID: testClientID, JWKSURL: jwksURL}
	for _, opt := range opts {
		opt(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return a
}

func TestVerifyLogin_SuccessRS256(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 私钥失败: %v", err)
	}
	srv := newJWKSServer(t, rsaJWKS(t, "kid-1", &rsaKey.PublicKey))
	a := newLoginApple(t, srv.srv.URL)

	token := makeIDTokenRS256(t, rsaKey, "kid-1", baseClaims(testClientID, nil))
	identity, err := a.VerifyLogin(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}
	if identity.Platform != PlatformName {
		t.Errorf("Platform = %q，期望 %q", identity.Platform, PlatformName)
	}
	if identity.OpenID != "001234.abcdef0123456789" {
		t.Errorf("OpenID = %q，期望 sub 声明值", identity.OpenID)
	}
	if identity.UnionID != "" || identity.SessionKey != "" {
		t.Errorf("UnionID/SessionKey 应为空（Apple 无此概念），实际 %q/%q", identity.UnionID, identity.SessionKey)
	}
	if identity.Raw["email"] != "user@privaterelay.appleid.com" {
		t.Errorf("Raw[email] = %q，期望透传", identity.Raw["email"])
	}
	if identity.Raw["email_verified"] != "true" {
		t.Errorf("Raw[email_verified] = %q，期望 \"true\"", identity.Raw["email_verified"])
	}
	if identity.Raw["iss"] != appleIssuer {
		t.Errorf("Raw[iss] = %q，期望透传", identity.Raw["iss"])
	}
}

func TestVerifyLogin_SuccessES256(t *testing.T) {
	ecKey := genECKey(t)
	srv := newJWKSServer(t, ecJWKS(t, "kid-ec", &ecKey.PublicKey))
	a := newLoginApple(t, srv.srv.URL)

	token := makeIDTokenES256(t, ecKey, "kid-ec", baseClaims(testClientID, nil))
	identity, err := a.VerifyLogin(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyLogin（ES256）失败: %v", err)
	}
	if identity.OpenID == "" {
		t.Error("OpenID 为空")
	}
}

func TestVerifyLogin_AudAsArray(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, rsaJWKS(t, "kid-1", &rsaKey.PublicKey))
	a := newLoginApple(t, srv.srv.URL)

	token := makeIDTokenRS256(t, rsaKey, "kid-1",
		baseClaims(testClientID, map[string]any{"aud": []string{"other.app", testClientID}}))
	if _, err := a.VerifyLogin(context.Background(), token); err != nil {
		t.Fatalf("aud 数组形式应通过，实际错误: %v", err)
	}
}

func TestVerifyLogin_Failures(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, rsaJWKS(t, "kid-1", &rsaKey.PublicKey))
	a := newLoginApple(t, srv.srv.URL)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name    string
		token   func() string
		wantErr string
	}{
		{
			name:    "credential 为空",
			token:   func() string { return "" },
			wantErr: "为空",
		},
		{
			name:    "不是 JWT",
			token:   func() string { return "garbage" },
			wantErr: "不是合法 JWT",
		},
		{
			name: "签名篡改（换别的私钥签）",
			token: func() string {
				return makeIDTokenRS256(t, otherKey, "kid-1", baseClaims(testClientID, nil))
			},
			wantErr: "签名校验失败",
		},
		{
			name: "payload 篡改",
			token: func() string {
				token := makeIDTokenRS256(t, rsaKey, "kid-1", baseClaims(testClientID, nil))
				parts := strings.Split(token, ".")
				// 直接替换 payload 段为另一个合法 base64url JSON（签名对不上）
				parts[1] = b64uEncode([]byte(`{"iss":"https://appleid.apple.com","aud":"` + testClientID + `","sub":"attacker","exp":99999999999}`))
				return strings.Join(parts, ".")
			},
			wantErr: "签名校验失败",
		},
		{
			name: "iss 非法",
			token: func() string {
				return makeIDTokenRS256(t, rsaKey, "kid-1",
					baseClaims(testClientID, map[string]any{"iss": "https://evil.example.com"}))
			},
			wantErr: "iss 声明非法",
		},
		{
			name: "aud 不匹配",
			token: func() string {
				return makeIDTokenRS256(t, rsaKey, "kid-1",
					baseClaims(testClientID, map[string]any{"aud": "com.other.app"}))
			},
			wantErr: "aud 声明",
		},
		{
			name: "token 已过期",
			token: func() string {
				return makeIDTokenRS256(t, rsaKey, "kid-1",
					baseClaims(testClientID, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}))
			},
			wantErr: "已过期",
		},
		{
			name: "exp 缺失",
			token: func() string {
				return makeIDTokenRS256(t, rsaKey, "kid-1",
					baseClaims(testClientID, map[string]any{"exp": nil}))
			},
			wantErr: "exp 声明缺失",
		},
		{
			name: "sub 缺失",
			token: func() string {
				return makeIDTokenRS256(t, rsaKey, "kid-1",
					baseClaims(testClientID, map[string]any{"sub": nil}))
			},
			wantErr: "sub 声明缺失",
		},
		{
			name: "未知 kid",
			token: func() string {
				return makeIDTokenRS256(t, rsaKey, "kid-unknown", baseClaims(testClientID, nil))
			},
			wantErr: "找不到 kid",
		},
		{
			name: "alg 与 JWK 不符（算法混淆）",
			token: func() string {
				// header 声明 ES256 但 kid 指向 RSA key
				token := makeIDTokenRS256(t, rsaKey, "kid-1", baseClaims(testClientID, nil))
				parts := strings.Split(token, ".")
				parts[0] = b64uEncode([]byte(`{"alg":"ES256","kid":"kid-1","typ":"JWT"}`))
				return strings.Join(parts, ".")
			},
			wantErr: "不一致",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.VerifyLogin(context.Background(), tc.token())
			if err == nil {
				t.Fatalf("期望错误（含 %q），实际成功", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误 %q 不含期望片段 %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestVerifyLogin_KeyRotation(t *testing.T) {
	// 模拟 Apple 轮换密钥：缓存里只有 kid-1，新 token 用 kid-2 → 触发强制刷新。
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, rsaJWKS(t, "kid-1", &key1.PublicKey))
	a := newLoginApple(t, srv.srv.URL)

	// 第一次登录灌满缓存（kid-1）。
	if _, err := a.VerifyLogin(context.Background(), makeIDTokenRS256(t, key1, "kid-1", baseClaims(testClientID, nil))); err != nil {
		t.Fatalf("首次登录失败: %v", err)
	}
	// 服务端轮换到 kid-2。
	srv.set(rsaJWKS(t, "kid-2", &key2.PublicKey), http.StatusOK)
	// 把缓存时钟拨过最小刷新间隔，允许未知 kid 触发强制刷新。
	a.jwks.now = func() time.Time { return time.Now().Add(2 * jwksMinRefreshInterval) }

	if _, err := a.VerifyLogin(context.Background(), makeIDTokenRS256(t, key2, "kid-2", baseClaims(testClientID, nil))); err != nil {
		t.Fatalf("轮换后登录失败: %v", err)
	}
}

func TestVerifyLogin_UnknownKidRefreshThrottled(t *testing.T) {
	// 最小刷新间隔内的未知 kid 不许反复打 JWKS 端点（防 DoS 放大）。
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, rsaJWKS(t, "kid-1", &key1.PublicKey))
	a := newLoginApple(t, srv.srv.URL)

	if _, err := a.VerifyLogin(context.Background(), makeIDTokenRS256(t, key1, "kid-1", baseClaims(testClientID, nil))); err != nil {
		t.Fatalf("首次登录失败: %v", err)
	}
	hitsBefore := srv.hits
	for i := 0; i < 5; i++ {
		_, err := a.VerifyLogin(context.Background(), makeIDTokenRS256(t, key1, "kid-x", baseClaims(testClientID, nil)))
		if err == nil {
			t.Fatal("未知 kid 应失败")
		}
	}
	if srv.hits != hitsBefore {
		t.Errorf("限流期内未知 kid 触发了 %d 次额外 JWKS 拉取，期望 0", srv.hits-hitsBefore)
	}
}

func TestVerifyLogin_NonceCheck(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := newJWKSServer(t, rsaJWKS(t, "kid-1", &rsaKey.PublicKey))

	var got string
	a := newLoginApple(t, srv.srv.URL, func(c *Config) {
		c.NonceCheck = func(nonce string) error {
			got = nonce
			if nonce != "expected-nonce" {
				return errors.New("nonce 不匹配")
			}
			return nil
		}
	})

	// nonce 匹配 → 成功
	token := makeIDTokenRS256(t, rsaKey, "kid-1", baseClaims(testClientID, map[string]any{"nonce": "expected-nonce"}))
	if _, err := a.VerifyLogin(context.Background(), token); err != nil {
		t.Fatalf("nonce 匹配应成功: %v", err)
	}
	if got != "expected-nonce" {
		t.Errorf("钩子收到 nonce=%q，期望 expected-nonce", got)
	}
	// nonce 不匹配 → 失败
	token = makeIDTokenRS256(t, rsaKey, "kid-1", baseClaims(testClientID, map[string]any{"nonce": "evil"}))
	if _, err := a.VerifyLogin(context.Background(), token); err == nil || !strings.Contains(err.Error(), "nonce 校验失败") {
		t.Fatalf("nonce 不匹配应失败，实际: %v", err)
	}
}

func TestVerifyLogin_NoClientID(t *testing.T) {
	// 只配支付凭据的实例没有登录能力。
	key := genECKey(t)
	a, err := New(Config{IssuerID: "i", KeyID: "k", PrivateKeyP8: p8PEM(t, key), BundleID: "b"})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if _, err := a.VerifyLogin(context.Background(), "whatever"); err == nil ||
		!strings.Contains(err.Error(), "未配置 Config.ClientID") {
		t.Fatalf("期望提示未配置 ClientID，实际: %v", err)
	}
}

func TestVerifyLogin_JWKSServerError(t *testing.T) {
	srv := newJWKSServer(t, []byte("oops"))
	srv.set([]byte("oops"), http.StatusInternalServerError)
	a := newLoginApple(t, srv.srv.URL)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := a.VerifyLogin(context.Background(), makeIDTokenRS256(t, rsaKey, "kid-1", baseClaims(testClientID, nil)))
	if err == nil {
		t.Fatal("JWKS 5xx 应失败")
	}
}
