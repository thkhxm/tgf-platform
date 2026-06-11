//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：VerifyLogin 单测——id_token 本地验签 / access_token 解析 / code 换 token 三形态 + JWKS 缓存与轮换
//2026/6/11
//***************************************************

package huawei

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
)

const (
	testKid             = "kid-2026-06"
	testUnionID         = "MDFAMTA0MzU4MTUxQHVuaW9u"
	testOpenID          = "MDFAMTA0MzU4MTUxQG9wZW4"
	testUserAccessToken = "CF0AtUserAccessToken001"
	testAuthCode        = "auth-code-001"
)

// baseIDClaims 构造一份基准合法的 ID Token 声明（字段名/语义取自官方声明表，
// 见 jwks.go idTokenClaims 注释的文档引用）。
func baseIDClaims(mutate func(map[string]any)) map[string]any {
	now := time.Now()
	claims := map[string]any{
		"iss":            idTokenIssuer,
		"sub":            testUnionID, // 官方："sub 即用户的 UnionId"
		"aud":            testClientID,
		"azp":            testClientID,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Add(-time.Minute).Unix(),
		"display_name":   "测试用户",
		"email":          "user@example.com",
		"email_verified": true,
	}
	if mutate != nil {
		mutate(claims)
	}
	return claims
}

// signJWTWithKey 用任意私钥签发 RS256 JWT（"他人密钥签名"攻击用例；
// testutil 的 signJWT 固定用共享测试密钥）。
func signJWTWithKey(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	pb, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("签发攻击 JWT 失败: %v", err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// tamperJWTPayload 替换 JWT 的 payload 段但保留原签名（签名比对失败用例）。
func tamperJWTPayload(t *testing.T, token string, claims map[string]any) string {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token 不是三段式 JWT: %s", token)
	}
	pb, _ := json.Marshal(claims)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(pb) + "." + parts[2]
}

// newIDTokenServer 起一个 OIDC 发现 + JWKS mock server；hits 记 /certs 拉取次数
// （缓存行为断言用）。
func newIDTokenServer(t *testing.T) (*httptest.Server, *jwksHandler, *atomic.Int64) {
	t.Helper()
	mux := http.NewServeMux()
	jh := &jwksHandler{}
	jh.setKids(testKid)
	jh.register(t, mux)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/certs" {
			hits.Add(1)
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, jh, &hits
}

// newIDTokenHuawei 构造 id_token 凭据形态、接到 mock JWKS 的实例。
func newIDTokenHuawei(t *testing.T, baseURL string, mutate func(*Config)) *Huawei {
	t.Helper()
	cfg := Config{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		OAuthBaseURL: baseURL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return h
}

func TestVerifyLoginIDToken(t *testing.T) {
	cases := []struct {
		name        string
		credential  func(t *testing.T) string
		wantOK      bool
		wantContain string // 失败时 err.Error() 应包含的片段；空 = 只断言失败
	}{
		{
			name:   "成功_RS256标准token",
			wantOK: true,
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "RS256", baseIDClaims(nil))
			},
		},
		{
			name:   "成功_PS256签名",
			wantOK: true,
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "PS256", baseIDClaims(nil))
			},
		},
		{
			name:   "成功_aud数组形态命中本应用",
			wantOK: true,
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "RS256", baseIDClaims(func(c map[string]any) {
					c["aud"] = []string{"other-app-id", testClientID}
				}))
			},
		},
		{
			name:        "失败_credential为空",
			credential:  func(t *testing.T) string { return "" },
			wantContain: "credential 为空",
		},
		{
			name:        "失败_非JWT格式",
			credential:  func(t *testing.T) string { return "not-a-jwt" },
			wantContain: "格式非法",
		},
		{
			name:        "失败_JWT四段",
			credential:  func(t *testing.T) string { return "a.b.c.d" },
			wantContain: "超过 3 段",
		},
		{
			name:        "失败_header非base64url",
			credential:  func(t *testing.T) string { return "@@@.YWJj.YWJj" },
			wantContain: "base64url",
		},
		{
			name: "失败_alg为HS256拒绝",
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "HS256", baseIDClaims(nil))
			},
			wantContain: "不支持的签名算法",
		},
		{
			name: "失败_alg为none拒绝",
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "none", baseIDClaims(nil))
			},
			wantContain: "不支持的签名算法",
		},
		{
			name: "失败_缺kid",
			credential: func(t *testing.T) string {
				return signJWT(t, "", "RS256", baseIDClaims(nil))
			},
			wantContain: "缺少 kid",
		},
		{
			name: "失败_kid未知强刷仍未命中",
			credential: func(t *testing.T) string {
				return signJWT(t, "kid-unknown", "RS256", baseIDClaims(nil))
			},
			wantContain: "JWKS 中不存在",
		},
		{
			name: "失败_payload篡改保留原签名",
			credential: func(t *testing.T) string {
				token := signJWT(t, testKid, "RS256", baseIDClaims(nil))
				return tamperJWTPayload(t, token, baseIDClaims(func(c map[string]any) {
					c["sub"] = "attacker-union-id"
				}))
			},
			wantContain: "签名校验失败",
		},
		{
			name: "失败_他人密钥签名",
			credential: func(t *testing.T) string {
				attacker, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("生成攻击密钥失败: %v", err)
				}
				return signJWTWithKey(t, attacker, testKid, baseIDClaims(nil))
			},
			wantContain: "签名校验失败",
		},
		{
			name: "失败_iss不匹配",
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "RS256", baseIDClaims(func(c map[string]any) {
					c["iss"] = "https://evil.example.com"
				}))
			},
			wantContain: "iss 不匹配",
		},
		{
			name: "失败_aud不含本应用",
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "RS256", baseIDClaims(func(c map[string]any) {
					c["aud"] = "evil-app-id"
				}))
			},
			wantContain: "aud 不含本应用",
		},
		{
			name: "失败_token已过期",
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "RS256", baseIDClaims(func(c map[string]any) {
					c["exp"] = time.Now().Add(-time.Hour).Unix()
				}))
			},
			wantContain: "已过期",
		},
		{
			name: "失败_缺sub",
			credential: func(t *testing.T) string {
				return signJWT(t, testKid, "RS256", baseIDClaims(func(c map[string]any) {
					delete(c, "sub")
				}))
			},
			wantContain: "缺少 sub",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newIDTokenServer(t)
			h := newIDTokenHuawei(t, srv.URL, nil)
			identity, err := h.VerifyLogin(context.Background(), tc.credential(t))
			if tc.wantOK {
				if err != nil {
					t.Fatalf("VerifyLogin 应成功，实际失败: %v", err)
				}
				if identity.Platform != PlatformName {
					t.Errorf("Platform = %q, 期望 %q", identity.Platform, PlatformName)
				}
				if identity.UnionID != testUnionID {
					t.Errorf("UnionID = %q, 期望 sub %q", identity.UnionID, testUnionID)
				}
				// 华为 ID Token 声明表没有 open_id 字段，OpenID 必须留空（绝不杜撰映射）。
				if identity.OpenID != "" || identity.SessionKey != "" {
					t.Errorf("OpenID/SessionKey 应为空，实际 %q/%q", identity.OpenID, identity.SessionKey)
				}
				return
			}
			if err == nil {
				t.Fatalf("VerifyLogin 应失败，实际成功: %+v", identity)
			}
			if _, ok := errs.AsPlatformError(err); !ok {
				t.Errorf("错误应为 *errs.Error，实际 %T: %v", err, err)
			}
			if tc.wantContain != "" && !strings.Contains(err.Error(), tc.wantContain) {
				t.Errorf("错误信息应包含 %q，实际: %v", tc.wantContain, err)
			}
		})
	}
}

// TestVerifyLoginIDTokenRawMapping 校验全量声明经 Raw 透传（字符串/布尔/数字形态归一）。
func TestVerifyLoginIDTokenRawMapping(t *testing.T) {
	srv, _, _ := newIDTokenServer(t)
	h := newIDTokenHuawei(t, srv.URL, nil)

	exp := time.Now().Add(time.Hour).Unix()
	token := signJWT(t, testKid, "RS256", baseIDClaims(func(c map[string]any) {
		c["exp"] = exp
	}))
	identity, err := h.VerifyLogin(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}
	for k, want := range map[string]string{
		"iss":            idTokenIssuer,
		"sub":            testUnionID,
		"aud":            testClientID,
		"display_name":   "测试用户",
		"email":          "user@example.com",
		"email_verified": "true",                     // 布尔声明 → "true"/"false"
		"exp":            strconv.FormatInt(exp, 10), // 整数声明 → 不带小数点
	} {
		if got := identity.Raw[k]; got != want {
			t.Errorf("Raw[%q] = %q, 期望 %q", k, got, want)
		}
	}
}

// TestVerifyLoginJWKSCacheAndRotation 校验 JWKS 缓存与密钥轮换：
// 缓存有效期内多次校验只拉一次；未知 kid 强制刷新一次兜底；旧 kid 下线后拒绝。
func TestVerifyLoginJWKSCacheAndRotation(t *testing.T) {
	srv, jh, hits := newIDTokenServer(t)
	h := newIDTokenHuawei(t, srv.URL, nil)

	for i := 0; i < 3; i++ {
		if _, err := h.VerifyLogin(context.Background(), signJWT(t, testKid, "RS256", baseIDClaims(nil))); err != nil {
			t.Fatalf("第 %d 次 VerifyLogin 失败: %v", i+1, err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("缓存有效期内 JWKS 应只拉取 1 次，实际 %d 次", n)
	}

	// 轮换：服务端只发布新 kid——新 kid 的 token 经强制刷新后应通过。
	const newKid = "kid-2026-12"
	jh.setKids(newKid)
	if _, err := h.VerifyLogin(context.Background(), signJWT(t, newKid, "RS256", baseIDClaims(nil))); err != nil {
		t.Fatalf("轮换后新 kid 的 token 应通过（未知 kid 强制刷新兜底），实际失败: %v", err)
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("未知 kid 应触发一次强制刷新，期望累计 2 次拉取，实际 %d 次", n)
	}

	// 旧 kid 已下线：再强刷一次仍未命中 → 拒绝。
	_, err := h.VerifyLogin(context.Background(), signJWT(t, testKid, "RS256", baseIDClaims(nil)))
	if err == nil || !strings.Contains(err.Error(), "已强制刷新仍未命中") {
		t.Errorf("旧 kid 下线后应拒绝并提示强刷未命中，实际: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("旧 kid 校验应再触发一次强制刷新，期望累计 3 次拉取，实际 %d 次", n)
	}
}

// TestVerifyLoginJWKSTTLExpire 校验 TTL 到期后重新拉取。
func TestVerifyLoginJWKSTTLExpire(t *testing.T) {
	srv, _, hits := newIDTokenServer(t)
	h := newIDTokenHuawei(t, srv.URL, func(c *Config) { c.JWKSCacheTTL = time.Nanosecond })

	for i := 0; i < 2; i++ {
		if _, err := h.VerifyLogin(context.Background(), signJWT(t, testKid, "RS256", baseIDClaims(nil))); err != nil {
			t.Fatalf("第 %d 次 VerifyLogin 失败: %v", i+1, err)
		}
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("TTL 到期后应重新拉取 JWKS，期望 2 次，实际 %d 次", n)
	}
}

// ---------- access_token / code 形态共用的帐号服务 mock ----------

// accountServer 是华为帐号服务 mock：/oauth2/v3/token + /rest.php（getTokenInfo）。
type accountServer struct {
	srv              *httptest.Server
	tokenHandler     http.HandlerFunc
	tokenInfoHandler http.HandlerFunc
}

func newAccountServer(t *testing.T) *accountServer {
	t.Helper()
	s := &accountServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/v3/token", func(w http.ResponseWriter, r *http.Request) {
		if s.tokenHandler == nil {
			t.Error("用例未注入 tokenHandler，却收到 oauth2/v3/token 请求")
			http.Error(w, "no handler", http.StatusInternalServerError)
			return
		}
		s.tokenHandler(w, r)
	})
	mux.HandleFunc("/rest.php", func(w http.ResponseWriter, r *http.Request) {
		// 公共断言：NSP 固定查询串 + open_id 固定入参（官方协议，见 getTokenInfoPath 注释）。
		if got := r.URL.Query().Get("nsp_svc"); got != "huawei.oauth2.user.getTokenInfo" {
			t.Errorf("nsp_svc = %q, 期望 huawei.oauth2.user.getTokenInfo", got)
		}
		if got := r.URL.Query().Get("nsp_fmt"); got != "JSON" {
			t.Errorf("nsp_fmt = %q, 期望 JSON", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("解析 rest.php 表单失败: %v", err)
		}
		if got := r.PostForm.Get("open_id"); got != "OPENID" {
			t.Errorf("open_id = %q, 期望固定值 OPENID", got)
		}
		if r.PostForm.Get("access_token") == "" {
			t.Error("rest.php 表单缺少 access_token")
		}
		if s.tokenInfoHandler == nil {
			t.Error("用例未注入 tokenInfoHandler，却收到 rest.php 请求")
			http.Error(w, "no handler", http.StatusInternalServerError)
			return
		}
		s.tokenInfoHandler(w, r)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// jsonHandler 返回固定 JSON 应答的 handler。
func jsonHandler(status int, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// nspHandler 返回带 NSP_STATUS 响应头的 handler（开放平台错误形态）。
func nspHandler(status int, nsp, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("NSP_STATUS", nsp)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// tokenInfoBody 构造 getTokenInfo 成功应答（字段表见 login.go getTokenInfoResp 注释）。
func tokenInfoBody(mutate func(map[string]any)) map[string]any {
	body := map[string]any{
		"client_id": testClientID,
		"expire_in": 3600,
		"union_id":  testUnionID,
		"open_id":   testOpenID,
		"scope":     "openid profile",
	}
	if mutate != nil {
		mutate(body)
	}
	return body
}

func TestVerifyLoginAccessToken(t *testing.T) {
	newAccessTokenHuawei := func(t *testing.T, s *accountServer) *Huawei {
		t.Helper()
		h, err := New(Config{
			ClientID:        testClientID,
			ClientSecret:    testClientSecret,
			CredentialType:  CredentialAccessToken,
			OAuthAPIBaseURL: s.srv.URL,
		})
		if err != nil {
			t.Fatalf("New 失败: %v", err)
		}
		return h
	}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		check   func(t *testing.T, h *Huawei, err error, openID, unionID string, raw map[string]string)
	}{
		{
			name:    "成功_用户级AT解析",
			handler: jsonHandler(200, tokenInfoBody(nil)),
			check: func(t *testing.T, h *Huawei, err error, openID, unionID string, raw map[string]string) {
				if err != nil {
					t.Fatalf("应成功，实际失败: %v", err)
				}
				if openID != testOpenID || unionID != testUnionID {
					t.Errorf("OpenID/UnionID = %q/%q, 期望 %q/%q", openID, unionID, testOpenID, testUnionID)
				}
				for k, want := range map[string]string{
					"client_id": testClientID,
					"scope":     "openid profile",
					"expire_in": "3600",
				} {
					if got := raw[k]; got != want {
						t.Errorf("Raw[%q] = %q, 期望 %q", k, got, want)
					}
				}
			},
		},
		{
			name:    "失败_NSP_STATUS_6_token过期不可重试",
			handler: nspHandler(200, "6", `{"error":"access token expire"}`),
			check: func(t *testing.T, h *Huawei, err error, _, _ string, _ map[string]string) {
				if err == nil {
					t.Fatal("NSP_STATUS=6 应失败")
				}
				if code := errs.CodeOf(err); code != "NSP_6" {
					t.Errorf("CodeOf = %q, 期望 NSP_6", code)
				}
				if errs.IsRetryable(err) {
					t.Error("token 过期是确定性失败，不应可重试")
				}
			},
		},
		{
			name:    "失败_NSP_STATUS_2_服务临时不可用可重试",
			handler: nspHandler(200, "2", `{"error":"service temporarily unavailable"}`),
			check: func(t *testing.T, h *Huawei, err error, _, _ string, _ map[string]string) {
				if err == nil {
					t.Fatal("NSP_STATUS=2 应失败")
				}
				if code := errs.CodeOf(err); code != "NSP_2" {
					t.Errorf("CodeOf = %q, 期望 NSP_2", code)
				}
				if !errs.IsRetryable(err) {
					t.Error("服务临时不可用应标记可重试")
				}
			},
		},
		{
			name:    "失败_HTTP500可重试",
			handler: jsonHandler(500, map[string]any{"error": "internal"}),
			check: func(t *testing.T, h *Huawei, err error, _, _ string, _ map[string]string) {
				if err == nil {
					t.Fatal("HTTP 500 应失败")
				}
				if !errs.IsRetryable(err) {
					t.Error("5xx 应标记可重试")
				}
			},
		},
		{
			name: "失败_client_id不匹配防串号",
			handler: jsonHandler(200, tokenInfoBody(func(b map[string]any) {
				b["client_id"] = "999999999"
			})),
			check: func(t *testing.T, h *Huawei, err error, _, _ string, _ map[string]string) {
				if err == nil || !strings.Contains(err.Error(), "client_id 不匹配") {
					t.Errorf("client_id 不一致应被防串号拦截，实际: %v", err)
				}
			},
		},
		{
			name: "失败_缺open_id疑似应用级AT",
			handler: jsonHandler(200, tokenInfoBody(func(b map[string]any) {
				delete(b, "open_id")
			})),
			check: func(t *testing.T, h *Huawei, err error, _, _ string, _ map[string]string) {
				if err == nil || !strings.Contains(err.Error(), "缺少 open_id") {
					t.Errorf("缺 open_id 应失败，实际: %v", err)
				}
			},
		},
		{
			name: "失败_应答非JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				_, _ = w.Write([]byte("<html>error page</html>"))
			},
			check: func(t *testing.T, h *Huawei, err error, _, _ string, _ map[string]string) {
				if err == nil {
					t.Fatal("非 JSON 应答应失败")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAccountServer(t)
			s.tokenInfoHandler = tc.handler
			h := newAccessTokenHuawei(t, s)
			identity, err := h.VerifyLogin(context.Background(), testUserAccessToken)
			var openID, unionID string
			var raw map[string]string
			if identity != nil {
				openID, unionID, raw = identity.OpenID, identity.UnionID, identity.Raw
				if identity.Platform != PlatformName {
					t.Errorf("Platform = %q, 期望 %q", identity.Platform, PlatformName)
				}
			}
			tc.check(t, h, err, openID, unionID, raw)
		})
	}
}

func TestVerifyLoginAuthCode(t *testing.T) {
	// okTokenHandler 按官方 authorization_code 协议断言后发 token。
	// wantRedirectURI 为空表示表单不应携带 redirect_uri。
	okTokenHandler := func(t *testing.T, wantRedirectURI string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("解析 token 表单失败: %v", err)
			}
			if got := r.PostForm.Get("grant_type"); got != "authorization_code" {
				t.Errorf("grant_type = %q, 期望 authorization_code", got)
			}
			if got := r.PostForm.Get("client_id"); got != testClientID {
				t.Errorf("client_id = %q, 期望 %q", got, testClientID)
			}
			if got := r.PostForm.Get("client_secret"); got != testClientSecret {
				t.Errorf("client_secret = %q, 期望 %q", got, testClientSecret)
			}
			if got := r.PostForm.Get("code"); got != testAuthCode {
				t.Errorf("code = %q, 期望 %q", got, testAuthCode)
			}
			gotURI, hasURI := r.PostForm["redirect_uri"]
			if wantRedirectURI == "" && hasURI {
				t.Errorf("未配置 RedirectURI 时表单不应携带 redirect_uri，实际 %v", gotURI)
			}
			if wantRedirectURI != "" && r.PostForm.Get("redirect_uri") != wantRedirectURI {
				t.Errorf("redirect_uri = %q, 期望 %q", r.PostForm.Get("redirect_uri"), wantRedirectURI)
			}
			jsonHandler(200, map[string]any{
				"access_token":  testUserAccessToken,
				"refresh_token": "rt-001",
				"id_token":      "idt-001",
				"expires_in":    3600,
				"scope":         "openid profile",
				"token_type":    "Bearer",
			})(w, r)
		}
	}

	newAuthCodeHuawei := func(t *testing.T, s *accountServer, mutate func(*Config)) *Huawei {
		t.Helper()
		cfg := Config{
			ClientID:        testClientID,
			ClientSecret:    testClientSecret,
			CredentialType:  CredentialAuthCode,
			OAuthBaseURL:    s.srv.URL,
			OAuthAPIBaseURL: s.srv.URL,
		}
		if mutate != nil {
			mutate(&cfg)
		}
		h, err := New(cfg)
		if err != nil {
			t.Fatalf("New 失败: %v", err)
		}
		return h
	}

	t.Run("成功_带redirect_uri", func(t *testing.T) {
		const redirectURI = "https://game.example.com/hw/callback"
		s := newAccountServer(t)
		s.tokenHandler = okTokenHandler(t, redirectURI)
		s.tokenInfoHandler = func(w http.ResponseWriter, r *http.Request) {
			// 换到的用户级 AT 应原样传给 getTokenInfo。
			if got := r.PostForm.Get("access_token"); got != testUserAccessToken {
				t.Errorf("getTokenInfo access_token = %q, 期望换 token 所得 %q", got, testUserAccessToken)
			}
			jsonHandler(200, tokenInfoBody(nil))(w, r)
		}
		h := newAuthCodeHuawei(t, s, func(c *Config) { c.RedirectURI = redirectURI })

		identity, err := h.VerifyLogin(context.Background(), testAuthCode)
		if err != nil {
			t.Fatalf("VerifyLogin 失败: %v", err)
		}
		if identity.OpenID != testOpenID || identity.UnionID != testUnionID {
			t.Errorf("OpenID/UnionID = %q/%q, 期望 %q/%q",
				identity.OpenID, identity.UnionID, testOpenID, testUnionID)
		}
		for k, want := range map[string]string{
			"access_token":  testUserAccessToken,
			"refresh_token": "rt-001",
			"id_token":      "idt-001",
			"expires_in":    "3600",
			"scope":         "openid profile",
			"token_type":    "Bearer",
		} {
			if got := identity.Raw[k]; got != want {
				t.Errorf("Raw[%q] = %q, 期望 %q", k, got, want)
			}
		}
	})

	t.Run("成功_不带redirect_uri", func(t *testing.T) {
		s := newAccountServer(t)
		s.tokenHandler = okTokenHandler(t, "")
		s.tokenInfoHandler = jsonHandler(200, tokenInfoBody(nil))
		h := newAuthCodeHuawei(t, s, nil)
		if _, err := h.VerifyLogin(context.Background(), testAuthCode); err != nil {
			t.Fatalf("VerifyLogin 失败: %v", err)
		}
	})

	t.Run("失败_code已被消费透传错误码", func(t *testing.T) {
		s := newAccountServer(t)
		// 官方失败应答形态（HTTP 400 + int 主/子错误码；1101/20156 = code 已被消费）。
		s.tokenHandler = jsonHandler(400, map[string]any{
			"error":             1101,
			"sub_error":         20156,
			"error_description": "authorization code has been used",
		})
		h := newAuthCodeHuawei(t, s, nil)

		_, err := h.VerifyLogin(context.Background(), testAuthCode)
		if err == nil {
			t.Fatal("code 已被消费应失败")
		}
		if code := errs.CodeOf(err); code != "1101.20156" {
			t.Errorf("CodeOf = %q, 期望透传 主.子 错误码 1101.20156", code)
		}
		if errs.IsRetryable(err) {
			t.Error("code 一次性失效是确定性失败，不应可重试")
		}
	})

	t.Run("失败_应答缺access_token", func(t *testing.T) {
		s := newAccountServer(t)
		s.tokenHandler = jsonHandler(200, map[string]any{"expires_in": 3600})
		h := newAuthCodeHuawei(t, s, nil)

		_, err := h.VerifyLogin(context.Background(), testAuthCode)
		if err == nil || !strings.Contains(err.Error(), "缺少 access_token") {
			t.Errorf("应答缺 access_token 应失败，实际: %v", err)
		}
	})

	t.Run("失败_换token成功但getTokenInfo报错", func(t *testing.T) {
		s := newAccountServer(t)
		s.tokenHandler = okTokenHandler(t, "")
		s.tokenInfoHandler = nspHandler(200, "6", `{"error":"access token expire"}`)
		h := newAuthCodeHuawei(t, s, nil)

		_, err := h.VerifyLogin(context.Background(), testAuthCode)
		if err == nil {
			t.Fatal("getTokenInfo 报错时应失败")
		}
		if code := errs.CodeOf(err); code != "NSP_6" {
			t.Errorf("CodeOf = %q, 期望 NSP_6", code)
		}
	})
}
