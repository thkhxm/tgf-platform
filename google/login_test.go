//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：VerifyLogin 单测——ID token 验签 / claim 校验 / 身份映射 / JWKS 缓存
//2026/6/11
//***************************************************

package google

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
)

const (
	testKid      = "kid-1"
	testClientID = "1008719970978-hb24n2dstb40o45d4feuo2ukqmcc6381.apps.googleusercontent.com"
	testSub      = "110169484474386276334"
)

// idTokenClaims 构造一份基准合法 claims（字段名/形态取自官方 tokeninfo 示例，
// https://developers.google.com/identity/sign-in/web/backend-auth ，2026-06-11 拉取）。
func idTokenClaims(mutate func(map[string]any)) map[string]any {
	now := time.Now()
	claims := map[string]any{
		"iss":            "https://accounts.google.com",
		"sub":            testSub,
		"azp":            testClientID,
		"aud":            testClientID,
		"iat":            now.Add(-time.Minute).Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"email":          "testuser@gmail.com",
		"email_verified": true,
		"name":           "Test User",
		"picture":        "https://lh4.googleusercontent.com/photo.jpg",
		"given_name":     "Test",
		"family_name":    "User",
		"locale":         "en",
	}
	if mutate != nil {
		mutate(claims)
	}
	return claims
}

// newLoginGoogle 构造接到 mock JWKS 的登录态实例。
func newLoginGoogle(t *testing.T, jwksURL string, mutate func(*Config)) *Google {
	t.Helper()
	cfg := Config{
		ClientIDs: []string{testClientID},
		JWKSURL:   jwksURL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return g
}

func TestVerifyLogin(t *testing.T) {
	priv := testRSAKey(t)
	srv, _ := newJWKSServer(t, []map[string]any{jwkOf(testKid, &priv.PublicKey)})
	rs256Header := map[string]any{"alg": "RS256", "kid": testKid, "typ": "JWT"}

	cases := []struct {
		name       string
		mutateCfg  func(*Config)
		credential func(t *testing.T) string
		wantErrIs  error // nil 表示只断言出错（无哨兵）；wantOK 时忽略
		wantOK     bool
	}{
		{
			name:   "成功_标准ID_token",
			wantOK: true,
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(nil))
			},
		},
		{
			name:   "成功_iss不带https前缀形态",
			wantOK: true,
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(func(c map[string]any) {
					c["iss"] = "accounts.google.com"
				}))
			},
		},
		{
			name:   "成功_aud数组形态命中白名单",
			wantOK: true,
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(func(c map[string]any) {
					c["aud"] = []string{"other-client", testClientID}
				}))
			},
		},
		{
			name:       "失败_credential为空",
			credential: func(t *testing.T) string { return "" },
		},
		{
			name: "失败_aud不在白名单",
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(func(c map[string]any) {
					c["aud"] = "evil-client-id"
				}))
			},
		},
		{
			name:      "失败_iss非Google",
			wantErrIs: ErrJWTIssuerMismatch,
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(func(c map[string]any) {
					c["iss"] = "https://evil.example.com"
				}))
			},
		},
		{
			name:      "失败_exp已过期",
			wantErrIs: ErrJWTExpired,
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(func(c map[string]any) {
					c["exp"] = time.Now().Add(-DefaultClockSkew - time.Hour).Unix()
				}))
			},
		},
		{
			name:      "失败_iat在未来",
			wantErrIs: ErrJWTIssuedInFuture,
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(func(c map[string]any) {
					c["iat"] = time.Now().Add(DefaultClockSkew + time.Hour).Unix()
				}))
			},
		},
		{
			name:      "失败_claims被篡改保留原签名",
			wantErrIs: ErrJWTSignatureMismatch,
			credential: func(t *testing.T) string {
				token := makeJWT(t, priv, rs256Header, idTokenClaims(nil))
				return tamperJWTClaims(t, token, idTokenClaims(func(c map[string]any) {
					c["sub"] = "999999999999999999999"
				}))
			},
		},
		{
			name:      "失败_他人密钥签名",
			wantErrIs: ErrJWTSignatureMismatch,
			credential: func(t *testing.T) string {
				attacker := testRSAKey(t)
				return makeJWT(t, attacker, rs256Header, idTokenClaims(nil))
			},
		},
		{
			name:      "失败_alg非RS256",
			wantErrIs: ErrJWTUnexpectedAlg,
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, map[string]any{"alg": "HS256", "kid": testKid, "typ": "JWT"},
					idTokenClaims(nil))
			},
		},
		{
			name:      "失败_kid未知",
			wantErrIs: ErrJWTUnknownKeyID,
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, map[string]any{"alg": "RS256", "kid": "kid-unknown", "typ": "JWT"},
					idTokenClaims(nil))
			},
		},
		{
			name:       "失败_非JWT格式",
			wantErrIs:  ErrJWTMalformed,
			credential: func(t *testing.T) string { return "not-a-jwt" },
		},
		{
			name: "失败_缺sub",
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(func(c map[string]any) {
					delete(c, "sub")
				}))
			},
		},
		{
			name:      "失败_配置了HostedDomain但token无hd",
			mutateCfg: func(c *Config) { c.HostedDomain = "example.com" },
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(nil))
			},
		},
		{
			name:      "成功_HostedDomain匹配",
			wantOK:    true,
			mutateCfg: func(c *Config) { c.HostedDomain = "example.com" },
			credential: func(t *testing.T) string {
				return makeJWT(t, priv, rs256Header, idTokenClaims(func(c map[string]any) {
					c["hd"] = "example.com"
				}))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newLoginGoogle(t, srv.URL, tc.mutateCfg)
			identity, err := g.VerifyLogin(context.Background(), tc.credential(t))
			if tc.wantOK {
				if err != nil {
					t.Fatalf("VerifyLogin 应成功，实际失败: %v", err)
				}
				if identity.Platform != PlatformName {
					t.Errorf("Platform = %q, 期望 %q", identity.Platform, PlatformName)
				}
				if identity.OpenID != testSub {
					t.Errorf("OpenID = %q, 期望 sub %q", identity.OpenID, testSub)
				}
				if identity.UnionID != "" || identity.SessionKey != "" {
					t.Errorf("UnionID/SessionKey 应为空（Google 无此概念），实际 %q/%q",
						identity.UnionID, identity.SessionKey)
				}
				return
			}
			if err == nil {
				t.Fatalf("VerifyLogin 应失败，实际成功: %+v", identity)
			}
			if _, ok := errs.AsPlatformError(err); !ok {
				t.Errorf("错误应为 *errs.Error，实际 %T: %v", err, err)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("错误链应命中 %v，实际: %v", tc.wantErrIs, err)
			}
		})
	}
}

// TestVerifyLoginRawMapping 校验 Raw 透传字段映射。
func TestVerifyLoginRawMapping(t *testing.T) {
	priv := testRSAKey(t)
	srv, _ := newJWKSServer(t, []map[string]any{jwkOf(testKid, &priv.PublicKey)})
	g := newLoginGoogle(t, srv.URL, nil)

	token := makeJWT(t, priv, map[string]any{"alg": "RS256", "kid": testKid, "typ": "JWT"},
		idTokenClaims(nil))
	identity, err := g.VerifyLogin(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}
	for k, want := range map[string]string{
		"iss":            "https://accounts.google.com",
		"aud":            testClientID,
		"azp":            testClientID,
		"email":          "testuser@gmail.com",
		"email_verified": "true",
		"name":           "Test User",
		"given_name":     "Test",
		"family_name":    "User",
		"locale":         "en",
	} {
		if got := identity.Raw[k]; got != want {
			t.Errorf("Raw[%q] = %q, 期望 %q", k, got, want)
		}
	}
	if identity.Raw["hd"] != "" {
		t.Errorf("无 hd claim 时 Raw 不应有 hd，实际 %q", identity.Raw["hd"])
	}
}

// TestVerifyLoginJWKSCache 校验 JWKS 缓存：缓存有效期内多次校验只拉一次；
// 未知 kid 在限频窗口内不触发二次拉取。
func TestVerifyLoginJWKSCache(t *testing.T) {
	priv := testRSAKey(t)
	srv, hits := newJWKSServer(t, []map[string]any{jwkOf(testKid, &priv.PublicKey)})
	g := newLoginGoogle(t, srv.URL, nil)
	header := map[string]any{"alg": "RS256", "kid": testKid, "typ": "JWT"}

	for i := 0; i < 3; i++ {
		if _, err := g.VerifyLogin(context.Background(), makeJWT(t, priv, header, idTokenClaims(nil))); err != nil {
			t.Fatalf("第 %d 次 VerifyLogin 失败: %v", i+1, err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("缓存有效期内 JWKS 应只拉取 1 次，实际 %d 次", n)
	}

	// 未知 kid：刚拉取过（限频窗口内）不应再打 JWKS 端点。
	badHeader := map[string]any{"alg": "RS256", "kid": "kid-unknown", "typ": "JWT"}
	_, err := g.VerifyLogin(context.Background(), makeJWT(t, priv, badHeader, idTokenClaims(nil)))
	if !errors.Is(err, ErrJWTUnknownKeyID) {
		t.Fatalf("未知 kid 应返回 ErrJWTUnknownKeyID，实际: %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("限频窗口内未知 kid 不应触发二次拉取，实际 %d 次", n)
	}
}

// TestVerifyLoginNotConfigured 未配置登录能力时报明确错误。
func TestVerifyLoginNotConfigured(t *testing.T) {
	g, err := New(Config{
		PubSubAudience:            "https://example.com/rtdn",
		PubSubServiceAccountEmail: "push@proj.iam.gserviceaccount.com",
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if _, err := g.VerifyLogin(context.Background(), "whatever"); err == nil {
		t.Fatal("未配置 ClientIDs 时 VerifyLogin 应失败")
	}
}
