//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：New 构造器 fail-fast 校验 / IAP 公钥解析 / 鉴权头格式 / 内存去重表单测
//2026/6/11
//***************************************************

package huawei

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"
)

// 全部测试文件共享的应用凭据常量（同包可见）。
const (
	testClientID     = "104358151"
	testClientSecret = "f3a9c2d1-test-client-secret"
)

// pemOfTestPublicKey 把测试 RSA 公钥编码为 PEM（Config.IAPPublicKey 的 PEM 兼容形态）。
func pemOfTestPublicKey(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&testRSAKey(t).PublicKey)
	if err != nil {
		t.Fatalf("公钥编码失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// ecPublicKeyB64 生成一把 EC 公钥的 base64 PKIX DER（非 RSA 类型拒绝用例）。
func ecPublicKeyB64(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 EC 测试密钥失败: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("EC 公钥编码失败: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     func(t *testing.T) Config
		wantErr bool
		check   func(t *testing.T, h *Huawei)
	}{
		{
			name:    "失败_缺ClientID",
			cfg:     func(t *testing.T) Config { return Config{ClientSecret: testClientSecret} },
			wantErr: true,
		},
		{
			name:    "失败_缺ClientSecret",
			cfg:     func(t *testing.T) Config { return Config{ClientID: testClientID} },
			wantErr: true,
		},
		{
			name: "成功_最小配置默认值齐备",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret}
			},
			check: func(t *testing.T, h *Huawei) {
				if h.cfg.CredentialType != CredentialIDToken {
					t.Errorf("CredentialType 默认 = %q, 期望 %q", h.cfg.CredentialType, CredentialIDToken)
				}
				if h.cfg.OAuthBaseURL != DefaultOAuthBaseURL {
					t.Errorf("OAuthBaseURL 默认 = %q, 期望 %q", h.cfg.OAuthBaseURL, DefaultOAuthBaseURL)
				}
				if h.cfg.OAuthAPIBaseURL != DefaultOAuthAPIBaseURL {
					t.Errorf("OAuthAPIBaseURL 默认 = %q, 期望 %q", h.cfg.OAuthAPIBaseURL, DefaultOAuthAPIBaseURL)
				}
				if h.cfg.OrderSiteURL != OrderSiteChina {
					t.Errorf("OrderSiteURL 默认 = %q, 期望中国站点", h.cfg.OrderSiteURL)
				}
				if h.cfg.SubscriptionSiteURL != SubscriptionSiteChina {
					t.Errorf("SubscriptionSiteURL 默认 = %q, 期望中国站点", h.cfg.SubscriptionSiteURL)
				}
				if h.cfg.JWKSCacheTTL != DefaultJWKSCacheTTL {
					t.Errorf("JWKSCacheTTL 默认 = %v, 期望 %v", h.cfg.JWKSCacheTTL, DefaultJWKSCacheTTL)
				}
				if h.cfg.WebhookTolerance != DefaultWebhookTolerance {
					t.Errorf("WebhookTolerance 默认 = %v, 期望 %v", h.cfg.WebhookTolerance, DefaultWebhookTolerance)
				}
				if h.cfg.WebhookMaxBodySize != DefaultWebhookMaxBodySize {
					t.Errorf("WebhookMaxBodySize 默认 = %d, 期望 %d", h.cfg.WebhookMaxBodySize, DefaultWebhookMaxBodySize)
				}
				if h.seen == nil {
					t.Error("未注入 WebhookSeen 时应使用内置内存去重")
				}
				if h.now == nil {
					t.Error("时钟未初始化")
				}
				if h.iapPublicKey != nil {
					t.Error("未配置 IAPPublicKey 时 iapPublicKey 应为 nil")
				}
			},
		},
		{
			name: "成功_凭据形态access_token",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret,
					CredentialType: CredentialAccessToken}
			},
		},
		{
			name: "成功_凭据形态code",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret,
					CredentialType: CredentialAuthCode}
			},
		},
		{
			name: "失败_凭据形态非法",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret,
					CredentialType: "wechat_code"}
			},
			wantErr: true,
		},
		{
			name: "成功_IAP公钥base64DER形态",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret,
					IAPPublicKey: testIAPPublicKeyB64(t)}
			},
			check: func(t *testing.T, h *Huawei) {
				if h.iapPublicKey == nil {
					t.Error("base64 DER 公钥应解析成功")
				}
			},
		},
		{
			name: "成功_IAP公钥PEM形态",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret,
					IAPPublicKey: pemOfTestPublicKey(t)}
			},
			check: func(t *testing.T, h *Huawei) {
				if h.iapPublicKey == nil {
					t.Error("PEM 公钥应解析成功")
				}
			},
		},
		{
			name: "失败_IAP公钥非base64",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret,
					IAPPublicKey: "!!!不是base64!!!"}
			},
			wantErr: true,
		},
		{
			name: "失败_IAP公钥base64但非DER",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret,
					IAPPublicKey: base64.StdEncoding.EncodeToString([]byte("hello world"))}
			},
			wantErr: true,
		},
		{
			name: "失败_IAP公钥非RSA类型",
			cfg: func(t *testing.T) Config {
				return Config{ClientID: testClientID, ClientSecret: testClientSecret,
					IAPPublicKey: ecPublicKeyB64(t)}
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := New(tc.cfg(t))
			if tc.wantErr {
				if err == nil {
					t.Fatal("New 应失败，实际成功")
				}
				return
			}
			if err != nil {
				t.Fatalf("New 应成功，实际失败: %v", err)
			}
			if h.Name() != PlatformName {
				t.Errorf("Name() = %q, 期望 %q", h.Name(), PlatformName)
			}
			if tc.check != nil {
				tc.check(t, h)
			}
		})
	}
}

func TestMustNewPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustNew 对非法配置应 panic")
		}
	}()
	MustNew(Config{})
}

// TestBuildIAPAuthorization 用官方文档给出的示例值钉死鉴权头格式：
// Base64("APPAT:thisIsAppAtValue") = QVBQQVQ6dGhpc0lzQXBwQXRWYWx1ZQ==
// （api-common-statement 文档原文示例，2026-06-11 拉取）。
func TestBuildIAPAuthorization(t *testing.T) {
	got := buildIAPAuthorization("thisIsAppAtValue")
	want := "Basic QVBQQVQ6dGhpc0lzQXBwQXRWYWx1ZQ=="
	if got != want {
		t.Errorf("buildIAPAuthorization = %q, 期望官方示例值 %q", got, want)
	}
}

// TestMemorySeen 校验内置内存去重表：首次放行 / 窗口内判重 / 过期后重新放行。
func TestMemorySeen(t *testing.T) {
	m := newMemorySeen()
	if m.seen("k1", time.Minute) {
		t.Error("k1 首次出现不应判重")
	}
	if !m.seen("k1", time.Minute) {
		t.Error("k1 窗口内第二次出现应判重")
	}
	if m.seen("k2", time.Minute) {
		t.Error("不同 key 不应互相判重")
	}
	if m.seen("k3", time.Millisecond) {
		t.Error("k3 首次出现不应判重")
	}
	time.Sleep(20 * time.Millisecond)
	if m.seen("k3", time.Minute) {
		t.Error("k3 过期出表后再次出现应视为首次")
	}
}

// TestTruncate 校验错误信息截断（防日志爆量）。
func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 10); got != "abcdef" {
		t.Errorf("未超限不应截断，实际 %q", got)
	}
	if got := truncate("abcdef", 3); got != "abc...(截断)" {
		t.Errorf("超限应截断并加标记，实际 %q", got)
	}
}
