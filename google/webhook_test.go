//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：VerifyWebhook 单测——Pub/Sub OIDC token 验签 / claim 校验 / 防重放 / Body 重置
//2026/6/11
//***************************************************

package google

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testPushAudience = "https://game.example.com/platform/google/rtdn"
	testPushSAEmail  = "rtdn-push@proj.iam.gserviceaccount.com"
)

// pushTokenClaims 构造基准合法的 Pub/Sub push OIDC claims（字段形态取自官方示例，
// https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions ，2026-06-11 拉取）。
func pushTokenClaims(mutate func(map[string]any)) map[string]any {
	now := time.Now()
	claims := map[string]any{
		"aud":            testPushAudience,
		"azp":            "113774264463038321964",
		"email":          testPushSAEmail,
		"sub":            "113774264463038321964",
		"email_verified": true,
		"iat":            now.Add(-time.Minute).Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"iss":            "https://accounts.google.com",
	}
	if mutate != nil {
		mutate(claims)
	}
	return claims
}

// rtdnEnvelope 构造 Pub/Sub push 包体（RTDN 通知 base64 进 data；形态取自官方示例，
// https://developer.android.com/google/play/billing/rtdn-reference ，2026-06-11 拉取）。
func rtdnEnvelope(t *testing.T, messageID, packageName string) []byte {
	t.Helper()
	notification := map[string]any{
		"version":         "1.0",
		"packageName":     packageName,
		"eventTimeMillis": "1503349566168",
		"oneTimeProductNotification": map[string]any{
			"version":          "1.0",
			"notificationType": 1, // ONE_TIME_PRODUCT_PURCHASED
			"purchaseToken":    testPurchaseToken,
			"sku":              testProductSKU,
		},
	}
	nj, err := json.Marshal(notification)
	if err != nil {
		t.Fatalf("序列化 RTDN 通知失败: %v", err)
	}
	envelope := map[string]any{
		"message": map[string]any{
			"attributes": map[string]string{},
			"data":       base64.StdEncoding.EncodeToString(nj),
			"messageId":  messageID,
		},
		"subscription": "projects/myproject/subscriptions/mysubscription",
	}
	ej, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("序列化 push 包体失败: %v", err)
	}
	return ej
}

// newWebhookGoogle 构造接到 mock JWKS 的 webhook 态实例。
func newWebhookGoogle(t *testing.T, jwksURL string, mutate func(*Config)) *Google {
	t.Helper()
	cfg := Config{
		PackageName:               testPackageName,
		PubSubAudience:            testPushAudience,
		PubSubServiceAccountEmail: testPushSAEmail,
		JWKSURL:                   jwksURL,
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

func TestVerifyWebhook(t *testing.T) {
	priv := testRSAKey(t)
	srv, _ := newJWKSServer(t, []map[string]any{jwkOf(testKid, &priv.PublicKey)})
	header := map[string]any{"alg": "RS256", "kid": testKid, "typ": "JWT"}
	bearer := func(claims map[string]any) string {
		return "Bearer " + makeJWT(t, priv, header, claims)
	}

	cases := []struct {
		name      string
		mutateCfg func(*Config)
		auth      string // Authorization 头；"-" 表示不带
		url       string
		body      []byte
		wantErrIs error
		wantOK    bool
	}{
		{
			name:   "成功_标准RTDN推送",
			wantOK: true,
			auth:   bearer(pushTokenClaims(nil)),
			body:   nil, // 用例内生成唯一 messageId
		},
		{
			name:      "失败_缺Authorization头",
			auth:      "-",
			wantErrIs: ErrWebhookMissingAuthorization,
		},
		{
			name:      "失败_非Bearer形态",
			auth:      "Basic dXNlcjpwYXNz",
			wantErrIs: ErrWebhookMissingAuthorization,
		},
		{
			name: "失败_claims被篡改保留原签名",
			auth: "Bearer " + tamperJWTClaims(t,
				makeJWT(t, priv, header, pushTokenClaims(nil)),
				pushTokenClaims(func(c map[string]any) { c["email"] = "evil@evil.com" })),
			wantErrIs: ErrJWTSignatureMismatch,
		},
		{
			name:      "失败_aud不符",
			auth:      bearer(pushTokenClaims(func(c map[string]any) { c["aud"] = "https://evil.example.com" })),
			wantErrIs: ErrWebhookAudienceMismatch,
		},
		{
			name:      "失败_email非订阅配置的服务账号",
			auth:      bearer(pushTokenClaims(func(c map[string]any) { c["email"] = "other@proj.iam.gserviceaccount.com" })),
			wantErrIs: ErrWebhookEmailMismatch,
		},
		{
			name:      "失败_email_verified为false",
			auth:      bearer(pushTokenClaims(func(c map[string]any) { c["email_verified"] = false })),
			wantErrIs: ErrWebhookEmailMismatch,
		},
		{
			name: "失败_token过期",
			auth: bearer(pushTokenClaims(func(c map[string]any) {
				c["exp"] = time.Now().Add(-DefaultClockSkew - time.Hour).Unix()
			})),
			wantErrIs: ErrJWTExpired,
		},
		{
			name:      "失败_包体非JSON",
			auth:      bearer(pushTokenClaims(nil)),
			body:      []byte("not json"),
			wantErrIs: ErrWebhookBadEnvelope,
		},
		{
			name:      "失败_缺messageId",
			auth:      bearer(pushTokenClaims(nil)),
			body:      []byte(`{"message":{"data":"eyJ9","attributes":{}},"subscription":"s"}`),
			wantErrIs: ErrWebhookBadEnvelope,
		},
		{
			name:      "失败_data非法base64",
			auth:      bearer(pushTokenClaims(nil)),
			body:      []byte(`{"message":{"data":"!!!!不是base64!!!!","messageId":"m-bad-b64"},"subscription":"s"}`),
			wantErrIs: ErrWebhookBadEnvelope,
		},
		{
			name:      "失败_packageName串包",
			auth:      bearer(pushTokenClaims(nil)),
			body:      nil, // 用例内生成串包包体
			wantErrIs: ErrWebhookPackageMismatch,
		},
		{
			name:      "失败_共享口令缺失",
			mutateCfg: func(c *Config) { c.PubSubVerificationToken = "secret-token" },
			auth:      bearer(pushTokenClaims(nil)),
			wantErrIs: ErrWebhookBadVerificationToken,
		},
		{
			name:      "成功_共享口令匹配",
			wantOK:    true,
			mutateCfg: func(c *Config) { c.PubSubVerificationToken = "secret-token" },
			auth:      bearer(pushTokenClaims(nil)),
			url:       "/rtdn?token=secret-token",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newWebhookGoogle(t, srv.URL, tc.mutateCfg)
			body := tc.body
			if body == nil {
				pkg := testPackageName
				if tc.wantErrIs == ErrWebhookPackageMismatch {
					pkg = "com.evil.other"
				}
				// 每个用例唯一 messageId，避免去重表串扰。
				body = rtdnEnvelope(t, "msg-"+strings.ReplaceAll(tc.name, " ", "_")+"-"+strconv.Itoa(i), pkg)
			}
			url := tc.url
			if url == "" {
				url = "/rtdn"
			}
			req := httptest.NewRequest("POST", url, bytes.NewReader(body))
			if tc.auth != "-" && tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			err := g.VerifyWebhook(req)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("VerifyWebhook 应通过，实际失败: %v", err)
				}
				// 合约硬要求：Body 必须被重置，业务 handler 能读到原文。
				got, readErr := io.ReadAll(req.Body)
				if readErr != nil {
					t.Fatalf("重读 Body 失败: %v", readErr)
				}
				if !bytes.Equal(got, body) {
					t.Error("VerifyWebhook 后 Body 与原文不一致（未正确重置）")
				}
				return
			}
			if err == nil {
				t.Fatal("VerifyWebhook 应失败，实际通过")
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("错误链应命中 %v，实际: %v", tc.wantErrIs, err)
			}
		})
	}
}

// TestVerifyWebhookReplay 校验防重放：同一 messageId 第二次投递被拦截。
func TestVerifyWebhookReplay(t *testing.T) {
	priv := testRSAKey(t)
	srv, _ := newJWKSServer(t, []map[string]any{jwkOf(testKid, &priv.PublicKey)})
	g := newWebhookGoogle(t, srv.URL, nil)
	auth := "Bearer " + makeJWT(t, priv,
		map[string]any{"alg": "RS256", "kid": testKid, "typ": "JWT"}, pushTokenClaims(nil))
	body := rtdnEnvelope(t, "msg-replay-1", testPackageName)

	req1 := httptest.NewRequest("POST", "/rtdn", bytes.NewReader(body))
	req1.Header.Set("Authorization", auth)
	if err := g.VerifyWebhook(req1); err != nil {
		t.Fatalf("首次投递应通过，实际失败: %v", err)
	}
	req2 := httptest.NewRequest("POST", "/rtdn", bytes.NewReader(body))
	req2.Header.Set("Authorization", auth)
	err := g.VerifyWebhook(req2)
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("重复 messageId 应返回 ErrWebhookReplayed，实际: %v", err)
	}
}

// TestVerifyWebhookBodyTooLarge 校验回调体超限拦截。
func TestVerifyWebhookBodyTooLarge(t *testing.T) {
	priv := testRSAKey(t)
	srv, _ := newJWKSServer(t, []map[string]any{jwkOf(testKid, &priv.PublicKey)})
	g := newWebhookGoogle(t, srv.URL, func(c *Config) { c.WebhookMaxBodySize = 64 })
	auth := "Bearer " + makeJWT(t, priv,
		map[string]any{"alg": "RS256", "kid": testKid, "typ": "JWT"}, pushTokenClaims(nil))

	req := httptest.NewRequest("POST", "/rtdn", bytes.NewReader(rtdnEnvelope(t, "msg-big", testPackageName)))
	req.Header.Set("Authorization", auth)
	if err := g.VerifyWebhook(req); err == nil {
		t.Fatal("回调体超过上限应失败")
	}
}

// TestVerifyWebhookNotConfigured 未配置 webhook 能力时报明确错误。
func TestVerifyWebhookNotConfigured(t *testing.T) {
	g, err := New(Config{ClientIDs: []string{testClientID}})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	req := httptest.NewRequest("POST", "/rtdn", bytes.NewReader(nil))
	if err := g.VerifyWebhook(req); !errors.Is(err, ErrWebhookNotConfigured) {
		t.Fatalf("未配置 webhook 能力应返回 ErrWebhookNotConfigured，实际: %v", err)
	}
}
