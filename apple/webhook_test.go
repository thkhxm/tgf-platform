//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：WebhookVerifier 单测——App Store Server Notifications V2 各路径
//2026/6/11
//***************************************************

package apple

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// baseNotification 构造一条合法的 V2 通知载荷（按需覆盖）。
func baseNotification(override map[string]any) map[string]any {
	p := map[string]any{
		"notificationType": "DID_RENEW",
		"notificationUUID": "uuid-0001",
		"version":          "2.0",
		"signedDate":       time.Now().UnixMilli(),
		"data": map[string]any{
			"bundleId":    testBundleID,
			"environment": envProduction,
		},
	}
	for k, v := range override {
		if v == nil {
			delete(p, k)
			continue
		}
		p[k] = v
	}
	return p
}

// newWebhookApple 构造 webhook 校验用实例（信任池注入测试链）。
func newWebhookApple(t *testing.T, chain *testChain, opts ...func(*Config)) *Apple {
	t.Helper()
	cfg := Config{
		ClientID: testClientID,
		BundleID: testBundleID,
		RootCAs:  chain.pool,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return a
}

// newWebhookReq 用通知载荷构造一条 V2 回调请求（body 同时返回供断言）。
func newWebhookReq(t *testing.T, chain *testChain, notif map[string]any) ([]byte, *http.Request) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"signedPayload": chain.signJWS(t, notif)})
	return body, newRawReq(body)
}

// newRawReq 用原始字节构造回调请求。
func newRawReq(body []byte) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "https://game.example.com/webhook/apple", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestVerifyWebhook_Success(t *testing.T) {
	chain := newTestChain(t, true)
	a := newWebhookApple(t, chain)

	body, req := newWebhookReq(t, chain, baseNotification(nil))
	if err := a.VerifyWebhook(req); err != nil {
		t.Fatalf("VerifyWebhook 失败: %v", err)
	}
	// 合约硬要求：Body 重置后业务 handler 能读到原文。
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("重读 Body 失败: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("Body 重置后内容与原文不一致")
	}
}

func TestVerifyWebhook_Replay(t *testing.T) {
	chain := newTestChain(t, true)
	a := newWebhookApple(t, chain)

	notif := baseNotification(nil)
	_, req1 := newWebhookReq(t, chain, notif)
	if err := a.VerifyWebhook(req1); err != nil {
		t.Fatalf("首次投递应通过: %v", err)
	}
	_, req2 := newWebhookReq(t, chain, notif)
	err := a.VerifyWebhook(req2)
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("重复投递应判 ErrWebhookReplayed，实际: %v", err)
	}

	// 不同 notificationUUID 不受影响。
	_, req3 := newWebhookReq(t, chain, baseNotification(map[string]any{"notificationUUID": "uuid-0002"}))
	if err := a.VerifyWebhook(req3); err != nil {
		t.Fatalf("不同 UUID 应通过: %v", err)
	}
}

func TestVerifyWebhook_TimestampWindow(t *testing.T) {
	chain := newTestChain(t, true)
	a := newWebhookApple(t, chain)

	// 过旧
	_, req := newWebhookReq(t, chain, baseNotification(map[string]any{
		"signedDate": time.Now().Add(-10 * time.Minute).UnixMilli(),
	}))
	if err := a.VerifyWebhook(req); !errors.Is(err, ErrWebhookTimestampOutOfWindow) {
		t.Fatalf("过旧 signedDate 应判超窗，实际: %v", err)
	}
	// 超前
	_, req = newWebhookReq(t, chain, baseNotification(map[string]any{
		"notificationUUID": "uuid-future",
		"signedDate":       time.Now().Add(10 * time.Minute).UnixMilli(),
	}))
	if err := a.VerifyWebhook(req); !errors.Is(err, ErrWebhookTimestampOutOfWindow) {
		t.Fatalf("超前 signedDate 应判超窗，实际: %v", err)
	}
	// 自定义窗口内通过
	a2 := newWebhookApple(t, chain, func(c *Config) { c.WebhookTolerance = 30 * time.Minute })
	_, req = newWebhookReq(t, chain, baseNotification(map[string]any{
		"notificationUUID": "uuid-wide",
		"signedDate":       time.Now().Add(-10 * time.Minute).UnixMilli(),
	}))
	if err := a2.VerifyWebhook(req); err != nil {
		t.Fatalf("30 分钟窗口内应通过: %v", err)
	}
}

func TestVerifyWebhook_InvalidPayloads(t *testing.T) {
	chain := newTestChain(t, true)
	evilChain := newTestChain(t, true)
	a := newWebhookApple(t, chain)

	tampered := func() []byte {
		jws := chain.signJWS(t, baseNotification(nil))
		parts := strings.Split(jws, ".")
		// 换掉 payload 段（签名必然对不上）
		parts[1] = b64uEncode([]byte(`{"notificationUUID":"hacked","signedDate":1}`))
		b, _ := json.Marshal(map[string]string{"signedPayload": strings.Join(parts, ".")})
		return b
	}

	tests := []struct {
		name     string
		body     []byte
		sentinel error
	}{
		{
			name:     "body 不是 JSON",
			body:     []byte("not json"),
			sentinel: ErrWebhookMissingPayload,
		},
		{
			name:     "缺 signedPayload 字段",
			body:     []byte(`{"foo":"bar"}`),
			sentinel: ErrWebhookMissingPayload,
		},
		{
			name:     "signedPayload 为空串",
			body:     []byte(`{"signedPayload":""}`),
			sentinel: ErrWebhookMissingPayload,
		},
		{
			name:     "payload 被篡改",
			body:     tampered(),
			sentinel: ErrWebhookInvalidJWS,
		},
		{
			name: "证书链根不可信",
			body: func() []byte {
				b, _ := json.Marshal(map[string]string{"signedPayload": evilChain.signJWS(t, baseNotification(nil))})
				return b
			}(),
			sentinel: ErrWebhookInvalidJWS,
		},
		{
			name: "缺 notificationUUID",
			body: func() []byte {
				b, _ := json.Marshal(map[string]string{
					"signedPayload": chain.signJWS(t, baseNotification(map[string]any{"notificationUUID": nil})),
				})
				return b
			}(),
			sentinel: ErrWebhookInvalidJWS,
		},
		{
			name: "缺 signedDate",
			body: func() []byte {
				b, _ := json.Marshal(map[string]string{
					"signedPayload": chain.signJWS(t, baseNotification(map[string]any{"signedDate": nil})),
				})
				return b
			}(),
			sentinel: ErrWebhookInvalidJWS,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := a.VerifyWebhook(newRawReq(tc.body))
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("期望哨兵错误 %v，实际: %v", tc.sentinel, err)
			}
		})
	}
}

func TestVerifyWebhook_BundleMismatch(t *testing.T) {
	chain := newTestChain(t, true)
	a := newWebhookApple(t, chain)

	_, req := newWebhookReq(t, chain, baseNotification(map[string]any{
		"data": map[string]any{"bundleId": "com.evil.app", "environment": envProduction},
	}))
	if err := a.VerifyWebhook(req); !errors.Is(err, ErrWebhookBundleMismatch) {
		t.Fatalf("bundleId 不符应判 ErrWebhookBundleMismatch，实际: %v", err)
	}

	// 未配置 BundleID（登录-only 实例）→ 跳过 bundle 核对。
	a2 := newWebhookApple(t, chain, func(c *Config) { c.BundleID = "" })
	_, req = newWebhookReq(t, chain, baseNotification(map[string]any{
		"notificationUUID": "uuid-nobundle",
		"data":             map[string]any{"bundleId": "com.whatever.app", "environment": envProduction},
	}))
	if err := a2.VerifyWebhook(req); err != nil {
		t.Fatalf("未配置 BundleID 时不应核对 bundle: %v", err)
	}

	// summary 形态（无 data.bundleId）→ 跳过 bundle 核对。
	_, req = newWebhookReq(t, chain, baseNotification(map[string]any{
		"notificationUUID": "uuid-summary",
		"data":             nil,
	}))
	if err := a.VerifyWebhook(req); err != nil {
		t.Fatalf("无 bundleId 的通知形态不应核对 bundle: %v", err)
	}
}

func TestVerifyWebhook_BodyTooLarge(t *testing.T) {
	chain := newTestChain(t, true)
	a := newWebhookApple(t, chain, func(c *Config) { c.WebhookMaxBodySize = 64 })

	big := append([]byte(`{"signedPayload":"`), bytes.Repeat([]byte("A"), 256)...)
	big = append(big, []byte(`"}`)...)
	if err := a.VerifyWebhook(newRawReq(big)); err == nil ||
		!strings.Contains(err.Error(), "超过上限") {
		t.Fatalf("超大 body 应被拒绝，实际: %v", err)
	}
}

func TestVerifyWebhook_NilBody(t *testing.T) {
	chain := newTestChain(t, true)
	a := newWebhookApple(t, chain)
	req, _ := http.NewRequest(http.MethodPost, "https://game.example.com/webhook/apple", nil)
	if err := a.VerifyWebhook(req); !errors.Is(err, ErrWebhookMissingPayload) {
		t.Fatalf("空 body 应判缺 signedPayload，实际: %v", err)
	}
}
