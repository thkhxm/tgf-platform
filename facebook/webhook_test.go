//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description facebook：VerifyWebhook 单测——X-Hub-Signature-256 验签 / 订阅核验 / 时间戳窗口 / 防重放 / Body 重置
//2026/6/11
//***************************************************

package facebook

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// signWebhookBody 按官方算法（HMAC-SHA256(key=App Secret, data=body) 十六进制）
// 生成签名——与实现独立实现一遍，互为印证。
func signWebhookBody(secret, body string) string {
	return hmacHex(secret, body)
}

// newWebhookFacebook 构造固定时钟的实例。
func newWebhookFacebook(t *testing.T, fixedNow time.Time, mutate func(*Config)) *Facebook {
	t.Helper()
	cfg := Config{AppID: testAppID, AppSecret: testAppSecret, WebhookVerifyToken: "meatyhamhock"}
	if mutate != nil {
		mutate(&cfg)
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	f.now = func() time.Time { return fixedNow }
	return f
}

// buildEventRequest 构造带 X-Hub-Signature-256 header 的事件通知请求。
func buildEventRequest(body, sigHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://game.example.com/webhook/facebook", strings.NewReader(body))
	if sigHeader != "" {
		r.Header.Set("X-Hub-Signature-256", sigHeader)
	}
	return r
}

// TestVerifyWebhook 表驱动覆盖验签 / header 解析 / 时间戳窗口的各分支。
func TestVerifyWebhook(t *testing.T) {
	now := time.Unix(1765432100, 0)
	// 官方 getting-started 样例形态：entry[].time 为 Unix 秒
	payloadFresh := `{"object":"user","entry":[{"time":` + strconv.FormatInt(now.Unix()-30, 10) +
		`,"changes":[{"field":"photos"}],"id":"123"}]}`
	// messenger-platform 样例形态：entry[].time 为 Unix 毫秒
	payloadFreshMs := `{"object":"page","entry":[{"id":"p1","time":` + strconv.FormatInt(now.UnixMilli()-30_000, 10) + `}]}`
	payloadOld := `{"object":"user","entry":[{"time":` + strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10) + `,"id":"123"}]}`
	// 多 entry 聚合投递：旧事件 + 新事件并存 → 取最新一条判窗口
	payloadMixed := `{"object":"user","entry":[{"time":` + strconv.FormatInt(now.Add(-30*time.Minute).Unix(), 10) +
		`,"id":"a"},{"time":` + strconv.FormatInt(now.Unix()-5, 10) + `,"id":"b"}]}`
	// 不含 entry.time 的载荷 → 跳过窗口校验
	payloadNoTime := `{"object":"user","entry":[{"id":"123"}]}`

	tests := []struct {
		name      string
		body      string
		sigHeader func(body string) string
		wantErr   error // nil = 期望通过；否则 errors.Is 断言哨兵
	}{
		{
			name: "合法签名 + entry.time（秒）在窗口内 → 通过",
			body: payloadFresh,
			sigHeader: func(b string) string {
				return "sha256=" + signWebhookBody(testAppSecret, b)
			},
		},
		{
			name: "合法签名 + entry.time（毫秒）在窗口内 → 通过",
			body: payloadFreshMs,
			sigHeader: func(b string) string {
				return "sha256=" + signWebhookBody(testAppSecret, b)
			},
		},
		{
			name: "聚合投递含旧事件 → 按最新一条判窗口通过",
			body: payloadMixed,
			sigHeader: func(b string) string {
				return "sha256=" + signWebhookBody(testAppSecret, b)
			},
		},
		{
			name: "载荷不含 entry.time → 跳过窗口校验通过",
			body: payloadNoTime,
			sigHeader: func(b string) string {
				return "sha256=" + signWebhookBody(testAppSecret, b)
			},
		},
		{
			name:      "缺签名 header",
			body:      payloadFresh,
			sigHeader: func(string) string { return "" },
			wantErr:   ErrWebhookMissingSignature,
		},
		{
			name: "缺 sha256= 前缀",
			body: payloadFresh,
			sigHeader: func(b string) string {
				return signWebhookBody(testAppSecret, b)
			},
			wantErr: ErrWebhookMalformedSignature,
		},
		{
			name: "签名错误（密钥不符）",
			body: payloadFresh,
			sigHeader: func(b string) string {
				return "sha256=" + signWebhookBody("wrong-secret", b)
			},
			wantErr: ErrWebhookSignatureMismatch,
		},
		{
			name: "签名非法（非 hex）",
			body: payloadFresh,
			sigHeader: func(string) string {
				return "sha256=zzzz"
			},
			wantErr: ErrWebhookSignatureMismatch,
		},
		{
			name: "body 被篡改",
			body: `{"tampered":true}`,
			sigHeader: func(string) string {
				return "sha256=" + signWebhookBody(testAppSecret, payloadFresh)
			},
			wantErr: ErrWebhookSignatureMismatch,
		},
		{
			name: "签名有效但事件时间戳过旧（超出 5 分钟窗口）",
			body: payloadOld,
			sigHeader: func(b string) string {
				return "sha256=" + signWebhookBody(testAppSecret, b)
			},
			wantErr: ErrWebhookTimestampOutOfWindow,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newWebhookFacebook(t, now, nil)
			r := buildEventRequest(tc.body, tc.sigHeader(tc.body))
			err := f.VerifyWebhook(r)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("期望通过，实际: %v", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("期望 errors.Is(err, %v)，实际: %v", tc.wantErr, err)
			}
			// 合约硬要求：无论结果如何，Body 必须被重置，业务 handler 可再读。
			got, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Fatalf("重读 Body 失败: %v", readErr)
			}
			if string(got) != tc.body {
				t.Errorf("Body 未正确重置: %q != %q", got, tc.body)
			}
		})
	}
}

// TestVerifyWebhookSubscription 订阅核验请求（GET hub.mode=subscribe）。
func TestVerifyWebhookSubscription(t *testing.T) {
	now := time.Unix(1765432100, 0)
	tests := []struct {
		name    string
		url     string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name: "verify_token 一致 → 通过",
			url:  "https://x/webhook?hub.mode=subscribe&hub.challenge=1158201444&hub.verify_token=meatyhamhock",
		},
		{
			name:    "verify_token 不符",
			url:     "https://x/webhook?hub.mode=subscribe&hub.challenge=1&hub.verify_token=wrong",
			wantErr: true,
		},
		{
			name:    "缺 hub.mode",
			url:     "https://x/webhook?hub.challenge=1&hub.verify_token=meatyhamhock",
			wantErr: true,
		},
		{
			name:    "未配置 WebhookVerifyToken → 拒绝",
			url:     "https://x/webhook?hub.mode=subscribe&hub.challenge=1&hub.verify_token=meatyhamhock",
			mutate:  func(c *Config) { c.WebhookVerifyToken = "" },
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newWebhookFacebook(t, now, tc.mutate)
			r := httptest.NewRequest(http.MethodGet, tc.url, nil)
			err := f.VerifyWebhook(r)
			if tc.wantErr {
				if !errors.Is(err, ErrWebhookVerifyTokenMismatch) {
					t.Fatalf("期望 ErrWebhookVerifyTokenMismatch，实际: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望通过，实际: %v", err)
			}
			if got := VerificationChallenge(r); got != "1158201444" {
				t.Errorf("VerificationChallenge = %q", got)
			}
		})
	}
}

// TestVerifyWebhookReplay 防重放：同一合法请求第二次投递被拦截。
func TestVerifyWebhookReplay(t *testing.T) {
	now := time.Unix(1765432100, 0)
	const payload = `{"object":"user","entry":[{"id":"e1"}]}`
	sig := "sha256=" + signWebhookBody(testAppSecret, payload)

	f := newWebhookFacebook(t, now, nil)
	if err := f.VerifyWebhook(buildEventRequest(payload, sig)); err != nil {
		t.Fatalf("首次投递应通过: %v", err)
	}
	err := f.VerifyWebhook(buildEventRequest(payload, sig))
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("重放应被拦截，实际: %v", err)
	}

	// 不同 payload（不同签名）不受影响
	const payload2 = `{"object":"user","entry":[{"id":"e2"}]}`
	sig2 := "sha256=" + signWebhookBody(testAppSecret, payload2)
	if err := f.VerifyWebhook(buildEventRequest(payload2, sig2)); err != nil {
		t.Fatalf("不同事件不应被去重拦截: %v", err)
	}
}

// TestVerifyWebhookCustomSeen 注入自定义去重钩子（多实例共享存储场景）。
func TestVerifyWebhookCustomSeen(t *testing.T) {
	now := time.Unix(1765432100, 0)
	const payload = `{"object":"user","entry":[{"id":"e1"}]}`
	wantKey := signWebhookBody(testAppSecret, payload)

	var gotKey string
	var gotTTL time.Duration
	f := newWebhookFacebook(t, now, func(c *Config) {
		c.WebhookSeen = func(key string, ttl time.Duration) bool {
			gotKey, gotTTL = key, ttl
			return true // 模拟共享存储里已存在 → 重放
		}
	})
	err := f.VerifyWebhook(buildEventRequest(payload, "sha256="+wantKey))
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("期望重放拦截，实际: %v", err)
	}
	if gotKey != wantKey {
		t.Errorf("去重 key = %q, 期望签名值 %q", gotKey, wantKey)
	}
	if gotTTL != 2*DefaultWebhookTolerance {
		t.Errorf("去重 ttl = %v, 期望 %v", gotTTL, 2*DefaultWebhookTolerance)
	}

	// 验签失败的请求不应进入去重表（垃圾签名不可污染共享存储）
	gotKey = ""
	_ = f.VerifyWebhook(buildEventRequest(payload, "sha256="+signWebhookBody("wrong", payload)))
	if gotKey != "" {
		t.Error("验签失败的请求不应调用去重钩子")
	}
}

// TestVerifyWebhookBodyTooLarge 回调体超限拒绝。
func TestVerifyWebhookBodyTooLarge(t *testing.T) {
	now := time.Unix(1765432100, 0)
	body := strings.Repeat("x", 128)
	sig := "sha256=" + signWebhookBody(testAppSecret, body)

	f := newWebhookFacebook(t, now, func(c *Config) { c.WebhookMaxBodySize = 64 })
	if err := f.VerifyWebhook(buildEventRequest(body, sig)); err == nil {
		t.Fatal("超限回调体应被拒绝")
	}
}

// TestMemorySeen 内存去重表：首见 / 重复 / 过期复位。
func TestMemorySeen(t *testing.T) {
	m := newMemorySeen()
	if m.seen("k1", 30*time.Millisecond) {
		t.Fatal("首见应返回 false")
	}
	if !m.seen("k1", 30*time.Millisecond) {
		t.Fatal("窗口内重复应返回 true")
	}
	if m.seen("k2", 30*time.Millisecond) {
		t.Fatal("不同 key 应互不影响")
	}
	time.Sleep(50 * time.Millisecond)
	if m.seen("k1", 30*time.Millisecond) {
		t.Fatal("过期后应视为首见")
	}
}

// TestNewestEntryTime entry.time 解析与单位归一。
func TestNewestEntryTime(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		want   int64
		wantOK bool
	}{
		{"秒单位", `{"entry":[{"time":1520383571}]}`, 1520383571, true},
		{"毫秒单位归一为秒", `{"entry":[{"time":1458692752478}]}`, 1458692752, true},
		{"多条取最新", `{"entry":[{"time":100},{"time":1520383571},{"time":200}]}`, 1520383571, true},
		{"无 time 字段", `{"entry":[{"id":"1"}]}`, 0, false},
		{"无 entry", `{"object":"user"}`, 0, false},
		{"非 JSON", `not-json`, 0, false},
		{"time 为 0", `{"entry":[{"time":0}]}`, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := newestEntryTime([]byte(tc.raw))
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("= (%d, %v), 期望 (%d, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
