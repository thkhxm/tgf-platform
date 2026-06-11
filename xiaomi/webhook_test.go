//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description xiaomi：VerifyWebhook 单元测试（验签 / payTime 窗口 / 防重放）
//2026/6/11
//***************************************************

package xiaomi

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// 固定时钟：与官方 5.3.5 示例 payTime 同刻（北京时间）。
var fixedNow = time.Date(2014, 9, 5, 15, 20, 27, 0, defaultPayTimeLocation)

// newWebhookTestXiaomi 构造注入固定时钟的实例。
func newWebhookTestXiaomi(t *testing.T) *Xiaomi {
	t.Helper()
	x, err := New(Config{AppID: testAppID, AppSecret: testAppSecret})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	x.now = func() time.Time { return fixedNow }
	return x
}

// notifyParams 按官方 5.3.1 示例构造通知参数（URL 解码后的原值）。
func notifyParams(mutate func(map[string]string)) map[string]string {
	params := map[string]string{
		"appId":            testAppID,
		"cpOrderId":        testCPOrderID,
		"orderConsumeType": "10",
		"orderId":          testOrderID,
		"orderStatus":      "TRADE_SUCCESS",
		"payFee":           "1",
		"payTime":          "2014-09-05 15:20:27",
		"productCode":      "com.demo_1",
		"productCount":     "1",
		"productName":      "银子1两",
		"uid":              testUID,
	}
	if mutate != nil {
		mutate(params)
	}
	return params
}

// buildNotifyURL 签名 + URL 编码，返回通知 URL（路径任意，验签只看参数）。
func buildNotifyURL(params map[string]string, overrideSig string) string {
	sig := overrideSig
	if sig == "" {
		sig = hmacSHA1Hex([]byte(testAppSecret), []byte(buildSignSource(params)))
	}
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	q.Set("signature", sig)
	return "/notify.do?" + q.Encode()
}

// TestVerifyWebhook_Success 合法通知（官方示例参数 + 正确签名 + payTime 在窗口内）。
// 官方签名串即已知答案向量（login_test.go，Python 独立预计算），这里直接用
// 该向量做 overrideSig，证明 VerifyWebhook 与官方算法对齐。
func TestVerifyWebhook_Success(t *testing.T) {
	x := newWebhookTestXiaomi(t)
	// e59a0382... = HMAC-SHA1(testAppSecret, 官方 5.3.5 示例签名串)，独立预计算。
	r := httptest.NewRequest("GET", buildNotifyURL(notifyParams(nil), "e59a0382dc72da5ae7d22e8d3cceae0d0320d360"), nil)
	if err := x.VerifyWebhook(r); err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}
}

// TestVerifyWebhook_Replay 同一通知第二次投递 → 防重放拦截。
func TestVerifyWebhook_Replay(t *testing.T) {
	x := newWebhookTestXiaomi(t)
	rawURL := buildNotifyURL(notifyParams(nil), "")
	if err := x.VerifyWebhook(httptest.NewRequest("GET", rawURL, nil)); err != nil {
		t.Fatalf("首次投递应通过: %v", err)
	}
	err := x.VerifyWebhook(httptest.NewRequest("GET", rawURL, nil))
	if !errors.Is(err, ErrWebhookReplayed) {
		t.Fatalf("重复投递应拦截, got %v", err)
	}
}

// TestVerifyWebhook_Failures 表驱动覆盖各失败分支与哨兵错误映射。
func TestVerifyWebhook_Failures(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		sentinel error
	}{
		{
			name:     "缺signature",
			url:      "/notify.do?appId=" + testAppID + "&payTime=2014-09-05+15%3A20%3A27",
			sentinel: ErrWebhookMissingSignature,
		},
		{
			name:     "签名篡改",
			url:      buildNotifyURL(notifyParams(nil), "0000000000000000000000000000000000000000"),
			sentinel: ErrWebhookSignatureMismatch,
		},
		{
			name:     "签名非法hex",
			url:      buildNotifyURL(notifyParams(nil), "zz"),
			sentinel: ErrWebhookSignatureMismatch,
		},
		{
			name: "金额参数篡改",
			url: func() string {
				// 对原值参数签名，再用篡改了 payFee 的参数集投递——签名对不上。
				sig := hmacSHA1Hex([]byte(testAppSecret), []byte(buildSignSource(notifyParams(nil))))
				tampered := notifyParams(func(p map[string]string) { p["payFee"] = "99999" })
				return buildNotifyURL(tampered, sig)
			}(),
			sentinel: ErrWebhookSignatureMismatch,
		},
		{
			name: "payTime缺失",
			url: buildNotifyURL(notifyParams(func(p map[string]string) {
				delete(p, "payTime")
			}), ""),
			sentinel: ErrWebhookMalformedNotify,
		},
		{
			name: "payTime格式非法",
			url: buildNotifyURL(notifyParams(func(p map[string]string) {
				p["payTime"] = "2014/09/05 15:20:27"
			}), ""),
			sentinel: ErrWebhookMalformedNotify,
		},
		{
			name: "payTime过旧超窗",
			url: buildNotifyURL(notifyParams(func(p map[string]string) {
				p["payTime"] = fixedNow.Add(-DefaultWebhookTolerance - time.Hour).Format(payTimeLayout)
			}), ""),
			sentinel: ErrWebhookTimestampOutOfWindow,
		},
		{
			name: "payTime超前超窗",
			url: buildNotifyURL(notifyParams(func(p map[string]string) {
				p["payTime"] = fixedNow.Add(DefaultWebhookTolerance + time.Hour).Format(payTimeLayout)
			}), ""),
			sentinel: ErrWebhookTimestampOutOfWindow,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := newWebhookTestXiaomi(t)
			err := x.VerifyWebhook(httptest.NewRequest("GET", tc.url, nil))
			if err == nil {
				t.Fatal("期望报错")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("哨兵错误不匹配: got %v, want %v", err, tc.sentinel)
			}
		})
	}
}

// TestVerifyWebhook_MetadataRules 验证官方签名规则的两个细节：
// partnerGiftConsume 有值时参与签名；空值参数不参与签名。
func TestVerifyWebhook_MetadataRules(t *testing.T) {
	t.Run("partnerGiftConsume参与签名", func(t *testing.T) {
		x := newWebhookTestXiaomi(t)
		// 官方 5.3.1：使用游戏券的订单带 partnerGiftConsume，如果有则参与签名。
		params := notifyParams(func(p map[string]string) { p["partnerGiftConsume"] = "50" })
		if err := x.VerifyWebhook(httptest.NewRequest("GET", buildNotifyURL(params, ""), nil)); err != nil {
			t.Fatalf("VerifyWebhook: %v", err)
		}
	})
	t.Run("空值参数不参与签名", func(t *testing.T) {
		x := newWebhookTestXiaomi(t)
		// 签名按官方规则排除空值参数；URL 上多一个空值 cpUserInfo 不应破坏验签。
		rawURL := buildNotifyURL(notifyParams(nil), "") + "&cpUserInfo="
		if err := x.VerifyWebhook(httptest.NewRequest("GET", rawURL, nil)); err != nil {
			t.Fatalf("VerifyWebhook: %v", err)
		}
	})
	t.Run("中文与空格参数经URL编码往返后验签通过", func(t *testing.T) {
		x := newWebhookTestXiaomi(t)
		// productName 中文、payTime 含空格——投递时 URLencoding、验签时用原值
		// （官方 5.3.5），Query() 解码后应严格还原。
		params := notifyParams(func(p map[string]string) { p["productName"] = "豪华礼包 x10&特价" })
		if err := x.VerifyWebhook(httptest.NewRequest("GET", buildNotifyURL(params, ""), nil)); err != nil {
			t.Fatalf("VerifyWebhook: %v", err)
		}
	})
}

// TestVerifyWebhook_CustomSeen 注入共享去重钩子时不再使用内置内存表。
func TestVerifyWebhook_CustomSeen(t *testing.T) {
	var gotKey string
	var gotTTL time.Duration
	x, err := New(Config{
		AppID: testAppID, AppSecret: testAppSecret,
		WebhookSeen: func(key string, ttl time.Duration) bool {
			gotKey, gotTTL = key, ttl
			return true // 模拟共享存储判定为重放
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	x.now = func() time.Time { return fixedNow }

	params := notifyParams(nil)
	sig := hmacSHA1Hex([]byte(testAppSecret), []byte(buildSignSource(params)))
	verr := x.VerifyWebhook(httptest.NewRequest("GET", buildNotifyURL(params, sig), nil))
	if !errors.Is(verr, ErrWebhookReplayed) {
		t.Fatalf("注入钩子判重放应拦截, got %v", verr)
	}
	if gotKey != sig {
		t.Errorf("去重 key 应为签名值: %s", gotKey)
	}
	if gotTTL != 2*DefaultWebhookTolerance {
		t.Errorf("去重 TTL = %v, want %v", gotTTL, 2*DefaultWebhookTolerance)
	}
}

// TestMemorySeen 内存去重表：首见 false、窗口内重复 true、过期出表。
func TestMemorySeen(t *testing.T) {
	m := newMemorySeen()
	if m.seen("k1", time.Hour) {
		t.Error("首次出现应返回 false")
	}
	if !m.seen("k1", time.Hour) {
		t.Error("窗口内重复应返回 true")
	}
	if m.seen("k2", time.Hour) {
		t.Error("不同 key 应返回 false")
	}
	// 过期清理：把 k1 的过期时刻改到过去，再次访问应视作首见。
	m.mu.Lock()
	m.entries["k1"] = time.Now().Add(-time.Minute)
	m.mu.Unlock()
	if m.seen("k1", time.Hour) {
		t.Error("过期后的 key 应视作首见")
	}
}
