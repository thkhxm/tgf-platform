//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：VerifyWebhook 单测——通知验签 / 时间窗 / 防重放 / Body 重置
//2026/6/11
//***************************************************

package alipay

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/sign"
)

// notifySignContentIndependent 独立实现的通知待验签串（与产线同语义但独立编码）：
// 除 sign / sign_type 外（keepSignType 时保留 sign_type）按 ASCII 排序 k=v&拼接。
func notifySignContentIndependent(params map[string]string, keepSignType bool) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "sign" || (k == "sign_type" && !keepSignType) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+params[k])
	}
	return strings.Join(pairs, "&")
}

// baseNotifyParams 按官方参数表（203/105286）构造一条交易成功通知。
func baseNotifyParams(t *testing.T, notifyTime time.Time) map[string]string {
	t.Helper()
	return map[string]string{
		"notify_time":  notifyTime.In(cstZone).Format(timeLayout),
		"notify_type":  "trade_status_sync",
		"notify_id":    "ac05099524730693a8b330c5ecf72da9786-" + strconv.FormatInt(notifyTime.UnixNano(), 36),
		"app_id":       testAppID,
		"charset":      "utf-8",
		"version":      "1.0",
		"sign_type":    "RSA2",
		"trade_no":     testTradeNo,
		"out_trade_no": testOutTradeNo,
		"trade_status": "TRADE_SUCCESS",
		"total_amount": "88.88",
		"subject":      "测试 & 商品=标题", // 含需 URL 编码的字符，验证 decode 后参与验签
	}
}

// signNotify 用平台私钥按官方异步通知算法补 sign 参数。
func signNotify(t *testing.T, params map[string]string, keepSignType bool) {
	t.Helper()
	_, platKey := testKeys(t)
	sig, err := sign.RSASHA256SignBase64(platKey, []byte(notifySignContentIndependent(params, keepSignType)))
	if err != nil {
		t.Fatalf("通知签名失败: %v", err)
	}
	params["sign"] = sig
}

// notifyRequest 把参数编码为 POST 表单请求（支付宝异步通知形态）。
func notifyRequest(t *testing.T, params map[string]string) *http.Request {
	t.Helper()
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	r := httptest.NewRequest(http.MethodPost, "https://api.example.com/alipay/notify",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestVerifyWebhook(t *testing.T) {
	now := time.Now()

	t.Run("合法通知通过且Body可再读", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		params := baseNotifyParams(t, now)
		signNotify(t, params, false)
		r := notifyRequest(t, params)

		if err := a.VerifyWebhook(r); err != nil {
			t.Fatalf("VerifyWebhook 失败: %v", err)
		}
		// 合约硬要求：实现读了 Body 必须重置，业务 handler 还能读到原文。
		raw, err := io.ReadAll(r.Body)
		if err != nil || len(raw) == 0 {
			t.Fatalf("Body 未重置: err=%v len=%d", err, len(raw))
		}
		form, err := url.ParseQuery(string(raw))
		if err != nil || form.Get("out_trade_no") != testOutTradeNo {
			t.Fatalf("重置后的 Body 解析异常: %v", err)
		}
	})

	t.Run("参数被篡改验签失败", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		params := baseNotifyParams(t, now)
		signNotify(t, params, false)
		params["total_amount"] = "0.01" // 签名后改金额
		r := notifyRequest(t, params)

		err := a.VerifyWebhook(r)
		if !errors.Is(err, ErrWebhookSignatureMismatch) {
			t.Fatalf("期望 ErrWebhookSignatureMismatch, got %v", err)
		}
	})

	t.Run("缺少sign", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		params := baseNotifyParams(t, now)
		r := notifyRequest(t, params)

		if err := a.VerifyWebhook(r); !errors.Is(err, ErrWebhookMalformed) {
			t.Fatalf("期望 ErrWebhookMalformed, got %v", err)
		}
	})

	t.Run("sign_type非RSA2", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		params := baseNotifyParams(t, now)
		params["sign_type"] = "RSA"
		signNotify(t, params, false)
		r := notifyRequest(t, params)

		if err := a.VerifyWebhook(r); !errors.Is(err, ErrWebhookSignTypeUnsupported) {
			t.Fatalf("期望 ErrWebhookSignTypeUnsupported, got %v", err)
		}
	})

	t.Run("app_id不一致", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		params := baseNotifyParams(t, now)
		params["app_id"] = "2021000000009999" // 签名合法但归属别的应用
		signNotify(t, params, false)
		r := notifyRequest(t, params)

		if err := a.VerifyWebhook(r); !errors.Is(err, ErrWebhookAppIDMismatch) {
			t.Fatalf("期望 ErrWebhookAppIDMismatch, got %v", err)
		}
	})

	t.Run("notify_time过旧", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		params := baseNotifyParams(t, now.Add(-DefaultWebhookTolerance-time.Minute))
		signNotify(t, params, false)
		r := notifyRequest(t, params)

		if err := a.VerifyWebhook(r); !errors.Is(err, ErrWebhookTimestampOutOfWindow) {
			t.Fatalf("期望 ErrWebhookTimestampOutOfWindow, got %v", err)
		}
	})

	t.Run("notify_time超前", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		params := baseNotifyParams(t, now.Add(DefaultWebhookTolerance+time.Minute))
		signNotify(t, params, false)
		r := notifyRequest(t, params)

		if err := a.VerifyWebhook(r); !errors.Is(err, ErrWebhookTimestampOutOfWindow) {
			t.Fatalf("期望 ErrWebhookTimestampOutOfWindow, got %v", err)
		}
	})

	t.Run("重复投递防重放", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		params := baseNotifyParams(t, now)
		signNotify(t, params, false)

		if err := a.VerifyWebhook(notifyRequest(t, params)); err != nil {
			t.Fatalf("首次通知应通过: %v", err)
		}
		if err := a.VerifyWebhook(notifyRequest(t, params)); !errors.Is(err, ErrWebhookReplayed) {
			t.Fatalf("期望 ErrWebhookReplayed, got %v", err)
		}
	})

	t.Run("空body", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		r := httptest.NewRequest(http.MethodPost, "https://api.example.com/alipay/notify", nil)

		if err := a.VerifyWebhook(r); !errors.Is(err, ErrWebhookMalformed) {
			t.Fatalf("期望 ErrWebhookMalformed, got %v", err)
		}
	})

	t.Run("body超限", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, func(c *Config) { c.WebhookMaxBodySize = 16 })
		params := baseNotifyParams(t, now)
		signNotify(t, params, false)
		r := notifyRequest(t, params)

		err := a.VerifyWebhook(r)
		if err == nil || !strings.Contains(err.Error(), "超过上限") {
			t.Fatalf("期望超限报错, got %v", err)
		}
	})

	t.Run("生活号形态保留sign_type", func(t *testing.T) {
		// 官方：生活号异步通知的待验签串保留 sign_type。
		a := newTestAlipay(t, DefaultGatewayURL, func(c *Config) { c.NotifyKeepSignType = true })
		params := baseNotifyParams(t, now)
		signNotify(t, params, true)
		if err := a.VerifyWebhook(notifyRequest(t, params)); err != nil {
			t.Fatalf("保留 sign_type 验签失败: %v", err)
		}

		// 同一报文在默认配置（排除 sign_type）下必须验不过——证明开关真在生效。
		b := newTestAlipay(t, DefaultGatewayURL, nil)
		params2 := baseNotifyParams(t, now.Add(time.Second))
		signNotify(t, params2, true)
		if err := b.VerifyWebhook(notifyRequest(t, params2)); !errors.Is(err, ErrWebhookSignatureMismatch) {
			t.Fatalf("期望 ErrWebhookSignatureMismatch, got %v", err)
		}
	})

	t.Run("自定义去重钩子", func(t *testing.T) {
		called := 0
		a := newTestAlipay(t, DefaultGatewayURL, func(c *Config) {
			c.WebhookSeen = func(key string, ttl time.Duration) bool {
				called++
				return key == "" // 永不重复
			}
		})
		params := baseNotifyParams(t, now)
		signNotify(t, params, false)
		if err := a.VerifyWebhook(notifyRequest(t, params)); err != nil {
			t.Fatalf("VerifyWebhook 失败: %v", err)
		}
		if called != 1 {
			t.Errorf("自定义去重钩子调用次数 = %d", called)
		}
	})
}
