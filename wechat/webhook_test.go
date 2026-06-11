//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：VerifyWebhook 单测——官方 golden vector 验签 / 时间戳窗口 / 防重放 / 密文解密 / 支付事件签名
//2026/6/11
//***************************************************

package wechat

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/sign"
)

// 官方文档 message-push.html（2026-06-11 拉取）给出的完整算例，原样作 golden vector：
//
// URL 验证（GET）：Token="AAAAA"，
//
//	signature=f464b24fc39322e44b38aa78f5edd27bd1441696&echostr=4375120948345356249
//	&timestamp=1714036504&nonce=1514711492
//
// 明文模式（POST）：signature=899cf89e464efb63f54ddac96b0a0a235f53aa78
//
//	&timestamp=1714037059&nonce=486452656
//
// 安全模式（POST）：EncodingAESKey=43 个 "A"，appid="wxba5fad812f8e6fb9"，
//
//	msg_signature=046e02f8204d34f8ba5fa3b1db94908f3df2e9b3
//	&timestamp=1714112445&nonce=415670741&encrypt_type=aes，
//	解密明文 = {"ToUserName":"gh_97417a04a28d",...,"Event":"debug_demo","debug_str":"hello world"}
const (
	officialToken = "AAAAA"

	officialGetSig       = "f464b24fc39322e44b38aa78f5edd27bd1441696"
	officialGetTimestamp = "1714036504"
	officialGetNonce     = "1514711492"
	officialGetEchoStr   = "4375120948345356249"

	officialPlainSig       = "899cf89e464efb63f54ddac96b0a0a235f53aa78"
	officialPlainTimestamp = "1714037059"
	officialPlainNonce     = "486452656"

	officialAESKey       = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 个 A
	officialAppID        = "wxba5fad812f8e6fb9"
	officialMsgSig       = "046e02f8204d34f8ba5fa3b1db94908f3df2e9b3"
	officialAESTimestamp = "1714112445"
	officialAESNonce     = "415670741"
	officialEncrypt      = "+qdx1OKCy+5JPCBFWw70tm0fJGb2Jmeia4FCB7kao+/Q5c/ohsOzQHi8khUOb05JCpj0JB4RvQMkUyus8TPxLKJGQqcvZqzDpVzazhZv6JsXUnnR8XGT740XgXZUXQ7vJVnAG+tE8NUd4yFyjPy7GgiaviNrlCTj+l5kdfMuFUPpRSrfMZuMcp3Fn2Pede2IuQrKEYwKSqFIZoNqJ4M8EajAsjLY2km32IIjdf8YL/P50F7mStwntrA2cPDrM1kb6mOcfBgRtWygb3VIYnSeOBrebufAlr7F9mFUPAJGj04="
)

// newWebhookWeChat 构造 webhook 测试实例（官方算例的 Token/AESKey/AppID +
// 固定时钟对齐算例时间戳）。
func newWebhookWeChat(t *testing.T, tsStr string, mutate func(*Config)) *WeChat {
	t.Helper()
	cfg := Config{
		AppID:          officialAppID,
		AppSecret:      "secret",
		PushToken:      officialToken,
		EncodingAESKey: officialAESKey,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	w, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if tsStr != "" {
		// 把时钟钉在算例时间戳上，使窗口校验通过。
		sec, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			t.Fatalf("算例时间戳非法: %v", err)
		}
		w.now = func() time.Time { return time.Unix(sec, 0) }
	}
	return w
}

// TestVerifyWebhookGetOfficialVector URL 验证（GET）官方算例。
func TestVerifyWebhookGetOfficialVector(t *testing.T) {
	wc := newWebhookWeChat(t, officialGetTimestamp, nil)
	r := httptest.NewRequest(http.MethodGet,
		"https://www.qq.com/revice?signature="+officialGetSig+
			"&echostr="+officialGetEchoStr+
			"&timestamp="+officialGetTimestamp+
			"&nonce="+officialGetNonce, nil)
	if err := wc.VerifyWebhook(r); err != nil {
		t.Fatalf("官方 GET 算例验签失败: %v", err)
	}
	if got := EchoStr(r); got != officialGetEchoStr {
		t.Errorf("EchoStr = %q, 期望 %q", got, officialGetEchoStr)
	}
}

// TestVerifyWebhookPostPlainOfficialVector 明文模式（POST）官方算例 + Body 重置。
func TestVerifyWebhookPostPlainOfficialVector(t *testing.T) {
	wc := newWebhookWeChat(t, officialPlainTimestamp, nil)
	body := `{"ToUserName":"gh_97417a04a28d","FromUserName":"o9AgO5Kd5ggOC-bXrbNODIiE3bGY","CreateTime":1714037059,"MsgType":"event","Event":"debug_demo","debug_str":"hello world"}`
	r := httptest.NewRequest(http.MethodPost,
		"https://www.qq.com/recive?signature="+officialPlainSig+
			"&timestamp="+officialPlainTimestamp+
			"&nonce="+officialPlainNonce,
		strings.NewReader(body))
	if err := wc.VerifyWebhook(r); err != nil {
		t.Fatalf("官方 POST 明文算例验签失败: %v", err)
	}
	// 合约硬要求：实现读了 Body 必须重置，业务 handler 能再读。
	raw, err := io.ReadAll(r.Body)
	if err != nil || string(raw) != body {
		t.Errorf("Body 未正确重置: %q / %v", raw, err)
	}
}

// TestVerifyWebhookPostAESOfficialVector 安全模式（POST）官方算例：
// msg_signature 验签（JSON 与 XML 双包体格式）。
func TestVerifyWebhookPostAESOfficialVector(t *testing.T) {
	target := "https://www.qq.com/recive?signature=6c5c811b55cc85e0e1b54100749188c20beb3f5d" +
		"&timestamp=" + officialAESTimestamp +
		"&nonce=" + officialAESNonce +
		"&openid=o9AgO5Kd5ggOC-bXrbNODIiE3bGY&encrypt_type=aes&msg_signature=" + officialMsgSig

	bodies := map[string]string{
		"JSON 包体": `{"ToUserName":"gh_97417a04a28d","Encrypt":"` + officialEncrypt + `"}`,
		"XML 包体":  `<xml><ToUserName><![CDATA[gh_97417a04a28d]]></ToUserName><Encrypt><![CDATA[` + officialEncrypt + `]]></Encrypt></xml>`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			wc := newWebhookWeChat(t, officialAESTimestamp, nil)
			r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
			if err := wc.VerifyWebhook(r); err != nil {
				t.Fatalf("官方安全模式算例验签失败: %v", err)
			}
			raw, _ := io.ReadAll(r.Body)
			if string(raw) != body {
				t.Error("Body 未正确重置")
			}
		})
	}

	t.Run("安全模式缺 msg_signature 被拒（官方：不要使用 signature 验证）", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialAESTimestamp, nil)
		noMsgSig := "https://www.qq.com/recive?signature=6c5c811b55cc85e0e1b54100749188c20beb3f5d" +
			"&timestamp=" + officialAESTimestamp + "&nonce=" + officialAESNonce + "&encrypt_type=aes"
		r := httptest.NewRequest(http.MethodPost, noMsgSig, strings.NewReader(bodies["JSON 包体"]))
		err := wc.VerifyWebhook(r)
		if !errors.Is(err, ErrWebhookMissingParam) {
			t.Errorf("期望 ErrWebhookMissingParam，实际: %v", err)
		}
	})

	t.Run("包体缺 Encrypt", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialAESTimestamp, nil)
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"ToUserName":"x"}`))
		err := wc.VerifyWebhook(r)
		if !errors.Is(err, ErrWebhookMissingEncrypt) {
			t.Errorf("期望 ErrWebhookMissingEncrypt，实际: %v", err)
		}
	})

	t.Run("密文被篡改 → 签名不匹配", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialAESTimestamp, nil)
		tampered := strings.Replace(bodies["JSON 包体"], officialEncrypt[:8], "AAAAAAAA", 1)
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(tampered))
		err := wc.VerifyWebhook(r)
		if !errors.Is(err, ErrWebhookSignatureMismatch) {
			t.Errorf("期望 ErrWebhookSignatureMismatch，实际: %v", err)
		}
	})
}

// TestVerifyWebhookFailures 通用失败路径：缺参 / 篡改 / 窗口 / 重放。
func TestVerifyWebhookFailures(t *testing.T) {
	makeGet := func() *http.Request {
		return httptest.NewRequest(http.MethodGet,
			"https://www.qq.com/revice?signature="+officialGetSig+
				"&timestamp="+officialGetTimestamp+"&nonce="+officialGetNonce, nil)
	}

	t.Run("缺 PushToken 配置", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialGetTimestamp, func(c *Config) { c.PushToken = "" })
		if err := wc.VerifyWebhook(makeGet()); err == nil {
			t.Error("PushToken 未配置应报错")
		}
	})

	t.Run("缺 timestamp/nonce", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialGetTimestamp, nil)
		r := httptest.NewRequest(http.MethodGet, "https://x/cb?signature=abc", nil)
		if err := wc.VerifyWebhook(r); !errors.Is(err, ErrWebhookMissingParam) {
			t.Errorf("期望 ErrWebhookMissingParam，实际: %v", err)
		}
	})

	t.Run("缺 signature", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialGetTimestamp, nil)
		r := httptest.NewRequest(http.MethodGet,
			"https://x/cb?timestamp="+officialGetTimestamp+"&nonce="+officialGetNonce, nil)
		if err := wc.VerifyWebhook(r); !errors.Is(err, ErrWebhookMissingParam) {
			t.Errorf("期望 ErrWebhookMissingParam，实际: %v", err)
		}
	})

	t.Run("签名篡改", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialGetTimestamp, nil)
		r := httptest.NewRequest(http.MethodGet,
			"https://x/cb?signature=deadbeef"+officialGetSig[8:]+
				"&timestamp="+officialGetTimestamp+"&nonce="+officialGetNonce, nil)
		if err := wc.VerifyWebhook(r); !errors.Is(err, ErrWebhookSignatureMismatch) {
			t.Errorf("期望 ErrWebhookSignatureMismatch，实际: %v", err)
		}
	})

	t.Run("Token 不符 → 签名不匹配", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialGetTimestamp, func(c *Config) { c.PushToken = "BBBBB" })
		if err := wc.VerifyWebhook(makeGet()); !errors.Is(err, ErrWebhookSignatureMismatch) {
			t.Errorf("期望 ErrWebhookSignatureMismatch，实际: %v", err)
		}
	})

	t.Run("时间戳超窗（签名有效）", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialGetTimestamp, nil)
		// 时钟拨快 6 分钟（窗口默认 5 分钟）。
		wc.now = func() time.Time { return time.Unix(1714036504+361, 0) }
		if err := wc.VerifyWebhook(makeGet()); !errors.Is(err, ErrWebhookTimestampOutOfWindow) {
			t.Errorf("期望 ErrWebhookTimestampOutOfWindow，实际: %v", err)
		}
	})

	t.Run("防重放：同一签名第二次被拒", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialGetTimestamp, nil)
		if err := wc.VerifyWebhook(makeGet()); err != nil {
			t.Fatalf("首次验签应通过: %v", err)
		}
		if err := wc.VerifyWebhook(makeGet()); !errors.Is(err, ErrWebhookReplayed) {
			t.Errorf("期望 ErrWebhookReplayed，实际: %v", err)
		}
	})

	t.Run("回调体超限", func(t *testing.T) {
		wc := newWebhookWeChat(t, officialPlainTimestamp, func(c *Config) { c.WebhookMaxBodySize = 8 })
		r := httptest.NewRequest(http.MethodPost,
			"https://x/cb?signature="+officialPlainSig+
				"&timestamp="+officialPlainTimestamp+"&nonce="+officialPlainNonce,
			bytes.NewReader(make([]byte, 64)))
		if err := wc.VerifyWebhook(r); err == nil {
			t.Error("超限包体应报错")
		}
	})
}

// TestDecryptWebhookEventOfficialVector 安全模式解密官方算例：
// 43 个 A 的 EncodingAESKey、官方密文 → 官方明文（含 K=32 PKCS#7 填充路径，
// 本算例 FullStr 205 字节、密文 224 字节，填充长度 19 > 16，恰好覆盖
// 「按 AES 块长 16 校验会误判」的关键差异）。
func TestDecryptWebhookEventOfficialVector(t *testing.T) {
	wc := newWebhookWeChat(t, "", nil)
	msg, err := wc.DecryptWebhookEvent(officialEncrypt)
	if err != nil {
		t.Fatalf("官方算例解密失败: %v", err)
	}
	wantMsg := `{"ToUserName":"gh_97417a04a28d","FromUserName":"o9AgO5Kd5ggOC-bXrbNODIiE3bGY","CreateTime":1714112445,"MsgType":"event","Event":"debug_demo","debug_str":"hello world"}`
	if string(msg) != wantMsg {
		t.Errorf("明文 = %q\n期望  = %q", msg, wantMsg)
	}

	t.Run("appid 不符（串投防御）", func(t *testing.T) {
		other := newWebhookWeChat(t, "", func(c *Config) { c.AppID = "wx_other_app" })
		if _, err := other.DecryptWebhookEvent(officialEncrypt); err == nil {
			t.Error("密文尾部 appid 与配置不符应报错")
		}
	})
	t.Run("缺 EncodingAESKey 配置", func(t *testing.T) {
		noKey := newWebhookWeChat(t, "", func(c *Config) { c.EncodingAESKey = "" })
		if _, err := noKey.DecryptWebhookEvent(officialEncrypt); err == nil {
			t.Error("EncodingAESKey 未配置应报错")
		}
	})
	t.Run("非法 base64 密文", func(t *testing.T) {
		if _, err := wc.DecryptWebhookEvent("!!!not-base64!!!"); err == nil {
			t.Error("非法密文应报错")
		}
	})
	t.Run("密文长度非块长整数倍", func(t *testing.T) {
		if _, err := wc.DecryptWebhookEvent("QUJD"); err == nil { // 3 字节
			t.Error("长度非法应报错")
		}
	})
}

// TestVerifyPayEventSig 支付类订阅事件签名（pay_event_sig =
// hex(hmac_sha256(app_key, event+"&"+payload))，官方算法见 webhook.go 注释）。
func TestVerifyPayEventSig(t *testing.T) {
	const (
		event   = "minigame_coin_deliver_completed"
		payload = `{"OpenId":"to_user_openid","OutTradeNo":"xxxxxxx","Env":0}`
	)
	wc := newWebhookWeChat(t, "", func(c *Config) {
		c.AppKey = testAppKey
		c.SandboxAppKey = testSandboxKey
	})

	good := sign.HMACSHA256Hex([]byte(testAppKey), []byte(event+"&"+payload))
	if err := wc.VerifyPayEventSig(EnvProduction, event, payload, good); err != nil {
		t.Fatalf("合法 PayEventSig 验签失败: %v", err)
	}

	t.Run("沙箱环境用 SandboxAppKey", func(t *testing.T) {
		sandboxSig := sign.HMACSHA256Hex([]byte(testSandboxKey), []byte(event+"&"+payload))
		if err := wc.VerifyPayEventSig(EnvSandbox, event, payload, sandboxSig); err != nil {
			t.Errorf("沙箱 PayEventSig 验签失败: %v", err)
		}
		// 现网签名拿到沙箱环境必须失败（环境错配防御）。
		if err := wc.VerifyPayEventSig(EnvSandbox, event, payload, good); err == nil {
			t.Error("环境错配的签名应被拒")
		}
	})
	t.Run("payload 被篡改", func(t *testing.T) {
		if err := wc.VerifyPayEventSig(EnvProduction, event, payload+"x", good); err == nil {
			t.Error("篡改 payload 应验签失败")
		}
	})
	t.Run("缺对应环境 AppKey", func(t *testing.T) {
		noKey := newWebhookWeChat(t, "", nil) // 未配支付 AppKey
		if err := noKey.VerifyPayEventSig(EnvProduction, event, payload, good); err == nil {
			t.Error("AppKey 未配置应报错")
		}
	})
}
