//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：测试基建（密钥对 / mock 网关）+ 签名串 / 金额换算 / 验签兜底单测
//2026/6/11
//***************************************************

package alipay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/thkhxm/tgf-platform/core/sign"
)

// 测试用 AppID。
const testAppID = "2021000000000001"

// 测试密钥对：appKey 模拟应用私钥（被测代码签请求），platKey 模拟支付宝平台
// 私钥（mock 网关签应答、签异步通知）。包级一次生成，省去每用例 2048 位
// keygen 的开销。
var (
	testKeyOnce sync.Once
	testAppKey  *rsa.PrivateKey
	testPlatKey *rsa.PrivateKey
)

func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	testKeyOnce.Do(func() {
		var err error
		if testAppKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if testPlatKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return testAppKey, testPlatKey
}

// pemPrivate 把私钥编码为 PKCS#8 PEM。
func pemPrivate(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("私钥编码失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// pemPublic 把公钥编码为 PKIX PEM。
func pemPublic(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("公钥编码失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// requestSignContent 独立实现的请求待签名串（与产线 signContent 同语义但独立
// 编码，避免「用被测代码验被测代码」）：排除 sign 与空值，ASCII 升序，k=v&拼接。
func requestSignContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || v == "" {
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

// gatewayHandler 是 mock 网关的业务回调：按 method 产出（节点 key, 节点 JSON）。
// 返回的节点 JSON 会被 mock 网关用平台私钥按官方规则（对节点原文 RSA2 签名）
// 签好再包装为完整应答。
type gatewayHandler func(t *testing.T, r *http.Request, params url.Values) (nodeKey, nodeJSON string)

// newMockGateway 启动 httptest 版支付宝网关：
//  1. 校验请求公共参数与 RSA2 签名（用应用公钥独立重算，签名错直接判失败）；
//  2. 回调 handler 产出业务节点；
//  3. 按官方验签规则（对节点原文签名）用平台私钥产出应答 sign。
func newMockGateway(t *testing.T, handler gatewayHandler) *httptest.Server {
	t.Helper()
	appKey, platKey := testKeys(t)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("mock 网关解析表单失败: %v", err)
			return
		}
		// 公共参数纪律核对（官方公共请求参数表）。
		q := r.URL.Query()
		for _, k := range []string{"app_id", "method", "charset", "sign_type", "timestamp", "version", "sign"} {
			if q.Get(k) == "" {
				t.Errorf("公共参数 %s 缺失或未置于 URL query（官方要求平台参数进 query）", k)
			}
		}
		if got := q.Get("charset"); got != "utf-8" {
			t.Errorf("charset = %q, 期望 utf-8", got)
		}
		if got := q.Get("sign_type"); got != "RSA2" {
			t.Errorf("sign_type = %q, 期望 RSA2", got)
		}
		if got := q.Get("version"); got != "1.0" {
			t.Errorf("version = %q, 期望 1.0", got)
		}
		// 请求验签（r.Form 已合并 query 与 body 的全部参数）。
		params := map[string]string{}
		for k := range r.Form {
			params[k] = r.Form.Get(k)
		}
		sigB64 := r.Form.Get("sign")
		if err := sign.RSASHA256VerifyBase64(&appKey.PublicKey, []byte(requestSignContent(params)), sigB64); err != nil {
			t.Errorf("mock 网关请求验签失败: %v", err)
		}

		nodeKey, nodeJSON := handler(t, r, r.Form)
		respSig, err := sign.RSASHA256SignBase64(platKey, []byte(nodeJSON))
		if err != nil {
			t.Errorf("mock 网关应答签名失败: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json;charset=utf-8")
		fmt.Fprintf(w, `{"%s":%s,"sign":%q}`, nodeKey, nodeJSON, respSig)
	}))
}

// newTestAlipay 构造指向 mock 网关的被测实例；mutate 可改写默认配置。
func newTestAlipay(t *testing.T, gatewayURL string, mutate func(*Config)) *Alipay {
	t.Helper()
	appKey, platKey := testKeys(t)
	cfg := Config{
		AppID:              testAppID,
		AppPrivateKeyPEM:   pemPrivate(t, appKey),
		AlipayPublicKeyPEM: pemPublic(t, &platKey.PublicKey),
		GatewayURL:         gatewayURL,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return a
}

func TestNewConfigValidation(t *testing.T) {
	appKey, platKey := testKeys(t)
	privPEM := pemPrivate(t, appKey)
	pubPEM := pemPublic(t, &platKey.PublicKey)

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"缺 AppID", Config{AppPrivateKeyPEM: privPEM, AlipayPublicKeyPEM: pubPEM}, "AppID"},
		{"缺私钥", Config{AppID: testAppID, AlipayPublicKeyPEM: pubPEM}, "AppPrivateKeyPEM"},
		{"缺公钥", Config{AppID: testAppID, AppPrivateKeyPEM: privPEM}, "AlipayPublicKeyPEM"},
		{"私钥非法", Config{AppID: testAppID, AppPrivateKeyPEM: "garbage", AlipayPublicKeyPEM: pubPEM}, "私钥解析失败"},
		{"公钥非法", Config{AppID: testAppID, AppPrivateKeyPEM: privPEM, AlipayPublicKeyPEM: "garbage"}, "公钥解析失败"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, 期望包含 %q", err, tt.wantErr)
			}
		})
	}

	t.Run("合法配置默认值", func(t *testing.T) {
		a, err := New(Config{AppID: testAppID, AppPrivateKeyPEM: privPEM, AlipayPublicKeyPEM: pubPEM})
		if err != nil {
			t.Fatalf("New 失败: %v", err)
		}
		if a.cfg.GatewayURL != DefaultGatewayURL {
			t.Errorf("GatewayURL 默认值 = %q", a.cfg.GatewayURL)
		}
		if a.cfg.WebhookTolerance != DefaultWebhookTolerance {
			t.Errorf("WebhookTolerance 默认值 = %v", a.cfg.WebhookTolerance)
		}
		if a.Name() != PlatformName {
			t.Errorf("Name = %q", a.Name())
		}
		if a.sandbox() {
			t.Error("生产网关不应判为沙箱")
		}
	})

	t.Run("沙箱网关判定", func(t *testing.T) {
		a, err := New(Config{AppID: testAppID, AppPrivateKeyPEM: privPEM,
			AlipayPublicKeyPEM: pubPEM, GatewayURL: SandboxGatewayURL})
		if err != nil {
			t.Fatalf("New 失败: %v", err)
		}
		if !a.sandbox() {
			t.Error("沙箱网关应判为沙箱")
		}
	})

	t.Run("MustNew 非法配置 panic", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("MustNew 应 panic")
			}
		}()
		MustNew(Config{})
	})
}

func TestSignContent(t *testing.T) {
	got := signContent(map[string]string{
		"method":      "alipay.trade.query",
		"app_id":      "2014072300007148",
		"sign":        "应被排除",
		"empty":       "",
		"blank":       "  ",
		"charset":     "utf-8",
		"biz_content": `{"out_trade_no":"123"}`,
	})
	want := `app_id=2014072300007148&biz_content={"out_trade_no":"123"}&charset=utf-8&method=alipay.trade.query`
	if got != want {
		t.Fatalf("signContent = %q\n期望 %q", got, want)
	}
}

func TestYuanToFen(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"88.88", 8888, false},
		{"10", 1000, false},
		{"11.2", 1120, false},
		{"0.01", 1, false},
		{"0", 0, false},
		{" 8.88 ", 888, false},
		{"-2.58", -258, false},
		{"88.888", 0, true},
		{"abc", 0, true},
		{"", 0, true},
		{"1.2.3", 0, true},
		{"1.", 0, true},
		{"1.x", 0, true},
	}
	for _, tt := range tests {
		got, err := yuanToFen(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("yuanToFen(%q) 期望报错, got %d", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("yuanToFen(%q) 报错: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("yuanToFen(%q) = %d, 期望 %d", tt.in, got, tt.want)
		}
	}
}

func TestVerifyResponseSignSlashFallback(t *testing.T) {
	_, platKey := testKeys(t)
	a := newTestAlipay(t, DefaultGatewayURL, nil)

	raw := []byte(`{"code":"10000","url":"https://qr.alipay.com/x"}`)
	escaped := []byte(`{"code":"10000","url":"https:\/\/qr.alipay.com\/x"}`)

	t.Run("原文直验", func(t *testing.T) {
		sig, _ := sign.RSASHA256SignBase64(platKey, raw)
		if err := a.verifyResponseSign(raw, sig); err != nil {
			t.Fatalf("原文验签失败: %v", err)
		}
	})
	t.Run("签名按转义形态计算_官方兜底", func(t *testing.T) {
		// 模拟平台对 \/ 转义形态签名而报文已被上游反转义的场景。
		sig, _ := sign.RSASHA256SignBase64(platKey, escaped)
		if err := a.verifyResponseSign(raw, sig); err != nil {
			t.Fatalf("转义兜底验签失败: %v", err)
		}
	})
	t.Run("签名按原文计算_报文为转义形态", func(t *testing.T) {
		sig, _ := sign.RSASHA256SignBase64(platKey, raw)
		if err := a.verifyResponseSign(escaped, sig); err != nil {
			t.Fatalf("反转义兜底验签失败: %v", err)
		}
	})
	t.Run("签名彻底不符", func(t *testing.T) {
		sig, _ := sign.RSASHA256SignBase64(platKey, []byte("别的内容"))
		if err := a.verifyResponseSign(raw, sig); err == nil {
			t.Fatal("期望验签失败")
		}
	})
}

func TestFlexString(t *testing.T) {
	var v struct {
		A flexString `json:"a"`
		B flexString `json:"b"`
		C flexString `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":"3600","b":3600,"c":null}`), &v); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if v.A != "3600" || v.B != "3600" || v.C != "" {
		t.Fatalf("flexString 解析结果 = %q %q %q", v.A, v.B, v.C)
	}
}
