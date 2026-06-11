//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description xiaomi：VerifyLogin / 凭据解析 / 签名算法 单元测试（httptest mock，不打真实平台）
//2026/6/11
//***************************************************

package xiaomi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// 测试用凭据（来源于官方文档 5.3.3 示例值，pId=1616）。
const (
	testAppID     = "2882303761517239138"
	testAppSecret = "testAppSecret"
	testUID       = "100010"
	testSession   = "1nlfxuAGmZk9IR2L"
)

// newTestXiaomi 构造指向 httptest server 的实例。
func newTestXiaomi(t *testing.T, baseURL string) *Xiaomi {
	t.Helper()
	x, err := New(Config{AppID: testAppID, AppSecret: testAppSecret, BaseURL: baseURL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return x
}

// TestBuildSignSource_OfficialOrder 验证待签名串构造与官方 5.3.5 示例的
// 参数顺序、原值拼接完全一致。
func TestBuildSignSource_OfficialOrder(t *testing.T) {
	// 官方 5.3.5 示例（pId=1616，2026-06-11 拉取）：URL 解码后的待签名串。
	params := map[string]string{
		"appId":            "2882303761517239138",
		"cpOrderId":        "9786bffc-996d-4553-aa33-f7e92c0b29d5",
		"orderConsumeType": "10",
		"orderId":          "21140990160359583390",
		"orderStatus":      "TRADE_SUCCESS",
		"payFee":           "1",
		"payTime":          "2014-09-05 15:20:27",
		"productCode":      "com.demo_1",
		"productCount":     "1",
		"productName":      "银子1两",
		"uid":              "100010",
		"signature":        "1388720d978021c20aa885d9b3e1b70cec751496", // 须被排除
		"emptyParam":       "",                                         // 无值参数须被排除
	}
	want := "appId=2882303761517239138&cpOrderId=9786bffc-996d-4553-aa33-f7e92c0b29d5&orderConsumeType=10&orderId=21140990160359583390&orderStatus=TRADE_SUCCESS&payFee=1&payTime=2014-09-05 15:20:27&productCode=com.demo_1&productCount=1&productName=银子1两&uid=100010"
	if got := buildSignSource(params); got != want {
		t.Fatalf("buildSignSource 与官方示例不一致:\ngot  %s\nwant %s", got, want)
	}
}

// TestHmacSHA1Hex_KnownAnswer 用独立实现（Python hmac/hashlib）预计算的
// 已知答案向量验证 HMAC-SHA1 十六进制输出。
func TestHmacSHA1Hex_KnownAnswer(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{
			name: "登录验签串",
			data: "appId=2882303761517239138&session=1nlfxuAGmZk9IR2L&uid=100010",
			want: "8a8ac8e41af088e362b98e14411922e3e72d822c",
		},
		{
			name: "订单通知签串（含中文原值）",
			data: "appId=2882303761517239138&cpOrderId=9786bffc-996d-4553-aa33-f7e92c0b29d5&orderConsumeType=10&orderId=21140990160359583390&orderStatus=TRADE_SUCCESS&payFee=1&payTime=2014-09-05 15:20:27&productCode=com.demo_1&productCount=1&productName=银子1两&uid=100010",
			want: "e59a0382dc72da5ae7d22e8d3cceae0d0320d360",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hmacSHA1Hex([]byte(testAppSecret), []byte(tc.data)); got != tc.want {
				t.Fatalf("hmacSHA1Hex = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestParseCredential 表驱动验证两种凭据格式与各类非法输入。
func TestParseCredential(t *testing.T) {
	cases := []struct {
		name       string
		credential string
		wantUID    string
		wantSess   string
		wantErr    bool
	}{
		{name: "简易格式", credential: "100010:1nlfxuAGmZk9IR2L", wantUID: "100010", wantSess: "1nlfxuAGmZk9IR2L"},
		{name: "简易格式_session含冒号", credential: "100010:a:b:c", wantUID: "100010", wantSess: "a:b:c"},
		{name: "JSON_uid字符串", credential: `{"uid":"100010","session":"s1"}`, wantUID: "100010", wantSess: "s1"},
		{name: "JSON_uid数字", credential: `{"uid":100010,"session":"s1"}`, wantUID: "100010", wantSess: "s1"},
		{name: "JSON_大数uid不丢精度", credential: `{"uid":9223372036854775807,"session":"s1"}`, wantUID: "9223372036854775807", wantSess: "s1"},
		{name: "空串", credential: "", wantErr: true},
		{name: "缺冒号", credential: "100010", wantErr: true},
		{name: "uid为空", credential: ":sess", wantErr: true},
		{name: "session为空", credential: "100010:", wantErr: true},
		{name: "uid非数字", credential: "abc:sess", wantErr: true},
		{name: "JSON非法", credential: `{"uid":`, wantErr: true},
		{name: "JSON缺session", credential: `{"uid":"100010"}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uid, sess, err := parseCredential(tc.credential)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望报错，得到 uid=%s session=%s", uid, sess)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCredential: %v", err)
			}
			if uid != tc.wantUID || sess != tc.wantSess {
				t.Fatalf("got (%s,%s), want (%s,%s)", uid, sess, tc.wantUID, tc.wantSess)
			}
		})
	}
}

// TestVerifyLogin_Success 成功路径：服务端校验请求形态（POST 表单 + 正确签名），
// 应答 errcode=200 + adult，断言身份映射。
func TestVerifyLogin_Success(t *testing.T) {
	var gotForm map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %s", ct)
		}
		if r.URL.Path != loginValidatePath {
			t.Errorf("Path = %s, want %s", r.URL.Path, loginValidatePath)
		}
		_ = r.ParseForm()
		gotForm = map[string]string{
			"appId":     r.PostForm.Get("appId"),
			"session":   r.PostForm.Get("session"),
			"uid":       r.PostForm.Get("uid"),
			"signature": r.PostForm.Get("signature"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":200,"adult":409}`))
	}))
	defer srv.Close()

	x := newTestXiaomi(t, srv.URL)
	identity, err := x.VerifyLogin(context.Background(), testUID+":"+testSession)
	if err != nil {
		t.Fatalf("VerifyLogin: %v", err)
	}
	// 请求侧断言：参数与签名（已知答案向量，与官方 5.3.3 示例参数一致）。
	if gotForm["appId"] != testAppID || gotForm["uid"] != testUID || gotForm["session"] != testSession {
		t.Fatalf("请求参数不符: %+v", gotForm)
	}
	if gotForm["signature"] != "8a8ac8e41af088e362b98e14411922e3e72d822c" {
		t.Fatalf("请求 signature = %s", gotForm["signature"])
	}
	// 身份映射断言。
	if identity.Platform != PlatformName {
		t.Errorf("Platform = %s", identity.Platform)
	}
	if identity.OpenID != testUID {
		t.Errorf("OpenID = %s, want %s", identity.OpenID, testUID)
	}
	if identity.UnionID != "" || identity.SessionKey != "" {
		t.Errorf("UnionID/SessionKey 应为空: %q %q", identity.UnionID, identity.SessionKey)
	}
	if identity.Raw["adult"] != "409" || identity.Raw["errcode"] != "200" {
		t.Errorf("Raw = %+v", identity.Raw)
	}
}

// TestVerifyLogin_PlatformErrors 表驱动验证官方各错误码的映射与重试分类。
func TestVerifyLogin_PlatformErrors(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		body          string
		wantCode      string
		wantRetryable bool
	}{
		{name: "appId错误1515", status: 200, body: `{"errcode":1515,"errMsg":"appId error"}`, wantCode: "1515"},
		{name: "uid错误1516", status: 200, body: `{"errcode":1516}`, wantCode: "1516"},
		{name: "session错误1520", status: 200, body: `{"errcode":1520}`, wantCode: "1520"},
		{name: "签名错误1525", status: 200, body: `{"errcode":1525}`, wantCode: "1525"},
		{name: "session过期4002", status: 200, body: `{"errcode":4002,"errMsg":"not match"}`, wantCode: "4002"},
		{name: "HTTP500", status: 500, body: `{"errcode":0}`, wantCode: "0", wantRetryable: true},
		{name: "限频429", status: 429, body: `{"errcode":0}`, wantCode: "0", wantRetryable: true},
		{name: "非JSON应答", status: 502, body: `<html>bad gateway</html>`, wantCode: "", wantRetryable: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			x := newTestXiaomi(t, srv.URL)
			_, err := x.VerifyLogin(context.Background(), testUID+":"+testSession)
			if err == nil {
				t.Fatal("期望报错")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("非平台错误: %v", err)
			}
			if pe.Platform != PlatformName || pe.Op != opLoginValidate {
				t.Errorf("Platform/Op = %s/%s", pe.Platform, pe.Op)
			}
			if pe.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", pe.Code, tc.wantCode)
			}
			if errs.IsRetryable(err) != tc.wantRetryable {
				t.Errorf("IsRetryable = %v, want %v", errs.IsRetryable(err), tc.wantRetryable)
			}
		})
	}
}

// TestVerifyLogin_BadCredential 凭据非法时不发起网络请求、直接报错。
func TestVerifyLogin_BadCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("凭据非法时不应发起请求")
	}))
	defer srv.Close()

	x := newTestXiaomi(t, srv.URL)
	for _, cred := range []string{"", "nocolon", "abc:sess"} {
		if _, err := x.VerifyLogin(context.Background(), cred); err == nil {
			t.Errorf("credential=%q 期望报错", cred)
		}
	}
}

// TestVerifyLogin_NetworkError 传输层失败应标记可重试。
func TestVerifyLogin_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // 立即关闭制造连接拒绝

	x := newTestXiaomi(t, srv.URL)
	_, err := x.VerifyLogin(context.Background(), testUID+":"+testSession)
	if err == nil {
		t.Fatal("期望报错")
	}
	if !errs.IsRetryable(err) {
		t.Errorf("网络错误应可重试: %v", err)
	}
}

// TestNew_Validation 构造期 fail-fast 校验。
func TestNew_Validation(t *testing.T) {
	if _, err := New(Config{AppSecret: "s"}); err == nil {
		t.Error("缺 AppID 应报错")
	}
	if _, err := New(Config{AppID: "a"}); err == nil {
		t.Error("缺 AppSecret 应报错")
	}
	x, err := New(Config{AppID: "a", AppSecret: "s"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if x.Name() != PlatformName {
		t.Errorf("Name = %s", x.Name())
	}
	if x.cfg.BaseURL != DefaultBaseURL || x.cfg.Currency != DefaultCurrency ||
		x.cfg.WebhookTolerance != DefaultWebhookTolerance || x.cfg.PayTimeLocation == nil {
		t.Errorf("默认值未生效: %+v", x.cfg)
	}
	// MustNew panic 路径。
	defer func() {
		if recover() == nil {
			t.Error("MustNew 配置非法应 panic")
		}
	}()
	MustNew(Config{})
}

// TestVerifyLogin_SentinelUnwrap errs.Error 链上保留底层错误供 errors.Is 匹配
// （这里验证凭据错误不属于任何 webhook 哨兵，防误用）。
func TestVerifyLogin_SentinelUnwrap(t *testing.T) {
	x := newTestXiaomi(t, "http://127.0.0.1:0")
	_, err := x.VerifyLogin(context.Background(), "")
	if err == nil {
		t.Fatal("期望报错")
	}
	if errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Error("凭据错误不应匹配 webhook 哨兵")
	}
}
