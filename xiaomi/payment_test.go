//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description xiaomi：VerifyPayment 单元测试（httptest mock，不打真实平台）
//2026/6/11
//***************************************************

package xiaomi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// 官方 5.3.2 示例订单数据（pId=1616，2026-06-11 拉取）。
const (
	testCPOrderID = "9786bffc-996d-4553-aa33-f7e92c0b29d5"
	testOrderID   = "21140990160359583390"
)

// testReceipt 标准请求凭据。
func testReceipt() platform.PaymentReceipt {
	return platform.PaymentReceipt{
		Platform: PlatformName,
		OrderID:  testCPOrderID,
		OpenID:   testUID,
	}
}

// officialQueryOrderResp 按官方 5.3.2 示例形态构造的成功应答。
// 其中 productName 是 URLencoding 形态（官方应答如此），而 signature
// 是对「URL 解码后的原值签名串」的 HMAC-SHA1——该签名串与官方 5.3.5 示例
// 完全一致，故签名值即 login_test.go 已知答案向量（Python 独立预计算）。
const officialQueryOrderResp = `{
  "signature": "e59a0382dc72da5ae7d22e8d3cceae0d0320d360",
  "uid": "100010",
  "appId": 2882303761517239138,
  "cpOrderId": "9786bffc-996d-4553-aa33-f7e92c0b29d5",
  "productCode": "com.demo_1",
  "orderStatus": "TRADE_SUCCESS",
  "productName": "%E9%93%B6%E5%AD%901%E4%B8%A4",
  "productCount": 1,
  "orderConsumeType": "10",
  "orderId": "21140990160359583390",
  "payFee": 1,
  "payTime": "2014-09-05 15:20:27"
}`

// signedQueryOrderResp 用包内签名原语对自定义字段组重签应答（算法本身已由
// 已知答案向量覆盖，这里只为构造行为分支数据）。
func signedQueryOrderResp(t *testing.T, mutate func(map[string]string)) string {
	t.Helper()
	values := map[string]string{
		"uid":              testUID,
		"appId":            testAppID,
		"cpOrderId":        testCPOrderID,
		"productCode":      "com.demo_1",
		"orderStatus":      orderStatusPaid,
		"productName":      "银子1两",
		"productCount":     "1",
		"orderConsumeType": "10",
		"orderId":          testOrderID,
		"payFee":           "1",
		"payTime":          "2014-09-05 15:20:27",
	}
	if mutate != nil {
		mutate(values)
	}
	sig := hmacSHA1Hex([]byte(testAppSecret), []byte(buildSignSource(values)))
	body := `{"signature":"` + sig + `"`
	for k, v := range values {
		body += `,"` + k + `":"` + v + `"`
	}
	return body + `}`
}

// TestVerifyPayment_Success 成功路径：官方示例形态应答 → 标准化结果映射。
func TestVerifyPayment_Success(t *testing.T) {
	var gotQuery map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Method = %s, want GET", r.Method)
		}
		if r.URL.Path != queryOrderPath {
			t.Errorf("Path = %s, want %s", r.URL.Path, queryOrderPath)
		}
		q := r.URL.Query()
		gotQuery = map[string]string{
			"appId":     q.Get("appId"),
			"cpOrderId": q.Get("cpOrderId"),
			"uid":       q.Get("uid"),
			"signature": q.Get("signature"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(officialQueryOrderResp))
	}))
	defer srv.Close()

	x := newTestXiaomi(t, srv.URL)
	result, err := x.VerifyPayment(context.Background(), testReceipt())
	if err != nil {
		t.Fatalf("VerifyPayment: %v", err)
	}

	// 请求侧断言：参数 + 签名（与包内原语一致；原语正确性由已知答案向量保证）。
	wantSig := hmacSHA1Hex([]byte(testAppSecret),
		[]byte("appId="+testAppID+"&cpOrderId="+testCPOrderID+"&uid="+testUID))
	if gotQuery["appId"] != testAppID || gotQuery["cpOrderId"] != testCPOrderID ||
		gotQuery["uid"] != testUID || gotQuery["signature"] != wantSig {
		t.Fatalf("请求参数不符: %+v", gotQuery)
	}

	// 结果映射断言。
	if result.Platform != PlatformName {
		t.Errorf("Platform = %s", result.Platform)
	}
	if !result.Paid {
		t.Error("TRADE_SUCCESS 应判定 Paid=true")
	}
	if result.OrderID != testCPOrderID || result.TransactionID != testOrderID {
		t.Errorf("OrderID/TransactionID = %s/%s", result.OrderID, result.TransactionID)
	}
	if result.ProductID != "com.demo_1" {
		t.Errorf("ProductID = %s", result.ProductID)
	}
	if result.Amount != 1 {
		t.Errorf("Amount = %d, want 1（payFee 单位分，原样透传）", result.Amount)
	}
	if result.Currency != DefaultCurrency {
		t.Errorf("Currency = %s", result.Currency)
	}
	if result.Sandbox {
		t.Error("小米无沙箱概念，Sandbox 应恒为 false")
	}
	wantPaidAt := time.Date(2014, 9, 5, 15, 20, 27, 0, defaultPayTimeLocation)
	if !result.PaidAt.Equal(wantPaidAt) {
		t.Errorf("PaidAt = %v, want %v", result.PaidAt, wantPaidAt)
	}
	// URLencoding 形态的文本字段须被解码为原值透传。
	if result.Raw["productName"] != "银子1两" {
		t.Errorf("Raw[productName] = %s", result.Raw["productName"])
	}
}

// TestVerifyPayment_NotPaid 非 TRADE_SUCCESS 状态：应答合法但 Paid=false，不报错。
func TestVerifyPayment_NotPaid(t *testing.T) {
	for _, status := range []string{"WAIT_BUYER_PAY", "REPEAT_PURCHASE"} {
		t.Run(status, func(t *testing.T) {
			body := signedQueryOrderResp(t, func(v map[string]string) { v["orderStatus"] = status })
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			x := newTestXiaomi(t, srv.URL)
			result, err := x.VerifyPayment(context.Background(), testReceipt())
			if err != nil {
				t.Fatalf("VerifyPayment: %v", err)
			}
			if result.Paid {
				t.Errorf("orderStatus=%s 不应判定 Paid", status)
			}
			if result.Raw["orderStatus"] != status {
				t.Errorf("Raw[orderStatus] = %s", result.Raw["orderStatus"])
			}
		})
	}
}

// TestVerifyPayment_TamperedSignature 应答签名被篡改 / 字段被改动 → 验签失败。
func TestVerifyPayment_TamperedSignature(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "签名字段篡改",
			body: signedQueryOrderResp(t, func(v map[string]string) { v["payFee"] = "1" }), // 先生成合法体再破坏签名
		},
		{
			name: "金额字段篡改",
			// 用官方示例签名但 payFee 改大：签名对不上
			body: `{"signature":"e59a0382dc72da5ae7d22e8d3cceae0d0320d360","uid":"100010","appId":2882303761517239138,"cpOrderId":"9786bffc-996d-4553-aa33-f7e92c0b29d5","productCode":"com.demo_1","orderStatus":"TRADE_SUCCESS","productName":"%E9%93%B6%E5%AD%901%E4%B8%A4","productCount":1,"orderConsumeType":"10","orderId":"21140990160359583390","payFee":99999,"payTime":"2014-09-05 15:20:27"}`,
		},
		{
			name: "缺签名字段",
			body: `{"uid":"100010","appId":2882303761517239138,"cpOrderId":"9786bffc-996d-4553-aa33-f7e92c0b29d5","orderStatus":"TRADE_SUCCESS","payFee":1,"payTime":"2014-09-05 15:20:27"}`,
		},
		{
			name: "签名非法hex",
			body: `{"signature":"zz-not-hex","uid":"100010","appId":2882303761517239138,"cpOrderId":"9786bffc-996d-4553-aa33-f7e92c0b29d5","orderStatus":"TRADE_SUCCESS","payFee":1,"payTime":"2014-09-05 15:20:27"}`,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if i == 0 {
				// 破坏签名：尾部字符翻转。
				body = body[:len(body)-3] + `x"}`
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			x := newTestXiaomi(t, srv.URL)
			if _, err := x.VerifyPayment(context.Background(), testReceipt()); err == nil {
				t.Fatal("篡改应答应验签失败")
			}
		})
	}
}

// TestVerifyPayment_FieldMismatch 应答字段与 receipt 不匹配（防串单硬要求）。
func TestVerifyPayment_FieldMismatch(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]string)
		receipt platform.PaymentReceipt
	}{
		{
			name:    "cpOrderId不匹配",
			mutate:  func(v map[string]string) { v["cpOrderId"] = "other-order" },
			receipt: testReceipt(),
		},
		{
			name:    "uid不匹配",
			mutate:  func(v map[string]string) { v["uid"] = "999999" },
			receipt: testReceipt(),
		},
		{
			name:    "appId不匹配",
			mutate:  func(v map[string]string) { v["appId"] = "1234567" },
			receipt: testReceipt(),
		},
		{
			name:   "orderId与TransactionID不匹配",
			mutate: nil,
			receipt: platform.PaymentReceipt{
				Platform: PlatformName, OrderID: testCPOrderID, OpenID: testUID,
				TransactionID: "different-platform-order",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := signedQueryOrderResp(t, tc.mutate)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			x := newTestXiaomi(t, srv.URL)
			if _, err := x.VerifyPayment(context.Background(), tc.receipt); err == nil {
				t.Fatal("字段不匹配应报错（防串单）")
			}
		})
	}
}

// TestVerifyPayment_PlatformErrors 官方错误码应答的映射与重试分类。
func TestVerifyPayment_PlatformErrors(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		body          string
		wantCode      string
		wantRetryable bool
	}{
		{name: "cpOrderId错误1506", status: 200, body: `{"errcode":1506,"errMsg":"cpOrderId error"}`, wantCode: "1506"},
		{name: "appId错误1515", status: 200, body: `{"errcode":1515}`, wantCode: "1515"},
		{name: "uid错误1516", status: 200, body: `{"errcode":1516}`, wantCode: "1516"},
		{name: "签名错误1525", status: 200, body: `{"errcode":1525}`, wantCode: "1525"},
		{name: "HTTP500", status: 500, body: `{"errcode":1}`, wantCode: "1", wantRetryable: true},
		{name: "非JSON应答", status: 503, body: `<html>oops</html>`, wantCode: "", wantRetryable: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			x := newTestXiaomi(t, srv.URL)
			_, err := x.VerifyPayment(context.Background(), testReceipt())
			if err == nil {
				t.Fatal("期望报错")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("非平台错误: %v", err)
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

// TestVerifyPayment_BadReceipt receipt 校验失败时不发起网络请求。
func TestVerifyPayment_BadReceipt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("receipt 非法时不应发起请求")
	}))
	defer srv.Close()

	x := newTestXiaomi(t, srv.URL)
	cases := []platform.PaymentReceipt{
		{Platform: "wechat", OrderID: testCPOrderID, OpenID: testUID}, // 平台串单
		{Platform: PlatformName, OpenID: testUID},                     // 缺 OrderID
		{Platform: PlatformName, OrderID: testCPOrderID},              // 缺 OpenID
	}
	for i, receipt := range cases {
		if _, err := x.VerifyPayment(context.Background(), receipt); err == nil {
			t.Errorf("case %d 期望报错", i)
		}
	}
}
