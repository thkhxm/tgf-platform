//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：VerifyPayment 单测——trade.query 状态映射 / 金额换算 / 防串单
//2026/6/11
//***************************************************

package alipay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

const (
	testOutTradeNo = "6823789339978248"
	testTradeNo    = "2013112011001004330000121536"
)

// tradeQueryNode 按官方响应示例形态构造成功节点。
func tradeQueryNode(status, totalAmount string) string {
	return fmt.Sprintf(`{"code":"10000","msg":"Success","trade_no":%q,"out_trade_no":%q,"buyer_logon_id":"159****5620","trade_status":%q,"total_amount":%q,"send_pay_date":"2014-11-27 15:45:57","buyer_pay_amount":"8.88","receipt_amount":"15.25","buyer_user_id":"2088101117955611"}`,
		testTradeNo, testOutTradeNo, status, totalAmount)
}

// tradeQueryGateway 构造校验 biz_content 的 mock 网关。
func tradeQueryGateway(t *testing.T, node string) (gatewayURL string, closeFn func()) {
	srv := newMockGateway(t, func(t *testing.T, r *http.Request, params url.Values) (string, string) {
		if got := params.Get("method"); got != methodTradeQuery {
			t.Errorf("method = %q", got)
		}
		// 业务参数纪律：trade.query 走 biz_content（JSON 串），置于表单体。
		bizRaw := r.PostForm.Get("biz_content")
		if bizRaw == "" {
			t.Error("缺少 biz_content（且必须置于 body 表单）")
		}
		var biz tradeQueryBiz
		if err := json.Unmarshal([]byte(bizRaw), &biz); err != nil {
			t.Errorf("biz_content 不是合法 JSON: %v", err)
		}
		if biz.OutTradeNo == "" && biz.TradeNo == "" {
			t.Error("out_trade_no 与 trade_no 至少一个（官方：二选一必填）")
		}
		return respNodeKey(methodTradeQuery), node
	})
	return srv.URL, srv.Close
}

func TestVerifyPayment(t *testing.T) {
	receipt := platform.PaymentReceipt{
		Platform: PlatformName,
		OrderID:  testOutTradeNo,
		Amount:   8888,
		Currency: "CNY",
	}

	t.Run("TRADE_SUCCESS已支付", func(t *testing.T) {
		gw, done := tradeQueryGateway(t, tradeQueryNode("TRADE_SUCCESS", "88.88"))
		defer done()
		a := newTestAlipay(t, gw, nil)

		result, err := a.VerifyPayment(context.Background(), receipt)
		if err != nil {
			t.Fatalf("VerifyPayment 失败: %v", err)
		}
		if !result.Paid {
			t.Error("TRADE_SUCCESS 应判已支付")
		}
		if result.Amount != 8888 {
			t.Errorf("Amount = %d, 期望 8888 分", result.Amount)
		}
		if result.Currency != "CNY" {
			t.Errorf("Currency = %q", result.Currency)
		}
		if result.TransactionID != testTradeNo {
			t.Errorf("TransactionID = %q", result.TransactionID)
		}
		if result.OrderID != testOutTradeNo {
			t.Errorf("OrderID = %q", result.OrderID)
		}
		wantPaidAt := time.Date(2014, 11, 27, 15, 45, 57, 0, cstZone)
		if !result.PaidAt.Equal(wantPaidAt) {
			t.Errorf("PaidAt = %v, 期望 %v", result.PaidAt, wantPaidAt)
		}
		if result.Sandbox {
			t.Error("httptest 网关无 alipaydev 域名，不应判沙箱")
		}
		if result.Raw["trade_status"] != "TRADE_SUCCESS" || result.Raw["buyer_user_id"] != "2088101117955611" {
			t.Errorf("Raw 透传缺失: %v", result.Raw)
		}
	})

	t.Run("TRADE_FINISHED已支付", func(t *testing.T) {
		gw, done := tradeQueryGateway(t, tradeQueryNode("TRADE_FINISHED", "88.88"))
		defer done()
		a := newTestAlipay(t, gw, nil)

		result, err := a.VerifyPayment(context.Background(), receipt)
		if err != nil {
			t.Fatalf("VerifyPayment 失败: %v", err)
		}
		if !result.Paid {
			t.Error("TRADE_FINISHED 应判已支付")
		}
	})

	t.Run("WAIT_BUYER_PAY未支付", func(t *testing.T) {
		gw, done := tradeQueryGateway(t, tradeQueryNode("WAIT_BUYER_PAY", "88.88"))
		defer done()
		a := newTestAlipay(t, gw, nil)

		result, err := a.VerifyPayment(context.Background(), receipt)
		if err != nil {
			t.Fatalf("VerifyPayment 失败: %v", err)
		}
		if result.Paid {
			t.Error("WAIT_BUYER_PAY 不应判已支付")
		}
	})

	t.Run("TRADE_CLOSED未支付", func(t *testing.T) {
		gw, done := tradeQueryGateway(t, tradeQueryNode("TRADE_CLOSED", "88.88"))
		defer done()
		a := newTestAlipay(t, gw, nil)

		result, err := a.VerifyPayment(context.Background(), receipt)
		if err != nil {
			t.Fatalf("VerifyPayment 失败: %v", err)
		}
		if result.Paid {
			t.Error("TRADE_CLOSED（关单/全额退款）不应判已支付")
		}
	})

	t.Run("未知trade_status协议异常", func(t *testing.T) {
		gw, done := tradeQueryGateway(t, tradeQueryNode("SOMETHING_NEW", "88.88"))
		defer done()
		a := newTestAlipay(t, gw, nil)

		_, err := a.VerifyPayment(context.Background(), receipt)
		if err == nil || !strings.Contains(err.Error(), "未知 trade_status") {
			t.Fatalf("期望未知状态报错, got %v", err)
		}
	})

	t.Run("金额数字形态容错", func(t *testing.T) {
		// total_amount 官方类型 price、示例带引号，但实际可能返回 JSON number。
		node := `{"code":"10000","msg":"Success","trade_no":"` + testTradeNo + `","out_trade_no":"` + testOutTradeNo + `","trade_status":"TRADE_SUCCESS","total_amount":88.88}`
		gw, done := tradeQueryGateway(t, node)
		defer done()
		a := newTestAlipay(t, gw, nil)

		result, err := a.VerifyPayment(context.Background(), receipt)
		if err != nil {
			t.Fatalf("VerifyPayment 失败: %v", err)
		}
		if result.Amount != 8888 {
			t.Errorf("Amount = %d, 期望 8888", result.Amount)
		}
	})

	t.Run("交易不存在", func(t *testing.T) {
		node := `{"code":"40004","msg":"Business Failed","sub_code":"ACQ.TRADE_NOT_EXIST","sub_msg":"查询的交易不存在"}`
		gw, done := tradeQueryGateway(t, node)
		defer done()
		a := newTestAlipay(t, gw, nil)

		_, err := a.VerifyPayment(context.Background(), receipt)
		if err == nil {
			t.Fatal("期望报错")
		}
		if errs.CodeOf(err) != "ACQ.TRADE_NOT_EXIST" {
			t.Errorf("Code = %q, 期望透传 sub_code", errs.CodeOf(err))
		}
		if errs.IsRetryable(err) {
			t.Error("交易不存在是确定性失败，不应可重试")
		}
	})

	t.Run("系统错误可重试", func(t *testing.T) {
		node := `{"code":"40004","msg":"Business Failed","sub_code":"ACQ.SYSTEM_ERROR","sub_msg":"系统错误"}`
		gw, done := tradeQueryGateway(t, node)
		defer done()
		a := newTestAlipay(t, gw, nil)

		_, err := a.VerifyPayment(context.Background(), receipt)
		if err == nil {
			t.Fatal("期望报错")
		}
		if !errs.IsRetryable(err) {
			t.Error("ACQ.SYSTEM_ERROR 官方解决方案是重新发起请求，应可重试")
		}
	})

	t.Run("应答out_trade_no不一致防串单", func(t *testing.T) {
		node := `{"code":"10000","msg":"Success","trade_no":"` + testTradeNo + `","out_trade_no":"别的订单","trade_status":"TRADE_SUCCESS","total_amount":"88.88"}`
		gw, done := tradeQueryGateway(t, node)
		defer done()
		a := newTestAlipay(t, gw, nil)

		_, err := a.VerifyPayment(context.Background(), receipt)
		if err == nil || !strings.Contains(err.Error(), "串单") {
			t.Fatalf("期望防串单报错, got %v", err)
		}
	})

	t.Run("total_amount缺失协议异常", func(t *testing.T) {
		node := `{"code":"10000","msg":"Success","trade_no":"` + testTradeNo + `","out_trade_no":"` + testOutTradeNo + `","trade_status":"TRADE_SUCCESS"}`
		gw, done := tradeQueryGateway(t, node)
		defer done()
		a := newTestAlipay(t, gw, nil)

		_, err := a.VerifyPayment(context.Background(), receipt)
		if err == nil || !strings.Contains(err.Error(), "total_amount") {
			t.Fatalf("期望金额解析报错, got %v", err)
		}
	})

	t.Run("Platform不匹配防串单", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		_, err := a.VerifyPayment(context.Background(), platform.PaymentReceipt{
			Platform: "wechat", OrderID: testOutTradeNo,
		})
		if err == nil || !strings.Contains(err.Error(), "防串单") {
			t.Fatalf("期望防串单报错, got %v", err)
		}
	})

	t.Run("订单号交易号均缺失", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		_, err := a.VerifyPayment(context.Background(), platform.PaymentReceipt{Platform: PlatformName})
		if err == nil || !strings.Contains(err.Error(), "至少填一个") {
			t.Fatalf("期望参数缺失报错, got %v", err)
		}
	})

	t.Run("TransactionID查单", func(t *testing.T) {
		gw, done := tradeQueryGateway(t, tradeQueryNode("TRADE_SUCCESS", "88.88"))
		defer done()
		a := newTestAlipay(t, gw, nil)

		result, err := a.VerifyPayment(context.Background(), platform.PaymentReceipt{
			Platform:      PlatformName,
			TransactionID: testTradeNo, // 仅传支付宝交易号
		})
		if err != nil {
			t.Fatalf("VerifyPayment 失败: %v", err)
		}
		if !result.Paid || result.TransactionID != testTradeNo {
			t.Errorf("查单结果异常: %+v", result)
		}
	})
}
