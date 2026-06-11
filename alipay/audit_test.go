//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：AuditText / AuditImage 单测——content.detect 处置映射
//2026/6/11
//***************************************************

package alipay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// contentDetectGateway 构造校验 biz_content.content 的 mock 网关。
func contentDetectGateway(t *testing.T, wantText, node string) (gatewayURL string, closeFn func()) {
	srv := newMockGateway(t, func(t *testing.T, r *http.Request, params url.Values) (string, string) {
		if got := params.Get("method"); got != methodContentDetect {
			t.Errorf("method = %q", got)
		}
		var biz contentDetectBiz
		if err := json.Unmarshal([]byte(r.PostForm.Get("biz_content")), &biz); err != nil {
			t.Errorf("biz_content 不是合法 JSON: %v", err)
		}
		if biz.Content != wantText {
			t.Errorf("content = %q, 期望 %q", biz.Content, wantText)
		}
		return respNodeKey(methodContentDetect), node
	})
	return srv.URL, srv.Close
}

func TestAuditText(t *testing.T) {
	t.Run("PASSED放行", func(t *testing.T) {
		gw, done := contentDetectGateway(t, "正常文本",
			`{"code":"10000","msg":"Success","action":"PASSED","unique_id":"0ba600421493362500440513027526"}`)
		defer done()
		a := newTestAlipay(t, gw, nil)

		result, err := a.AuditText(context.Background(), "ignored-openid", "正常文本")
		if err != nil {
			t.Fatalf("AuditText 失败: %v", err)
		}
		if !result.Pass || result.Suggestion != platform.SuggestionPass {
			t.Errorf("PASSED 应放行: %+v", result)
		}
		if result.TraceID != "0ba600421493362500440513027526" {
			t.Errorf("TraceID = %q, 期望透传 unique_id", result.TraceID)
		}
	})

	t.Run("REJECTED拦截", func(t *testing.T) {
		gw, done := contentDetectGateway(t, `特殊"字符&文本`,
			`{"code":"10000","msg":"Success","action":"REJECTED","unique_id":"0ba6"}`)
		defer done()
		a := newTestAlipay(t, gw, nil)

		// 同时验证含双引号/& 的文本经 json.Marshal 规范转义后能正确送达。
		result, err := a.AuditText(context.Background(), "", `特殊"字符&文本`)
		if err != nil {
			t.Fatalf("AuditText 失败: %v", err)
		}
		if result.Pass || result.Suggestion != platform.SuggestionReject {
			t.Errorf("REJECTED 应拦截: %+v", result)
		}
	})

	t.Run("未知action协议异常", func(t *testing.T) {
		gw, done := contentDetectGateway(t, "文本",
			`{"code":"10000","msg":"Success","action":"REVIEW_MAYBE","unique_id":"0ba6"}`)
		defer done()
		a := newTestAlipay(t, gw, nil)

		_, err := a.AuditText(context.Background(), "", "文本")
		if err == nil || !strings.Contains(err.Error(), "未知 action") {
			t.Fatalf("期望未知 action 报错, got %v", err)
		}
	})

	t.Run("业务错误透传", func(t *testing.T) {
		gw, done := contentDetectGateway(t, "文本",
			`{"code":"40004","msg":"Business Failed","sub_code":"INVALID_PARAMETER","sub_msg":"参数有误"}`)
		defer done()
		a := newTestAlipay(t, gw, nil)

		_, err := a.AuditText(context.Background(), "", "文本")
		if errs.CodeOf(err) != "INVALID_PARAMETER" {
			t.Fatalf("Code = %q, 期望 INVALID_PARAMETER（err=%v）", errs.CodeOf(err), err)
		}
	})

	t.Run("text为空", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		if _, err := a.AuditText(context.Background(), "", ""); err == nil {
			t.Fatal("期望报错")
		}
	})
}

func TestAuditImage(t *testing.T) {
	a := newTestAlipay(t, DefaultGatewayURL, nil)
	_, err := a.AuditImage(context.Background(), "openid", []byte{0x89, 0x50})
	if err == nil || !strings.Contains(err.Error(), "图片内容风险检测") {
		t.Fatalf("AuditImage 应返回明确的能力缺失错误, got %v", err)
	}
}
