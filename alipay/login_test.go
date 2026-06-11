//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：VerifyLogin 单测——mock 网关按官方 RSA2 算法重算签名
//2026/6/11
//***************************************************

package alipay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
)

const testAuthCode = "4b203fe6c11548bcabd8da5bb087a83b"

// oauthTokenNode 官方响应示例形态的成功节点（注意：无 code/msg 字段）。
func oauthTokenNode(userID, openID string) string {
	return fmt.Sprintf(`{"user_id":%q,"open_id":%q,"access_token":"20120823ac6ffaa4d2d84e7384bf983531473993","expires_in":"3600","refresh_token":"20120823ac6ffdsdf2d84e7384bf983531473993","re_expires_in":"3600","auth_start":"2010-11-11 11:11:11"}`,
		userID, openID)
}

func TestVerifyLogin(t *testing.T) {
	t.Run("成功_user_id形态", func(t *testing.T) {
		srv := newMockGateway(t, func(t *testing.T, r *http.Request, params url.Values) (string, string) {
			if got := params.Get("method"); got != methodOAuthToken {
				t.Errorf("method = %q", got)
			}
			// 业务参数纪律：grant_type / code 平铺在表单体（不是 biz_content）。
			if got := r.PostForm.Get("grant_type"); got != "authorization_code" {
				t.Errorf("grant_type = %q（且必须置于 body 表单）", got)
			}
			if got := r.PostForm.Get("code"); got != testAuthCode {
				t.Errorf("code = %q", got)
			}
			if got := params.Get("biz_content"); got != "" {
				t.Errorf("oauth.token 不应携带 biz_content: %q", got)
			}
			return respNodeKey(methodOAuthToken), oauthTokenNode("2088102150477652", "")
		})
		defer srv.Close()
		a := newTestAlipay(t, srv.URL, nil)

		identity, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err != nil {
			t.Fatalf("VerifyLogin 失败: %v", err)
		}
		if identity.Platform != PlatformName {
			t.Errorf("Platform = %q", identity.Platform)
		}
		if identity.OpenID != "2088102150477652" {
			t.Errorf("OpenID = %q, 期望回退 user_id", identity.OpenID)
		}
		if identity.UnionID != "" || identity.SessionKey != "" {
			t.Errorf("UnionID/SessionKey 应为空: %q %q", identity.UnionID, identity.SessionKey)
		}
		if identity.Raw["access_token"] != "20120823ac6ffaa4d2d84e7384bf983531473993" {
			t.Errorf("Raw[access_token] = %q", identity.Raw["access_token"])
		}
		if identity.Raw["expires_in"] != "3600" || identity.Raw["refresh_token"] == "" {
			t.Errorf("Raw 透传缺失: %v", identity.Raw)
		}
	})

	t.Run("成功_open_id优先", func(t *testing.T) {
		srv := newMockGateway(t, func(t *testing.T, r *http.Request, params url.Values) (string, string) {
			return respNodeKey(methodOAuthToken), oauthTokenNode("2088102150477652", "074a1CcTG1LelxKe4xQC0zgNdId0nxi95b5lsNpazWYoCo5")
		})
		defer srv.Close()
		a := newTestAlipay(t, srv.URL, nil)

		identity, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err != nil {
			t.Fatalf("VerifyLogin 失败: %v", err)
		}
		if identity.OpenID != "074a1CcTG1LelxKe4xQC0zgNdId0nxi95b5lsNpazWYoCo5" {
			t.Errorf("OpenID = %q, 期望优先 open_id", identity.OpenID)
		}
		if identity.Raw["user_id"] != "2088102150477652" {
			t.Errorf("Raw[user_id] = %q", identity.Raw["user_id"])
		}
	})

	t.Run("credential为空", func(t *testing.T) {
		a := newTestAlipay(t, DefaultGatewayURL, nil)
		if _, err := a.VerifyLogin(context.Background(), ""); err == nil {
			t.Fatal("期望报错")
		}
	})

	t.Run("平台错误_isv_code_invalid", func(t *testing.T) {
		appKey, platKey := testKeys(t)
		_ = appKey
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 网关级错误走 error_response 节点（官方业务错误码表：isv.code-invalid）。
			node := `{"code":"40002","msg":"Invalid Arguments","sub_code":"isv.code-invalid","sub_msg":"授权码错误、状态不对或过期"}`
			respSig, _ := sign.RSASHA256SignBase64(platKey, []byte(node))
			fmt.Fprintf(w, `{"error_response":%s,"sign":%q}`, node, respSig)
		}))
		defer srv.Close()
		a := newTestAlipay(t, srv.URL, nil)

		_, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err == nil {
			t.Fatal("期望报错")
		}
		pe, ok := errs.AsPlatformError(err)
		if !ok {
			t.Fatalf("期望平台错误, got %T: %v", err, err)
		}
		if pe.Code != "isv.code-invalid" {
			t.Errorf("Code = %q, 期望透传 sub_code", pe.Code)
		}
		if pe.Retryable {
			t.Error("授权码错误是确定性失败，不应可重试")
		}
	})

	t.Run("应答签名被篡改", func(t *testing.T) {
		_, platKey := testKeys(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			node := oauthTokenNode("2088102150477652", "")
			// 对篡改后的内容签名——与下发节点不一致，验签必须失败。
			respSig, _ := sign.RSASHA256SignBase64(platKey, []byte(`{"user_id":"2088999999999999"}`))
			fmt.Fprintf(w, `{"%s":%s,"sign":%q}`, respNodeKey(methodOAuthToken), node, respSig)
		}))
		defer srv.Close()
		a := newTestAlipay(t, srv.URL, nil)

		_, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err == nil || !strings.Contains(err.Error(), "验签失败") {
			t.Fatalf("期望验签失败, got %v", err)
		}
	})

	t.Run("应答缺少sign", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"%s":%s}`, respNodeKey(methodOAuthToken), oauthTokenNode("2088102150477652", ""))
		}))
		defer srv.Close()
		a := newTestAlipay(t, srv.URL, nil)

		_, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err == nil || !strings.Contains(err.Error(), "缺少 sign") {
			t.Fatalf("期望缺少 sign 报错, got %v", err)
		}
	})

	t.Run("应答缺少关键字段", func(t *testing.T) {
		srv := newMockGateway(t, func(t *testing.T, r *http.Request, params url.Values) (string, string) {
			return respNodeKey(methodOAuthToken), `{"expires_in":"3600"}`
		})
		defer srv.Close()
		a := newTestAlipay(t, srv.URL, nil)

		_, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err == nil || !strings.Contains(err.Error(), "缺少 access_token") {
			t.Fatalf("期望缺字段报错, got %v", err)
		}
	})

	t.Run("FetchUserInfo成功", func(t *testing.T) {
		srv := newMockGateway(t, func(t *testing.T, r *http.Request, params url.Values) (string, string) {
			switch params.Get("method") {
			case methodOAuthToken:
				return respNodeKey(methodOAuthToken), oauthTokenNode("2088102104794936", "")
			case methodUserInfoShare:
				// auth_token 必须是刚换到的用户 access_token。
				if got := r.PostForm.Get("auth_token"); got != "20120823ac6ffaa4d2d84e7384bf983531473993" {
					t.Errorf("auth_token = %q", got)
				}
				return respNodeKey(methodUserInfoShare),
					`{"code":"10000","msg":"Success","user_id":"2088102104794936","avatar":"http://tfsimg.alipay.com/images/partner/T1uIxXXbpXXXXXXXX","city":"安庆","nick_name":"支付宝小二","province":"安徽省","gender":"F"}`
			default:
				t.Errorf("意外的 method: %q", params.Get("method"))
				return "error_response", `{"code":"40004","msg":"unexpected"}`
			}
		})
		defer srv.Close()
		a := newTestAlipay(t, srv.URL, func(c *Config) { c.FetchUserInfo = true })

		identity, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err != nil {
			t.Fatalf("VerifyLogin 失败: %v", err)
		}
		if identity.Raw["nick_name"] != "支付宝小二" || identity.Raw["gender"] != "F" ||
			identity.Raw["province"] != "安徽省" || identity.Raw["city"] != "安庆" {
			t.Errorf("用户信息透传缺失: %v", identity.Raw)
		}
	})

	t.Run("FetchUserInfo串号防御", func(t *testing.T) {
		srv := newMockGateway(t, func(t *testing.T, r *http.Request, params url.Values) (string, string) {
			switch params.Get("method") {
			case methodOAuthToken:
				return respNodeKey(methodOAuthToken), oauthTokenNode("2088102104794936", "")
			default:
				return respNodeKey(methodUserInfoShare),
					`{"code":"10000","msg":"Success","user_id":"2088999999999999","nick_name":"别人"}`
			}
		})
		defer srv.Close()
		a := newTestAlipay(t, srv.URL, func(c *Config) { c.FetchUserInfo = true })

		_, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err == nil || !strings.Contains(err.Error(), "串号") {
			t.Fatalf("期望串号防御报错, got %v", err)
		}
	})

	t.Run("传输层失败可重试", func(t *testing.T) {
		a := newTestAlipay(t, "http://127.0.0.1:1", nil) // 必然连接失败
		_, err := a.VerifyLogin(context.Background(), testAuthCode)
		if err == nil {
			t.Fatal("期望报错")
		}
		if !errs.IsRetryable(err) {
			t.Errorf("传输层失败应标记可重试: %v", err)
		}
		var pe *errs.Error
		if !errors.As(err, &pe) {
			t.Fatalf("期望 *errs.Error, got %T", err)
		}
	})
}
