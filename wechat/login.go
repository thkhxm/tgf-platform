//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：LoginProvider——jscode2session 用 wx.login code 换 openid / session_key / unionid
//2026/6/11
//***************************************************

package wechat

import (
	"context"
	"net/url"
	"strconv"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opCode2Session = "code2session"

// code2SessionPath 小程序/小游戏登录凭证校验。
//
// 文档：https://developers.weixin.qq.com/minigame/dev/api-backend/login/api_code2session.html
// （2026-06-11 拉取；原 https://developers.weixin.qq.com/minigame/dev/api-backend/open-api/login/auth.code2Session.html
// 已 301 至此）
//   - GET https://api.weixin.qq.com/sns/jscode2session?appid=APPID&secret=SECRET
//     &js_code=JS_CODE&grant_type=authorization_code
//   - 查询参数：appid（小程序 appId）/ secret（appSecret）/ js_code（wx.login
//     获取的 code）/ grant_type（固定 authorization_code）
//   - 成功响应（JSON）：openid（用户唯一标识）/ session_key（会话密钥）/
//     unionid（绑定微信开放平台帐号时返回）
//   - 失败响应：errcode（number）/ errmsg；错误码表：-1 系统繁忙（稍候再试）/
//     40029 code 无效 / 40226 code blocked（高风险用户拦截）/ 45011 API 分钟
//     级限频（retry next minute）
//
// 关键纪律：js_code 是一次性凭据（消费过即作废），网络歧义失败后重试同一 code
// 会得到确定性的 40029——本实现不开 HTTP 层重试，由上层按 errs.IsRetryable 决策。
const code2SessionPath = "/sns/jscode2session"

// code2SessionResp jscode2session 应答（成功与错误字段平铺共存，
// 字段名以官方文档为准，见 code2SessionPath 注释）。
type code2SessionResp struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid"`

	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端 wx.login 拿到的一次性临时登录凭证 code，本方法调
// jscode2session 换取身份并映射为标准化身份：
//
//   - OpenID     ← openid
//   - UnionID    ← unionid（小游戏绑定到微信开放平台帐号时返回，否则为空）
//   - SessionKey ← session_key
//
// 安全注意（合约纪律）：SessionKey 属凭据类数据，只允许留在服务端受控存储，
// 严禁下发客户端或打日志。业务应把它按 openid 存好——后续米大师支付校验
// （VerifyPayment）经 Config.SessionKeyFunc 取回做登录态签名。
func (w *WeChat) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, opCode2Session, "", "credential（wx.login code）为空")
	}

	query := url.Values{
		"appid":      {w.cfg.AppID},
		"secret":     {w.cfg.AppSecret},
		"js_code":    {credential},
		"grant_type": {"authorization_code"},
	}
	resp, err := w.hc.Get(ctx, httpx.JoinURL(w.cfg.BaseURL, code2SessionPath), query, nil)
	if err != nil {
		// 传输层失败（网络错误/超时）——可重试；但注意 code 一次性，重试由上层决策。
		return nil, errs.Wrap(PlatformName, opCode2Session, err).WithRetryable(true)
	}

	var body code2SessionResp
	if err := resp.JSON(&body); err != nil {
		// 非 JSON 应答（HTML 错误页等）：5xx/429 视为暂时性。
		return nil, errs.Wrap(PlatformName, opCode2Session, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 平台业务错误（errcode 平铺在顶层，0 为成功）。
	if body.ErrCode != 0 {
		return nil, errs.New(PlatformName, opCode2Session, strconv.FormatInt(body.ErrCode, 10), body.ErrMsg).
			WithHTTPStatus(resp.StatusCode).
			// -1 系统繁忙、45011 分钟级限频官方明确「稍候再试」；
			// 40029（code 无效）/ 40226（高风险拦截）是确定性失败。
			WithRetryable(body.ErrCode == -1 || body.ErrCode == 45011 || retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opCode2Session, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.OpenID == "" || body.SessionKey == "" {
		// errcode==0 却缺关键字段——按官方文档这不该发生，视为协议异常。
		return nil, errs.New(PlatformName, opCode2Session, "",
			"应答缺少 openid / session_key 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}

	return &platform.PlatformIdentity{
		Platform:   PlatformName,
		OpenID:     body.OpenID,
		UnionID:    body.UnionID,
		SessionKey: body.SessionKey,
	}, nil
}
