//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：LoginProvider——jscode2session 用 tt.login 的 code 换 openid / session_key / unionid
//2026/6/11
//***************************************************

package douyin

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opCode2Session = "code2session"

// code2SessionPath code2Session 接口。
//
// 文档：https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/server/log-in/code-2-session
// （2026-06-11 curl 拉取正文）
//   - GET https://minigame.zijieapi.com/mgplatform/api/apps/jscode2session
//     （原域名 https://developer.toutiao.com/api/apps/jscode2session 仍可用，
//     官方建议更换到新域名）
//   - 请求头：content-type: application/json（文档标注固定值、必填——虽是 GET，
//     仍按文档原样携带）
//   - Query 参数：appid（必填，小游戏 ID）/ secret（必填，APP Secret）/
//     code（tt.login 返回的登录凭证）/ anonymous_code（tt.login 返回的匿名登录凭证）
//     ——code 和 anonymous_code 至少要有一个；非匿名需要 code，匿名需要 anonymous_code
//   - 应答字段：error（Int64 错误号，非 0 即错）/ errcode（Int64 详细错误号）/
//     errmsg / message（错误信息）/ openid（请求带 code 才返回）/
//     session_key（请求带 code 才返回）/ unionid（请求带 code 才返回，开发者拥有
//     多个小游戏时跨游戏唯一）/ anonymous_openid（请求带 anonymous_code 才返回）
//   - 错误码（HTTP 200 + 错误码）：0 成功 / -1 系统错误 / 40014 未传必要参数 /
//     40015 appid 错误 / 40017 secret 错误 / 40018 code 错误 / 40019 anonymous code 错误
//   - 官方告诫：登录凭证 code / anonymous_code 只能使用一次；session_key 不应下发
//     到小游戏，泄露可能导致小游戏被下架。
const code2SessionPath = "/mgplatform/api/apps/jscode2session"

// code2SessionResp 是 jscode2session 接口的应答（成功与错误字段平铺共存，
// 字段名以官方文档为准，见 code2SessionPath 注释）。
type code2SessionResp struct {
	Error           int64  `json:"error"`
	ErrCode         int64  `json:"errcode"`
	ErrMsg          string `json:"errmsg"`
	Message         string `json:"message"`
	OpenID          string `json:"openid"`
	SessionKey      string `json:"session_key"`
	UnionID         string `json:"unionid"`
	AnonymousOpenID string `json:"anonymous_openid"`
}

// VerifyLogin 实现 platform.LoginProvider（非匿名登录）。
//
// credential 是客户端 tt.login 拿到的一次性登录凭证 code，本方法调 jscode2session
// 换取身份并映射为标准化身份：
//
//   - OpenID     ← openid（用户在当前小游戏的 ID）
//   - UnionID    ← unionid（开发者多个小游戏间的跨游戏唯一标识）
//   - SessionKey ← session_key（凭据类数据：只允许留在服务端，严禁下发客户端或打日志）
//   - Raw        ← anonymous_openid 透传（通常为空）
//
// 匿名登录（tt.login 的 anonymous_code）走 VerifyLoginAnonymous。
func (d *Douyin) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, opCode2Session, "", "credential（tt.login 的 code）为空")
	}
	body, err := d.code2Session(ctx, url.Values{"code": {credential}})
	if err != nil {
		return nil, err
	}
	if body.OpenID == "" {
		// 200 且 error==0 却缺 openid——官方文档明确请求带 code 时返回 openid，
		// 视为协议异常。
		return nil, errs.New(PlatformName, opCode2Session, "", "应答缺少 openid 字段")
	}
	return &platform.PlatformIdentity{
		Platform:   PlatformName,
		OpenID:     body.OpenID,
		UnionID:    body.UnionID,
		SessionKey: body.SessionKey,
		Raw: map[string]string{
			"anonymous_openid": body.AnonymousOpenID,
		},
	}, nil
}

// VerifyLoginAnonymous 匿名登录校验（平台扩展能力，不属于合约接口）。
//
// anonymousCode 是 tt.login 返回的匿名登录凭证 anonymous_code，本方法换取
// anonymous_openid（匿名用户在当前小游戏的 ID）并映射：
//
//   - OpenID ← anonymous_openid
//   - Raw["anonymous"] = "true" 标记匿名身份（匿名无 unionid / session_key）
//
// 协议同 VerifyLogin（见 code2SessionPath 注释）：官方明确「匿名需要 anonymous_code」。
func (d *Douyin) VerifyLoginAnonymous(ctx context.Context, anonymousCode string) (*platform.PlatformIdentity, error) {
	if anonymousCode == "" {
		return nil, errs.New(PlatformName, opCode2Session, "", "anonymousCode（tt.login 的 anonymous_code）为空")
	}
	body, err := d.code2Session(ctx, url.Values{"anonymous_code": {anonymousCode}})
	if err != nil {
		return nil, err
	}
	if body.AnonymousOpenID == "" {
		// 官方文档明确请求带 anonymous_code 时返回 anonymous_openid。
		return nil, errs.New(PlatformName, opCode2Session, "", "应答缺少 anonymous_openid 字段")
	}
	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   body.AnonymousOpenID,
		Raw: map[string]string{
			"anonymous": "true",
		},
	}, nil
}

// code2Session 调 jscode2session 并完成传输层 / 业务层错误归一
// （endpoint 协议见 code2SessionPath 注释）。
func (d *Douyin) code2Session(ctx context.Context, creds url.Values) (*code2SessionResp, error) {
	query := url.Values{
		"appid":  {d.cfg.AppID},
		"secret": {d.cfg.AppSecret},
	}
	for k, vs := range creds {
		for _, v := range vs {
			query.Add(k, v)
		}
	}
	// 文档把 content-type: application/json 标注为必填请求头（虽是 GET），按文档原样携带。
	header := http.Header{}
	header.Set("Content-Type", "application/json")

	resp, err := d.hc.Get(ctx, httpx.JoinURL(d.cfg.MinigameBaseURL, code2SessionPath), query, header)
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
	// 平台业务错误：error 非 0 即错（错误码表见 code2SessionPath 注释）。
	// 详细错误号优先用 errcode，缺失时回退 error；描述优先 errmsg，缺失时回退 message。
	if body.Error != 0 {
		code := body.ErrCode
		if code == 0 {
			code = body.Error
		}
		msg := body.ErrMsg
		if msg == "" {
			msg = body.Message
		}
		return nil, errs.New(PlatformName, opCode2Session, strconv.FormatInt(code, 10), msg).
			WithHTTPStatus(resp.StatusCode).
			// -1 系统错误属暂时性；40014~40019 是确定性参数/凭据错误。
			WithRetryable(body.Error == -1 || retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opCode2Session, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	return &body, nil
}
