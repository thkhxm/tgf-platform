//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：LoginProvider——OAuth v2 授权 code 换 open_id / access_token（+ 可选 user/info 补 union_id）
//2026/6/11
//***************************************************

package tiktok

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op），按平台 API 名命名。
const (
	opOAuthToken = "oauth_token"
	opUserInfo   = "user_info"
)

// endpoint 路径。
const (
	// oauthTokenPath OAuth v2 用户 access token 接口。
	//
	// 文档：https://developers.tiktok.com/doc/oauth-user-access-token-management
	// （2026-06-11 经本机代理直连拉取正文核对，本文件各 endpoint 引注同此方式，下同）
	//   - POST https://open.tiktokapis.com/v2/oauth/token/
	//   - Content-Type: application/x-www-form-urlencoded
	//   - 请求参数：client_key / client_secret / code / grant_type=authorization_code
	//     / redirect_uri（Login Kit 必填，须与请求 code 时一致）
	//   - 成功响应（平铺 JSON）：access_token / expires_in（86400，单位秒，24h 有效）
	//     / open_id / refresh_expires_in（31536000，365 天）/ refresh_token / scope
	//     / token_type（"Bearer"）
	//   - 错误响应（平铺 JSON）：error / error_description / log_id
	//
	// TikTok Minis（小游戏）流程：同一 endpoint、同一结构，仅省略 redirect_uri
	// 与 code_verifier（官方原文 "OAuth for TikTok Minis has the same structure as
	// User Access Token Management, with the exception of omitting redirect_uri and
	// code_verifier in the request body parameters for fetching an access token"）。
	// 文档：https://developers.tiktok.com/doc/minis-oauth（2026-06-11 拉取）
	//
	// 关键坑（历史实战教训）：
	//   - 这里换到的 access_token（act.* 前缀）是「用户 OAuth token」，与
	//     client_credentials 换的「应用 client token」是两种东西。后续用户级
	//     接口（user/info、IAP 下单等）必须用用户 token——种类用错平台直接报
	//     access_token_invalid（文档：https://developers.tiktok.com/doc/client-access-token-management ，
	//     2026-06-11 拉取，client token 仅用于应用级接口）。
	//   - code 是一次性凭据，消费过即作废——网络歧义失败后重试同一 code 会得到
	//     确定性 invalid_grant，故本实现不开 HTTP 层重试。
	oauthTokenPath = "/v2/oauth/token/"

	// userInfoPath 用户信息接口（补取 union_id 用）。
	//
	// 文档：https://developers.tiktok.com/doc/minis-user-data（2026-06-11 拉取；
	// 与 https://developers.tiktok.com/doc/tiktok-api-v2-get-user-info 同一接口）
	//   - GET https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id
	//   - 鉴权：Authorization: Bearer <用户 access token>（act.* 前缀；必须是
	//     用户 token，不是 client token——同上关键坑）
	//   - 响应：{"data":{"user":{...请求的 fields...}},"error":{"code":"ok",
	//     "message":"","log_id":"..."}}，error.code 非 "ok" 即业务失败
	//   - open_id / union_id 均需 user.info.basic scope（TikTok Minis 目前仅
	//     支持 user.info.basic 与 user.info.open_id 两个 scope）
	userInfoPath = "/v2/user/info/"
)

// userInfoFields user/info 请求的 fields 参数——只取登录身份映射需要的字段。
const userInfoFields = "open_id,union_id"

// oauthTokenResp 是 oauth/token 接口的应答（成功与错误字段平铺共存，
// 字段名以官方文档为准，见 oauthTokenPath 注释）。
type oauthTokenResp struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	OpenID           string `json:"open_id"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	TokenType        string `json:"token_type"`

	// 错误字段（OAuth 风格，平铺在顶层）。
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	LogID            string `json:"log_id"`
}

// userInfoResp 是 user/info 接口的应答（v2 data/error 包封风格，
// 字段名以官方文档为准，见 userInfoPath 注释）。
type userInfoResp struct {
	Data struct {
		User struct {
			OpenID  string `json:"open_id"`
			UnionID string `json:"union_id"`
		} `json:"user"`
	} `json:"data"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		LogID   string `json:"log_id"`
	} `json:"error"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端从 TikTok SDK 拿到的一次性授权 code（Login Kit 回调的
// code，或 TikTok Minis tt.login 返回的 code），本方法调 oauth/token 换取
// open_id / access_token 并映射为标准化身份：
//
//   - OpenID   ← open_id
//   - UnionID  ← user/info 的 union_id（仅 Config.FetchUserInfo 开启时补取）
//   - SessionKey 恒为空（TikTok 无 session_key 概念）
//   - Raw      ← access_token / refresh_token / expires_in / refresh_expires_in
//     / scope / token_type 透传
//
// 安全注意：Raw 中的 access_token / refresh_token 属凭据类数据（与合约对
// SessionKey 的纪律相同）——只允许留在服务端受控存储，严禁下发客户端或打日志。
func (t *TikTok) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, opOAuthToken, "", "credential（授权 code）为空")
	}

	form := url.Values{
		"client_key":    {t.cfg.ClientKey},
		"client_secret": {t.cfg.ClientSecret},
		"code":          {credential},
		"grant_type":    {"authorization_code"},
	}
	// Login Kit 流程必填且须与请求 code 时一致；Minis 流程省略（见 oauthTokenPath 注释）。
	if t.cfg.RedirectURI != "" {
		form.Set("redirect_uri", t.cfg.RedirectURI)
	}

	resp, err := t.hc.PostForm(ctx, httpx.JoinURL(t.cfg.BaseURL, oauthTokenPath), form, nil)
	if err != nil {
		// 传输层失败（网络错误/超时）——可重试；但注意 code 一次性，重试由上层决策。
		return nil, errs.Wrap(PlatformName, opOAuthToken, err).WithRetryable(true)
	}

	var body oauthTokenResp
	if err := resp.JSON(&body); err != nil {
		// 非 JSON 应答（HTML 错误页等）：5xx/429 视为暂时性。
		return nil, errs.Wrap(PlatformName, opOAuthToken, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 平台业务错误（error 字段平铺在顶层；官方成功应答不含 error 字段，
	// 防御性地把 "ok" 也视作无错）。
	if body.Error != "" && !strings.EqualFold(body.Error, "ok") {
		msg := body.ErrorDescription
		if body.LogID != "" {
			msg += " (log_id=" + body.LogID + ")"
		}
		return nil, errs.New(PlatformName, opOAuthToken, body.Error, msg).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opOAuthToken, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.AccessToken == "" || body.OpenID == "" {
		// 200 且无 error 却缺关键字段——按官方文档这不该发生，视为协议异常。
		return nil, errs.New(PlatformName, opOAuthToken, "",
			"应答缺少 access_token / open_id 字段: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}

	identity := &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   body.OpenID,
		Raw: map[string]string{
			"access_token":       body.AccessToken,
			"refresh_token":      body.RefreshToken,
			"expires_in":         strconv.FormatInt(body.ExpiresIn, 10),
			"refresh_expires_in": strconv.FormatInt(body.RefreshExpiresIn, 10),
			"scope":              body.Scope,
			"token_type":         body.TokenType,
		},
	}

	if t.cfg.FetchUserInfo {
		if err := t.fillUserInfo(ctx, body.AccessToken, identity); err != nil {
			return nil, err
		}
	}
	return identity, nil
}

// fillUserInfo 调 user/info 补取 union_id（endpoint 协议见 userInfoPath 注释）。
// 鉴权用 VerifyLogin 刚换到的「用户 access token」——不是 client token。
func (t *TikTok) fillUserInfo(ctx context.Context, userAccessToken string, identity *platform.PlatformIdentity) error {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+userAccessToken)
	query := url.Values{"fields": {userInfoFields}}

	resp, err := t.hc.Get(ctx, httpx.JoinURL(t.cfg.BaseURL, userInfoPath), query, header)
	if err != nil {
		return errs.Wrap(PlatformName, opUserInfo, err).WithRetryable(true)
	}
	var body userInfoResp
	if err := resp.JSON(&body); err != nil {
		return errs.Wrap(PlatformName, opUserInfo, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// v2 包封：error.code == "ok" 表示成功。
	if body.Error.Code != "" && !strings.EqualFold(body.Error.Code, "ok") {
		msg := body.Error.Message
		if body.Error.LogID != "" {
			msg += " (log_id=" + body.Error.LogID + ")"
		}
		return errs.New(PlatformName, opUserInfo, body.Error.Code, msg).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return errs.New(PlatformName, opUserInfo, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 防串号：user/info 返回的 open_id 必须与 token 应答一致（同一用户 token 查
	// 自己的信息，不一致即协议异常或实现 bug，宁可失败不可错绑身份）。
	if u := body.Data.User.OpenID; u != "" && u != identity.OpenID {
		return errs.New(PlatformName, opUserInfo, "",
			"user/info 返回的 open_id 与 oauth/token 不一致（疑似串号）: "+u+" != "+identity.OpenID)
	}
	identity.UnionID = body.Data.User.UnionID
	return nil
}

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 其余 4xx 是确定性失败（参数/凭据错误），重试无意义。
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// truncate 截断字符串到 n 字节（错误信息里附应答片段用，防日志爆量）。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}
