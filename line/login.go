//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description line：LoginProvider——LINE Login ID token 服务端校验（官方 verify 接口），取 sub→OpenID
//2026/6/11
//***************************************************

package line

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
const opVerifyIDToken = "verify_id_token"

// verifyIDTokenPath ID token 服务端校验接口。
//
// 文档：https://developers.line.biz/en/reference/line-login/#verify-id-token
// （2026-06-11 拉取，正文已抓取核对）：
//   - POST https://api.line.me/oauth2/v2.1/verify
//   - Content-Type: application/x-www-form-urlencoded（Required）
//   - 请求体：id_token（String, Required）/ client_id（String, Required,
//     "Expected channel ID"）/ nonce（String, Optional, 授权请求未带 nonce 则省略）
//     / user_id（String, Optional, 期望的用户 ID）
//   - 成功响应（即 ID token payload）：iss（String, 生成方 URL）/ sub（String,
//     用户 ID）/ aud（String, Channel ID）/ exp（Number, UNIX 秒）/ iat（Number,
//     UNIX 秒）/ auth_time（Number, UNIX 秒, 授权请求带 max_age 才有）/ nonce
//     （String, 可选）/ amr（字符串数组：pwd / lineautologin / lineqr / linesso /
//     mfa）/ name / picture（profile scope 才有）/ email（email scope 才有）
//   - 校验失败响应：JSON 对象 {"error","error_description"}，error_description
//     的官方取值：Invalid IdToken. / Invalid IdToken Issuer. / IdToken expired. /
//     Invalid IdToken Audience. / Invalid IdToken Nonce. /
//     Invalid IdToken Subject Identifier.
//     （结构已于 2026-06-11 对真实 endpoint 发非法 id_token 实测核对：
//     HTTP 400 + {"error":"invalid_request","error_description":"JWS format error"}）
//
// 配套指南：https://developers.line.biz/en/docs/line-login/verify-id-token/
// （2026-06-11 拉取）——官方明确推荐用本接口完成服务端校验（"use the Verify
// ID token endpoint ... you can validate the ID token and get the corresponding
// user's profile information ... by simply sending the ID token ... and LINE
// Login channel ID"），签名 / iss / exp / aud / nonce 校验全部由平台侧完成。
const verifyIDTokenPath = "/oauth2/v2.1/verify"

// expectedIssuer ID token 的合法签发方。
// 官方错误描述原文："The ID token was generated on a site other than
// "https://access.line.me"."（同 verifyIDTokenPath 引用的 reference 文档，
// 2026-06-11 拉取）——成功应答的 iss 必为该值，本实现做防御性双查。
const expectedIssuer = "https://access.line.me"

// loginCredential 是 VerifyLogin credential 参数的 JSON 包封形式（本实现的
// 入参约定，不是 LINE 协议）：业务在授权请求里带了 nonce、或想顺带核对
// user_id 时，把 credential 组织成 JSON 传入；否则直接传 ID token 原串。
type loginCredential struct {
	// IDToken LINE ID token（必填）。
	IDToken string `json:"id_token"`
	// Nonce 授权请求时指定的 nonce（可选）——传入后由平台核对
	// "Invalid IdToken Nonce."，是官方推荐的防重放手段。
	Nonce string `json:"nonce"`
	// UserID 期望的 LINE 用户 ID（可选）——传入后由平台核对
	// "Invalid IdToken Subject Identifier."。
	UserID string `json:"user_id"`
}

// verifyIDTokenResp 是 verify 接口的应答（成功 = ID token payload；失败 =
// {"error","error_description"}；字段名以官方文档为准，见 verifyIDTokenPath 注释）。
type verifyIDTokenResp struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce"`
	Amr      []string `json:"amr"`
	Name     string   `json:"name"`
	Picture  string   `json:"picture"`
	Email    string   `json:"email"`

	// 错误字段（校验失败时返回）。
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端从 LINE SDK / LIFF（liff.getIDToken()）拿到的 ID token；
// 也支持 JSON 包封形式 {"id_token":"...","nonce":"...","user_id":"..."}（本实现
// 的入参约定，见 loginCredential），用于把可选的 nonce / user_id 一并交给平台核对。
//
// 本方法把 ID token 提交到 LINE 官方 verify 接口（协议见 verifyIDTokenPath
// 注释）完成服务端校验，并映射为标准化身份：
//
//   - OpenID     ← sub（ID token 的用户 ID）
//   - UnionID    恒为空（LINE 无跨应用统一 id 概念）
//   - SessionKey 恒为空（LINE 无 session_key 概念）
//   - Raw        ← iss / aud / exp / iat / auth_time / nonce / amr / name /
//     picture / email 透传（可选字段仅在平台返回时存在）
//
// 安全注意：Raw 中的 email / name / picture 属用户隐私数据，遵守业务侧合规
// 要求存储与使用，严禁无关下发或打日志。
func (l *Line) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	cred, err := parseLoginCredential(credential)
	if err != nil {
		return nil, err
	}

	// 请求体字段以官方文档为准（见 verifyIDTokenPath 注释）：id_token /
	// client_id 必填；nonce / user_id 仅在业务提供时携带（官方原文：授权请求
	// 未指定 nonce 则省略该参数）。
	form := url.Values{
		"id_token":  {cred.IDToken},
		"client_id": {l.cfg.ChannelID},
	}
	if cred.Nonce != "" {
		form.Set("nonce", cred.Nonce)
	}
	if cred.UserID != "" {
		form.Set("user_id", cred.UserID)
	}

	resp, err := l.hc.PostForm(ctx, httpx.JoinURL(l.cfg.BaseURL, verifyIDTokenPath), form, nil)
	if err != nil {
		// 传输层失败（网络错误/超时）——verify 是只读校验，可安全重试。
		return nil, errs.Wrap(PlatformName, opVerifyIDToken, err).WithRetryable(true)
	}

	var body verifyIDTokenResp
	if err := resp.JSON(&body); err != nil {
		// 非 JSON 应答（HTML 错误页等）：5xx/429 视为暂时性。
		return nil, errs.Wrap(PlatformName, opVerifyIDToken, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 平台校验失败（{"error","error_description"}，实测 HTTP 400）。
	if body.Error != "" {
		return nil, errs.New(PlatformName, opVerifyIDToken, body.Error, body.ErrorDescription).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opVerifyIDToken, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.Sub == "" {
		// 200 且无 error 却缺关键字段——按官方文档这不该发生，视为协议异常。
		return nil, errs.New(PlatformName, opVerifyIDToken, "",
			"应答缺少 sub 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}
	// 防御性双查（平台 verify 已各自校验过 iss / aud / exp，这里宁严勿松，
	// 防 BaseURL 被错误注入等实现层事故导致身份误信）：
	//   - iss 必须是官方签发方；
	//   - aud 必须等于本配置的 Channel ID；
	//   - exp 必须未过期（官方单位 UNIX 秒）。
	if body.Iss != expectedIssuer {
		return nil, errs.New(PlatformName, opVerifyIDToken, "",
			"应答 iss 非法（期望 "+expectedIssuer+"）: "+truncate(body.Iss, 128))
	}
	if body.Aud != l.cfg.ChannelID {
		return nil, errs.New(PlatformName, opVerifyIDToken, "",
			"应答 aud 与配置的 ChannelID 不一致: "+truncate(body.Aud, 64)+" != "+l.cfg.ChannelID)
	}
	if body.Exp <= l.now().Unix() {
		return nil, errs.New(PlatformName, opVerifyIDToken, "",
			"ID token 已过期（exp="+strconv.FormatInt(body.Exp, 10)+"）")
	}

	raw := map[string]string{
		"iss": body.Iss,
		"aud": body.Aud,
		"exp": strconv.FormatInt(body.Exp, 10),
		"iat": strconv.FormatInt(body.Iat, 10),
	}
	if body.AuthTime > 0 {
		raw["auth_time"] = strconv.FormatInt(body.AuthTime, 10)
	}
	if body.Nonce != "" {
		raw["nonce"] = body.Nonce
	}
	if len(body.Amr) > 0 {
		raw["amr"] = strings.Join(body.Amr, ",")
	}
	if body.Name != "" {
		raw["name"] = body.Name
	}
	if body.Picture != "" {
		raw["picture"] = body.Picture
	}
	if body.Email != "" {
		raw["email"] = body.Email
	}

	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   body.Sub,
		Raw:      raw,
	}, nil
}

// parseLoginCredential 解析 credential 入参：以 "{" 开头按 JSON 包封解析
// （见 loginCredential），否则整串视为 ID token。
func parseLoginCredential(credential string) (*loginCredential, error) {
	trimmed := strings.TrimSpace(credential)
	if trimmed == "" {
		return nil, errs.New(PlatformName, opVerifyIDToken, "", "credential（ID token）为空")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return &loginCredential{IDToken: trimmed}, nil
	}
	var cred loginCredential
	if err := httpx.DecodeJSON([]byte(trimmed), &cred); err != nil {
		return nil, errs.Wrap(PlatformName, opVerifyIDToken, err)
	}
	if cred.IDToken == "" {
		return nil, errs.New(PlatformName, opVerifyIDToken, "", "credential JSON 包封缺少 id_token 字段")
	}
	return &cred, nil
}

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 其余 4xx 是确定性失败（token 非法/过期、参数错误），重试无意义。
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}
