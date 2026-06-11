//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description facebook：LoginProvider——Graph API debug_token 校验用户 access token + 取 user_id（+ 可选 /me 补昵称）
//2026/6/11
//***************************************************

package facebook

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op），按平台 API 名命名。
const (
	opDebugToken = "debug_token"
	opMe         = "me"
)

// debug_token 接口。
//
// 文档：https://developers.facebook.com/docs/graph-api/reference/debug_token/
// （2026-06-11 拉取；任务原给的
// /docs/facebook-login/guides/access-tokens/debugging 路径已 404，文档站改版后
// 该 endpoint 的权威页即此 reference）：
//   - GET /v25.0/debug_token?input_token={input-token}   Host: graph.facebook.com
//   - input_token：被校验的 access token（必填）；
//   - 鉴权：须用「app access token」或该应用开发者的用户 token——本实现用
//     app access token；
//   - 应答（data 包封）：app_id(string) / application(string) /
//     error{code(int), message(string), subcode(int)} / expires_at(unixtime) /
//     data_access_expires_at(unixtime) / is_valid(bool) / issued_at(unixtime) /
//     profile_id(string) / scopes(string[]) / user_id(string)。
//
// app access token 的形式
// 文档：https://developers.facebook.com/documentation/facebook-login/guides/access-tokens
// （2026-06-11 拉取，自 /docs/facebook-login/guides/access-tokens 301 而来）：
// 官方明确可以直接以 "{your-app_id}|{your-app_secret}" 作为 access_token 参数，
// 等价于 client_credentials 换出的 app token，且只允许在服务端使用。
//
// appsecret_proof
// 文档：https://developers.facebook.com/docs/graph-api/guides/secure-requests
// （2026-06-11 拉取，自 /docs/graph-api/securing-requests 301 而来）：
// appsecret_proof = HMAC-SHA256(key=app_secret, data=access_token) 的十六进制，
// 官方建议服务端每个调用都附带；App Dashboard 开启 Require App Secret 后强制。
const debugTokenPathFmt = "/%s/debug_token"

// /me 接口（FetchUserInfo 补取昵称用）。
//
// 文档：
//   - User 节点字段：https://developers.facebook.com/docs/graph-api/reference/v19.0/user
//     （2026-06-11 拉取，文档站当前按 v25.0 呈现；public_profile 权限可读
//     id / name 等字段；id 为 App-Scoped User ID，numeric string）；
//   - /me 相对路径的官方用例见
//     https://developers.facebook.com/docs/graph-api/guides/secure-requests
//     （2026-06-11 拉取，batch 示例 relative_url "me"）。
const mePathFmt = "/%s/me"

// graphError 是 Graph API 标准错误包封里的 error 对象。
// 文档：https://developers.facebook.com/docs/graph-api/guides/error-handling
// （2026-06-11 拉取）：
//
//	{"error": {"message": "...", "type": "OAuthException", "code": 190,
//	           "error_subcode": 460, "fbtrace_id": "EJplcsCHuLu"}}
type graphError struct {
	Message   string `json:"message"`
	Type      string `json:"type"`
	Code      int    `json:"code"`
	Subcode   int    `json:"error_subcode"`
	FBTraceID string `json:"fbtrace_id"`
}

// errsFrom 把 Graph 标准错误映射为 *errs.Error。
// 可重试码以官方错误码表为准（文档同 graphError，2026-06-11 拉取）：
// 1（API Unknown，可能是临时故障）/ 2（API Service，临时故障）/
// 4（API Too Many Calls，限频）/ 17（API User Too Many Calls，限频）/
// 341（Application limit reached，限频或临时故障）→ 等待后重试；
// 其余（如 190 token 失效、10 权限不足）为确定性失败。
func (e *graphError) errsFrom(op string, httpStatus int) *errs.Error {
	msg := e.Message
	if e.Type != "" {
		msg = e.Type + ": " + msg
	}
	if e.Subcode != 0 {
		msg += " (subcode=" + strconv.Itoa(e.Subcode) + ")"
	}
	if e.FBTraceID != "" {
		msg += " (fbtrace_id=" + e.FBTraceID + ")"
	}
	retryable := false
	switch e.Code {
	case 1, 2, 4, 17, 341:
		retryable = true
	}
	return errs.New(PlatformName, op, strconv.Itoa(e.Code), msg).
		WithHTTPStatus(httpStatus).
		WithRetryable(retryable)
}

// debugTokenResp 是 debug_token 接口的应答（字段名与类型以官方 reference 为准，
// 见 debugTokenPathFmt 注释）。校验失败时有两种形态：
//   - 顶层 error：Graph 标准错误包封（如鉴权用的 app token 本身有问题）；
//   - data.error：input_token 自身的问题（token 过期/无效等），同时 is_valid=false。
type debugTokenResp struct {
	Data struct {
		AppID       string `json:"app_id"`
		Application string `json:"application"`
		Error       *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Subcode int    `json:"subcode"`
		} `json:"error"`
		ExpiresAt           int64    `json:"expires_at"`
		DataAccessExpiresAt int64    `json:"data_access_expires_at"`
		IsValid             bool     `json:"is_valid"`
		IssuedAt            int64    `json:"issued_at"`
		ProfileID           string   `json:"profile_id"`
		Scopes              []string `json:"scopes"`
		UserID              string   `json:"user_id"`
	} `json:"data"`
	Error *graphError `json:"error"`
}

// meResp 是 /me?fields=id,name 的应答（字段见 mePathFmt 注释的 User 节点文档）。
type meResp struct {
	ID    string      `json:"id"`
	Name  string      `json:"name"`
	Error *graphError `json:"error"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端从 Facebook SDK（FB.login / Limited Login 之外的标准登录）
// 拿到的「用户 access token」。本方法调 Graph API /debug_token 校验其有效性与
// 应用归属，并映射为标准化身份：
//
//   - OpenID   ← data.user_id（App-Scoped User ID，对每个应用唯一）
//   - UnionID  恒为空（Facebook 无跨应用统一 id 概念；Business 场景的
//     token_for_business 不在本实现范围）
//   - SessionKey 恒为空（Facebook 无 session_key 概念）
//   - Raw      ← application / expires_at / data_access_expires_at / issued_at /
//     scopes（逗号拼接）/ profile_id（非空时）/ name（FetchUserInfo 开启时）
//
// 防串号硬校验：data.app_id 必须等于 Config.AppID——别人应用签发的 token 在
// 这里直接拒绝；is_valid 必须为 true。
//
// 安全注意：credential（用户 access token）属凭据类数据——只允许留在服务端
// 受控存储，严禁回写客户端日志或打印。
func (f *Facebook) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, opDebugToken, "", "credential（用户 access token）为空")
	}

	// app access token："app_id|app_secret" 形式（官方支持，仅限服务端，
	// 见 debugTokenPathFmt 注释的文档引用）。
	appToken := f.cfg.AppID + "|" + f.cfg.AppSecret
	query := url.Values{
		"input_token":  {credential},
		"access_token": {appToken},
		// appsecret_proof = HMAC-SHA256(key=app_secret, data=本次调用所用的
		// access_token) 的十六进制（文档见 debugTokenPathFmt 注释）。
		"appsecret_proof": {sign.HMACSHA256Hex([]byte(f.cfg.AppSecret), []byte(appToken))},
	}

	resp, err := f.hc.Get(ctx, f.graphURL(debugTokenPathFmt), query, nil)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opDebugToken, err).WithRetryable(true)
	}
	var body debugTokenResp
	if err := resp.JSON(&body); err != nil {
		// 非 JSON 应答（HTML 错误页等）：5xx/429 视为暂时性。
		return nil, errs.Wrap(PlatformName, opDebugToken, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 顶层 Graph 标准错误（鉴权 app token 问题、限频等）。
	if body.Error != nil {
		return nil, body.Error.errsFrom(opDebugToken, resp.StatusCode)
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opDebugToken, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// input_token 自身的问题（data.error 与 is_valid=false 同时出现）。
	if body.Data.Error != nil {
		msg := body.Data.Error.Message
		if body.Data.Error.Subcode != 0 {
			msg += " (subcode=" + strconv.Itoa(body.Data.Error.Subcode) + ")"
		}
		return nil, errs.New(PlatformName, opDebugToken, strconv.Itoa(body.Data.Error.Code), msg).
			WithHTTPStatus(resp.StatusCode)
	}
	if !body.Data.IsValid {
		return nil, errs.New(PlatformName, opDebugToken, "", "access token 无效（is_valid=false）").
			WithHTTPStatus(resp.StatusCode)
	}
	// 防串号：token 必须是签给本应用的。
	if body.Data.AppID != f.cfg.AppID {
		return nil, errs.New(PlatformName, opDebugToken, "",
			"token 不属于本应用（app_id="+body.Data.AppID+" != "+f.cfg.AppID+"），疑似串号或配置错误")
	}
	if body.Data.UserID == "" {
		// is_valid 且无 error 却缺 user_id——可能是 app token / page token 被
		// 当作用户凭据传入，拒绝。
		return nil, errs.New(PlatformName, opDebugToken, "",
			"应答缺少 user_id（传入的可能不是用户 access token）: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}

	identity := &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   body.Data.UserID,
		Raw: map[string]string{
			"application":            body.Data.Application,
			"expires_at":             strconv.FormatInt(body.Data.ExpiresAt, 10),
			"data_access_expires_at": strconv.FormatInt(body.Data.DataAccessExpiresAt, 10),
			"issued_at":              strconv.FormatInt(body.Data.IssuedAt, 10),
			"scopes":                 strings.Join(body.Data.Scopes, ","),
		},
	}
	if body.Data.ProfileID != "" {
		identity.Raw["profile_id"] = body.Data.ProfileID
	}

	if f.cfg.FetchUserInfo {
		if err := f.fillUserInfo(ctx, credential, identity); err != nil {
			return nil, err
		}
	}
	return identity, nil
}

// fillUserInfo 调 /me?fields=id,name 补取昵称（endpoint 协议见 mePathFmt 注释）。
// 鉴权用「用户 access token」本身 + 对应的 appsecret_proof。
func (f *Facebook) fillUserInfo(ctx context.Context, userToken string, identity *platform.PlatformIdentity) error {
	query := url.Values{
		"fields":          {"id,name"},
		"access_token":    {userToken},
		"appsecret_proof": {sign.HMACSHA256Hex([]byte(f.cfg.AppSecret), []byte(userToken))},
	}
	resp, err := f.hc.Get(ctx, f.graphURL(mePathFmt), query, nil)
	if err != nil {
		return errs.Wrap(PlatformName, opMe, err).WithRetryable(true)
	}
	var body meResp
	if err := resp.JSON(&body); err != nil {
		return errs.Wrap(PlatformName, opMe, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.Error != nil {
		return body.Error.errsFrom(opMe, resp.StatusCode)
	}
	if !resp.OK() {
		return errs.New(PlatformName, opMe, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 防串号：/me 返回的 id 必须与 debug_token 的 user_id 一致（同一用户 token
	// 查自己的信息，不一致即协议异常或实现 bug，宁可失败不可错绑身份）。
	if body.ID != "" && body.ID != identity.OpenID {
		return errs.New(PlatformName, opMe, "",
			"/me 返回的 id 与 debug_token 的 user_id 不一致（疑似串号）: "+body.ID+" != "+identity.OpenID)
	}
	identity.Raw["name"] = body.Name
	return nil
}

// graphURL 拼接 base + 版本化路径（pathFmt 形如 "/%s/debug_token"）。
func (f *Facebook) graphURL(pathFmt string) string {
	path := strings.Replace(pathFmt, "%s", f.cfg.GraphVersion, 1)
	return httpx.JoinURL(f.cfg.BaseURL, path)
}

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 其余 4xx 是确定性失败（参数/凭据错误），重试无意义。
func retryableStatus(status int) bool {
	return status == 429 || status >= 500
}

// truncate 截断字符串到 n 字节（错误信息里附应答片段用，防日志爆量）。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(截断)"
}
