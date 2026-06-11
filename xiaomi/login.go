//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description xiaomi：LoginProvider——用户 session 验证接口（loginvalidate）
//2026/6/11
//***************************************************

package xiaomi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op），按平台 API 名命名。
const opLoginValidate = "loginvalidate"

// loginValidatePath 用户 session 验证接口。
//
// 文档：《小米游戏SDK3.0接入指南》5.3.3 用户session验证接口
// https://dev.mi.com/distribute/doc/details?pId=1616（2026-06-11 拉取）；
// https 地址以《小米游戏渠道服务器升级通知》为准
// https://dev.mi.com/distribute/doc/details?pId=1559（2026-06-11 拉取）：
//   - POST https://mis.migc.xiaomi.com/api/biz/service/loginvalidate
//   - Headers: Content-Type: application/x-www-form-urlencoded
//   - 请求参数：appId（游戏 ID）/ session（用户 sessionID）/ uid（用户 ID）
//     / signature（HMAC-SHA1 签名，算法见 xiaomi.go buildSignSource）
//   - 返回 JSON：errcode（200 验证正确）/ errMsg（可选）/ adult（可选，实名标识：
//     407 已实名且 ≥18 岁；408 已实名且 <18 岁；409 未实名）
//   - 错误码：1515 appId 错误；1516 uid 错误；1520 session 错误；
//     1525 signature 错误；4002 appid/uid/session 不匹配（常见为 session 过期）
//
// 官方强调（同文档 + 《最佳安全实践》pId=1543，2026-06-11 拉取）：
// 用户唯一标识是 uid 而非 session；session 只用于校验登录有效性，每次登录
// 都必须做 session 验证，不可把 uid/session 落在客户端本地复用。
const loginValidatePath = "/api/biz/service/loginvalidate"

// loginValidateResp 是 loginvalidate 接口的应答
// （字段名以官方文档为准，见 loginValidatePath 注释）。
type loginValidateResp struct {
	Errcode int    `json:"errcode"`
	ErrMsg  string `json:"errMsg"`
	Adult   int    `json:"adult"`
}

// loginValidateOK errcode 成功值（官方：200 验证正确）。
const loginValidateOK = 200

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端从小米游戏 SDK 登录回调拿到的 uid 与 session
// （OnLoginProcessListener 的 getUid() / getSessionId()，pId=1616 第 5.2 节），
// 二选一格式提交：
//
//   - 简易格式："<uid>:<session>"，如 "100010:1nlfxuAGmZk9IR2L"
//     （uid 是平台 long 型数字，不含冒号，首个冒号即分隔符）；
//   - JSON 格式：{"uid":"100010","session":"1nlfxuAGmZk9IR2L"}
//     （uid 可为 JSON 数字或字符串；大数 uid 用 json.Number 解析防精度丢失）。
//
// 校验通过映射为标准化身份：
//
//   - OpenID   ← uid（官方：用户唯一标识是 uid）
//   - UnionID  恒为空（小米无跨应用统一 id 概念）
//   - SessionKey 恒为空（session 是登录凭据本身，不是解密密钥，不回填）
//   - Raw      ← errcode / adult（实名标识，防沉迷接入用）
func (x *Xiaomi) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	uid, session, err := parseCredential(credential)
	if err != nil {
		return nil, errs.New(PlatformName, opLoginValidate, "", err.Error())
	}

	params := map[string]string{
		"appId":   x.cfg.AppID,
		"session": session,
		"uid":     uid,
	}
	form := url.Values{
		"appId":     {x.cfg.AppID},
		"session":   {session},
		"uid":       {uid},
		"signature": {x.signParams(params)},
	}

	resp, err := x.hc.PostForm(ctx, httpx.JoinURL(x.cfg.BaseURL, loginValidatePath), form, nil)
	if err != nil {
		// 传输层失败（网络错误/超时）——校验类接口幂等，可安全重试。
		return nil, errs.Wrap(PlatformName, opLoginValidate, err).WithRetryable(true)
	}

	var body loginValidateResp
	if err := resp.JSON(&body); err != nil {
		// 非 JSON 应答（HTML 错误页等）：5xx/429 视为暂时性。
		return nil, errs.Wrap(PlatformName, opLoginValidate, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.Errcode != loginValidateOK {
		// 平台业务错误（1515/1516/1520/1525/4002，确定性失败不重试）。
		return nil, errs.New(PlatformName, opLoginValidate, strconv.Itoa(body.Errcode), body.ErrMsg).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opLoginValidate, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   uid,
		Raw: map[string]string{
			"errcode": strconv.Itoa(body.Errcode),
			// adult：407 实名 ≥18 / 408 实名 <18 / 409 未实名；0 表示平台未返回该字段。
			"adult": strconv.Itoa(body.Adult),
		},
	}, nil
}

// parseCredential 解析登录凭据（格式约定见 VerifyLogin 注释）。
// uid 必须是十进制数字（官方 long 型），session 非空。
func parseCredential(credential string) (uid, session string, err error) {
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return "", "", errInvalidCredential("credential 为空")
	}
	if strings.HasPrefix(credential, "{") {
		// JSON 格式：用 json.Number 解析 uid，防大数 uid 经 float64 丢精度。
		var c struct {
			UID     json.Number `json:"uid"`
			Session string      `json:"session"`
		}
		dec := json.NewDecoder(strings.NewReader(credential))
		dec.UseNumber()
		if err := dec.Decode(&c); err != nil {
			return "", "", errInvalidCredential("JSON 解析失败: " + err.Error())
		}
		uid, session = c.UID.String(), c.Session
	} else {
		// 简易格式 "<uid>:<session>"：uid 是数字不含冒号，按首个冒号切分。
		var ok bool
		uid, session, ok = strings.Cut(credential, ":")
		if !ok {
			return "", "", errInvalidCredential(`格式非法，应为 "<uid>:<session>" 或 JSON {"uid":...,"session":...}`)
		}
	}
	if uid == "" || session == "" {
		return "", "", errInvalidCredential("uid / session 不能为空")
	}
	if _, perr := strconv.ParseUint(uid, 10, 64); perr != nil {
		return "", "", errInvalidCredential("uid 必须是十进制数字（平台 long 型用户 ID）: " + truncate(uid, 64))
	}
	return uid, session, nil
}

// errInvalidCredential 构造凭据格式错误（statictext error，便于消息拼装）。
type errInvalidCredential string

func (e errInvalidCredential) Error() string { return "credential " + string(e) }

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 其余 4xx 是确定性失败（参数/凭据错误），重试无意义。
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}
