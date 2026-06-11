//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：LoginProvider——id_token 本地验签 / access_token 解析 / code 换 token 三种凭据形态
//2026/6/11
//***************************************************

package huawei

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const (
	opGetTokenInfo = "get_token_info"
	opOAuthToken   = "oauth_token"
)

// getTokenInfoResp 是解析凭证 Access Token 接口的成功应答。
// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/account-gettokeninfo-0000001050050585
// （2026-06-11 拉取）：client_id / expire_in（秒，有效期 60 分钟）/ union_id /
// open_id（AT 为用户级且入参 open_id=OPENID 时才返回）/ scope（用户级 AT 才返回）。
type getTokenInfoResp struct {
	ClientID string `json:"client_id"`
	ExpireIn int64  `json:"expire_in"`
	UnionID  string `json:"union_id"`
	OpenID   string `json:"open_id"`
	Scope    string `json:"scope"`
}

// oauthTokenResp 是 oauth2/v3/token 的应答（成功与 400 错误字段并列声明，
// 字段名以官方文档为准，见 huawei.go oauthTokenPath 注释）。
type oauthTokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`

	// 失败应答（HTTP 400）字段：主/子错误码为 int（官方示例：
	// {"sub_error":12304,"error_description":"invalid client_secret","error":1101}）。
	Error            int    `json:"error"`
	SubError         int    `json:"sub_error"`
	ErrorDescription string `json:"error_description"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 形态由 Config.CredentialType 决定（默认 id_token）：
//
//   - CredentialIDToken：credential = Account Kit 的 ID Token（JWT）。本地 JWKS
//     验签（官方明确商用环境必须本地验证）。身份映射：UnionID ← sub（官方文档
//     明确"sub 即用户的 UnionId"）；OpenID 留空——华为 ID Token 的声明表中没有
//     open_id 字段，绝不杜撰映射。业务需要 open_id 时请改用 access_token 或
//     code 凭据形态。Raw 透传全量声明（display_name / email / picture 等）。
//   - CredentialAccessToken：credential = 用户级 Access Token。调 getTokenInfo
//     解析：OpenID ← open_id、UnionID ← union_id，Raw 透传 scope / expire_in /
//     client_id。
//   - CredentialAuthCode：credential = Authorization Code（5 分钟有效、一次性）。
//     先经 oauth2/v3/token（grant_type=authorization_code）换 access_token /
//     refresh_token / id_token，再调 getTokenInfo 取 open_id / union_id；Raw
//     透传 access_token / refresh_token / id_token / expires_in / scope / token_type。
//
// SessionKey 恒为空（华为无 session_key 概念）。
//
// 安全注意：Raw 中的 access_token / refresh_token / id_token 属凭据类数据（与
// 合约对 SessionKey 的纪律相同）——只允许留在服务端受控存储，严禁下发客户端或
// 打日志。
func (h *Huawei) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, "verify_login", "",
			"credential 为空（凭据形态 "+string(h.cfg.CredentialType)+"）")
	}
	switch h.cfg.CredentialType {
	case CredentialIDToken:
		return h.loginByIDToken(ctx, credential)
	case CredentialAccessToken:
		return h.loginByAccessToken(ctx, credential)
	case CredentialAuthCode:
		return h.loginByAuthCode(ctx, credential)
	default:
		// New 已校验过枚举，此处理论不可达——防御性兜底。
		return nil, errs.New(PlatformName, "verify_login", "",
			"未知凭据形态 "+string(h.cfg.CredentialType))
	}
}

// loginByIDToken ID Token 本地验签路径（验签与声明校验见 jwks.go verifyIDToken）。
func (h *Huawei) loginByIDToken(ctx context.Context, idToken string) (*platform.PlatformIdentity, error) {
	claims, all, err := h.verifyIDToken(ctx, idToken)
	if err != nil {
		return nil, err
	}
	raw := make(map[string]string, len(all))
	for k, v := range all {
		raw[k] = stringifyClaim(v)
	}
	return &platform.PlatformIdentity{
		Platform: PlatformName,
		// OpenID 留空：华为 ID Token 声明表（官方文档，见 idTokenClaims 注释）中
		// 没有 open_id 字段——sub 是 UnionId，不能冒充 OpenID。
		OpenID:  "",
		UnionID: claims.Sub,
		Raw:     raw,
	}, nil
}

// loginByAccessToken 用户级 Access Token 解析路径。
// endpoint 协议见 huawei.go getTokenInfoPath 注释（官方文档 URL + 拉取日期）。
func (h *Huawei) loginByAccessToken(ctx context.Context, accessToken string) (*platform.PlatformIdentity, error) {
	info, err := h.getTokenInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   info.OpenID,
		UnionID:  info.UnionID,
		Raw: map[string]string{
			"client_id": info.ClientID,
			"scope":     info.Scope,
			"expire_in": strconv.FormatInt(info.ExpireIn, 10),
		},
	}, nil
}

// loginByAuthCode Authorization Code 路径：换 token → 解析 open_id / union_id。
func (h *Huawei) loginByAuthCode(ctx context.Context, code string) (*platform.PlatformIdentity, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {h.cfg.ClientID},
		"client_secret": {h.cfg.ClientSecret},
		"code":          {code},
	}
	// 官方：当 grant_type 为 authorization_code 时传入获取 code 时配置的回调地址；
	// 获取 code 时没带 redirect_uri 的场景留空（见 Config.RedirectURI 注释）。
	if h.cfg.RedirectURI != "" {
		form.Set("redirect_uri", h.cfg.RedirectURI)
	}
	tok, err := h.postOAuthToken(ctx, form)
	if err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, errs.New(PlatformName, opOAuthToken, "", "应答缺少 access_token 字段")
	}

	info, err := h.getTokenInfo(ctx, tok.AccessToken)
	if err != nil {
		return nil, err
	}
	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   info.OpenID,
		UnionID:  info.UnionID,
		Raw: map[string]string{
			"access_token":  tok.AccessToken,
			"refresh_token": tok.RefreshToken,
			"id_token":      tok.IDToken,
			"expires_in":    strconv.FormatInt(tok.ExpiresIn, 10),
			"scope":         tok.Scope,
			"token_type":    tok.TokenType,
		},
	}, nil
}

// getTokenInfo 调解析凭证 Access Token 接口（endpoint 协议与错误机制见
// huawei.go getTokenInfoPath 注释）。
func (h *Huawei) getTokenInfo(ctx context.Context, accessToken string) (*getTokenInfoResp, error) {
	form := url.Values{
		// access_token 官方要求 UrlEncode 后传入——url.Values.Encode 已覆盖。
		"access_token": {accessToken},
		// open_id 固定值 "OPENID"：传入才会在应答返回 open_id（官方文档字段表）。
		"open_id": {"OPENID"},
	}
	resp, err := h.hc.PostForm(ctx, httpx.JoinURL(h.cfg.OAuthAPIBaseURL, getTokenInfoPath), form, nil)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opGetTokenInfo, err).WithRetryable(true)
	}
	// 平台层错误经响应头 NSP_STATUS 标识（非 0 即错误）。
	// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/open-platform-error-0000001053869182
	// （2026-06-11 拉取）：2=服务临时不可用、6=token 过期、7/8=限频——2/7/8 可重试。
	if nsp := resp.Header.Get("NSP_STATUS"); nsp != "" && nsp != "0" {
		return nil, errs.New(PlatformName, opGetTokenInfo, "NSP_"+nsp,
			"开放平台错误 NSP_STATUS="+nsp+": "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(nsp == "2" || nsp == "7" || nsp == "8")
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opGetTokenInfo, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	var info getTokenInfoResp
	if err := resp.JSON(&info); err != nil {
		return nil, errs.Wrap(PlatformName, opGetTokenInfo, err).WithHTTPStatus(resp.StatusCode)
	}
	// 防串号：应答 client_id 是签发该 AT 的应用 Client ID，与本应用不一致说明
	// 拿了别家应用的 token——宁可失败不可错绑身份。
	if info.ClientID != "" && info.ClientID != h.cfg.ClientID {
		return nil, errs.New(PlatformName, opGetTokenInfo, "",
			"client_id 不匹配（疑似其他应用的 Access Token）: "+truncate(info.ClientID, 64))
	}
	// 官方：open_id 当且仅当 AT 为用户级且入参 open_id=OPENID 时返回。入参已传，
	// 仍缺失即说明这是应用级 AT 或协议异常——登录凭据必须是用户级。
	if info.OpenID == "" {
		return nil, errs.New(PlatformName, opGetTokenInfo, "",
			"应答缺少 open_id（Access Token 可能不是用户级凭据）: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}
	return &info, nil
}

// postOAuthToken 调 oauth2/v3/token（endpoint 协议见 huawei.go oauthTokenPath
// 注释），统一处理 400 错误应答（error/sub_error/error_description）。
func (h *Huawei) postOAuthToken(ctx context.Context, form url.Values) (*oauthTokenResp, error) {
	resp, err := h.hc.PostForm(ctx, httpx.JoinURL(h.cfg.OAuthBaseURL, oauthTokenPath), form, nil)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opOAuthToken, err).WithRetryable(true)
	}
	var body oauthTokenResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opOAuthToken, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 失败应答：HTTP 400 + {error, sub_error, error_description}。Code 透传
	// "主错误码.子错误码"（如 1101.20156=code 已被消费），便于上层分支判断。
	if body.Error != 0 {
		code := strconv.Itoa(body.Error)
		if body.SubError != 0 {
			code += "." + strconv.Itoa(body.SubError)
		}
		return nil, errs.New(PlatformName, opOAuthToken, code, body.ErrorDescription).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opOAuthToken, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	return &body, nil
}

// stringifyClaim 把 JWT 声明值转为字符串（Raw 透传用）：字符串原样；数字按
// JSON 原义（整数不带小数点）；布尔 true/false；复合类型回退 JSON 文本。
func stringifyClaim(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
