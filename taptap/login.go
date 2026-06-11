//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description taptap：LoginProvider——客户端 Access Token（kid/mac_key）经 MAC 签名调账户接口验证并换 openid/unionid
//2026/6/11
//***************************************************

package taptap

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
const (
	opCredential = "parse_credential"
	opBasicInfo  = "account_basic_info"
	opProfile    = "account_profile"
)

// endpoint 路径。
//
// 文档：https://developer.taptap.cn/docs/sdk/taptap-login/taptap-oauth/
// （2026-06-11 拉取，快照 .docs/taptap-oauth.html）：
//
//   - GET https://open.tapapis.cn/account/basic-info/v1?client_id=xxx
//     Authorization: mac token；需 basic_info scope；
//     响应字段：openid / unionid
//   - GET https://open.tapapis.cn/account/profile/v1?client_id=xxx
//     Authorization: mac token；需 public_profile scope；
//     响应字段：name / avatar / openid / unionid
//
// scope 匹配规则（同文档）：移动端仅授 basic_info → 服务端只能调基础信息接口；
// 授 public_profile → 两个接口均可调，否则平台返回 insufficient_scope。
//
// openid：TapTap 用户 + Client ID = openid（同一用户在不同游戏中 openid 不同）；
// unionid：TapTap 用户 + 开发者账号 = unionid（同一开发者的所有游戏中相同）。
const (
	basicInfoPath = "/account/basic-info/v1"
	profilePath   = "/account/profile/v1"
)

// accessToken 是 credential（客户端 SDK Access Token 的 JSON 序列化）的结构。
// 字段名以官方文档的 Access Token 字段定义为准（kid / token_type / mac_key /
// mac_algorithm / scopes，文档见 doc.go）。
type accessToken struct {
	// Kid Access Token 标识符，用于 Authorization 头中的 MAC id 字段。
	Kid string `json:"kid"`
	// MacKey 用于 HMAC-SHA1 签算的密钥（与控制台 Server Secret 是不同的值）。
	MacKey string `json:"mac_key"`
	// TokenType Token 类型，如 "mac"。
	TokenType string `json:"token_type"`
	// MacAlgorithm 签算算法，如 "hmac-sha-1"。
	MacAlgorithm string `json:"mac_algorithm"`
	// Scopes 授权范围，如 "basic_info" / "public_profile"（透传，不参与签算）。
	Scopes []string `json:"scopes"`
}

// accountPayload 是账户接口的业务字段（成功字段与错误统一格式共存；
// 字段名以官方文档为准，见 basicInfoPath / profilePath 注释与下方错误码表）。
type accountPayload struct {
	// 成功字段。
	OpenID  string `json:"openid"`
	UnionID string `json:"unionid"`
	// 详细信息接口（profile/v1）额外返回。
	Name   string `json:"name"`
	Avatar string `json:"avatar"`

	// 错误统一格式（文档「错误码」节）：
	//   code             int    预留字段，用于以后追踪问题
	//   error            string 错误码，代码逻辑判断时使用
	//   error_description string 错误描述信息
	Code             int    `json:"code"`
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// accountResp 是账户接口应答的防御性外层。
//
// NEEDS-DOC：官方 v4 文档（含 v3 与国际站同页）只给了字段表与错误统一格式，
// 均未给出完整 JSON 应答示例——无法确认线上应答是平铺还是
// {"data":{...},"success":bool,"now":int} 包封（TDS 时代真实线上行为是包封）。
// 本结构对两种形态都能解析：Data 非空时业务字段从 Data 取，否则取平铺字段。
// 真凭据端到端验证时务必复核实际形态（见 doc.go）。
type accountResp struct {
	Success *bool           `json:"success"`
	Now     int64           `json:"now"`
	Data    json.RawMessage `json:"data"`
	accountPayload
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端 SDK 登录后返回的 Access Token 对象的 JSON 序列化
// （至少含 kid / mac_key，约定见 doc.go），本方法按官方 MAC Token 协议
// （HMAC-SHA1，见 mac.go）签算 Authorization 头，调账户接口验证凭据有效性
// 并映射为标准化身份：
//
//   - OpenID   ← openid（TapTap 用户 + Client ID 维度唯一）
//   - UnionID  ← unionid（TapTap 用户 + 开发者账号维度唯一）
//   - SessionKey 恒为空（TapTap 无 session_key 概念）
//   - Raw      ← name / avatar（仅 Config.UseProfileAPI 开启且平台返回时）
//
// 安全注意：credential 中的 mac_key 属凭据类数据——只允许留在服务端内存，
// 严禁回写客户端以外的存储或打日志（与合约对 SessionKey 的纪律相同）。
func (t *TapTap) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	tok, err := parseAccessToken(credential)
	if err != nil {
		return nil, err
	}

	op, apiPath := opBasicInfo, basicInfoPath
	if t.cfg.UseProfileAPI {
		op, apiPath = opProfile, profilePath
	}

	// uri = 请求路径含 query string（官方签算步骤第 1 步），必须与实际请求的
	// URI 逐字符一致——签算与发请求共用同一个 uri 串，杜绝重编码差异。
	uri := apiPath + "?client_id=" + url.QueryEscape(t.cfg.ClientID)

	ts := strconv.FormatInt(t.now().Unix(), 10)
	nonce, err := t.nonce()
	if err != nil {
		return nil, errs.Wrap(PlatformName, op, err)
	}
	mac := macSign(buildSigningString(ts, nonce, http.MethodGet, uri, t.host, t.port), tok.MacKey)

	header := http.Header{}
	header.Set("Authorization", buildAuthorization(tok.Kid, ts, nonce, mac))

	resp, err := t.hc.Do(ctx, http.MethodGet, t.cfg.BaseURL+uri, nil, header)
	if err != nil {
		// 传输层失败（网络错误/超时）——GET 查询幂等，可安全重试。
		return nil, errs.Wrap(PlatformName, op, err).WithRetryable(true)
	}
	return t.decodeAccountResp(op, resp)
}

// parseAccessToken 解析并校验 credential（Access Token JSON）。
func parseAccessToken(credential string) (*accessToken, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, opCredential, "", "credential（Access Token JSON）为空")
	}
	var tok accessToken
	if err := json.Unmarshal([]byte(credential), &tok); err != nil {
		return nil, errs.New(PlatformName, opCredential, "",
			"credential 不是合法的 Access Token JSON（约定见包文档）").WithCause(err)
	}
	if tok.Kid == "" {
		return nil, errs.New(PlatformName, opCredential, "", "credential 缺少 kid 字段")
	}
	if tok.MacKey == "" {
		return nil, errs.New(PlatformName, opCredential, "", "credential 缺少 mac_key 字段")
	}
	// token_type / mac_algorithm 缺省按官方默认（"mac" / "hmac-sha-1"）处理；
	// 显式给出其它取值时直接报错——平台未来若升级算法，静默用 SHA1 错签只会
	// 得到难排查的 access_denied。
	if tok.TokenType != "" && !strings.EqualFold(tok.TokenType, "mac") {
		return nil, errs.New(PlatformName, opCredential, "",
			"不支持的 token_type: "+tok.TokenType+"（本实现仅支持官方文档定义的 mac 类型）")
	}
	if tok.MacAlgorithm != "" && !strings.EqualFold(tok.MacAlgorithm, "hmac-sha-1") {
		return nil, errs.New(PlatformName, opCredential, "",
			"不支持的 mac_algorithm: "+tok.MacAlgorithm+"（本实现仅支持官方文档定义的 hmac-sha-1）")
	}
	return &tok, nil
}

// decodeAccountResp 解析账户接口应答并映射为标准化身份。
func (t *TapTap) decodeAccountResp(op string, resp *httpx.Response) (*platform.PlatformIdentity, error) {
	var env accountResp
	if err := resp.JSON(&env); err != nil {
		// 非 JSON 应答（HTML 错误页等）：5xx/429 视为暂时性。
		return nil, errs.Wrap(PlatformName, op, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 包封形态时业务字段从 data 取，平铺形态直接用顶层字段（见 accountResp 注释）。
	payload := env.accountPayload
	if len(env.Data) > 0 && string(env.Data) != "null" {
		payload = accountPayload{}
		if err := httpx.DecodeJSON(env.Data, &payload); err != nil {
			return nil, errs.Wrap(PlatformName, op, err).WithHTTPStatus(resp.StatusCode)
		}
	}

	// 平台业务错误（错误统一格式的 error 字段）。
	if payload.ErrorCode != "" {
		return nil, errs.New(PlatformName, op, payload.ErrorCode, payload.ErrorDescription).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableAPICode(payload.ErrorCode) || retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, op, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 包封形态 success=false 却没带错误码——协议异常，宁可失败不可错认成功。
	if env.Success != nil && !*env.Success {
		return nil, errs.New(PlatformName, op, "",
			"应答 success=false 且无错误码: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}
	if payload.OpenID == "" {
		// 200 且无 error 却缺关键字段——按官方文档这不该发生，视为协议异常。
		return nil, errs.New(PlatformName, op, "",
			"应答缺少 openid 字段: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}

	identity := &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   payload.OpenID,
		UnionID:  payload.UnionID,
		Raw:      map[string]string{},
	}
	if payload.Name != "" {
		identity.Raw["name"] = payload.Name
	}
	if payload.Avatar != "" {
		identity.Raw["avatar"] = payload.Avatar
	}
	return identity, nil
}

// retryableAPICode 报告平台业务错误码是否属暂时性失败。
//
// 错误码表（文档「错误码」节，2026-06-11 拉取）：
//   - invalid_request    请求缺少必需参数/参数不支持/格式不正确（确定性）
//   - invalid_time       MAC ts 时间不合法，应请求服务器时间重新构造（确定性——
//     盲目原样重试无意义，需校时后重签，由上层处理）
//   - invalid_client     client_id 参数无效（确定性）
//   - access_denied      授权服务器拒绝请求，客户端应退出本地登录态引导重新
//     登录（确定性）
//   - forbidden          无权限，且“这个请求也不应该被重复提交”（确定性）
//   - not_found          资源未发现，“参数相同的情况下不应该重复请求”（确定性）
//   - server_error       服务器异常，“可稍等后重新尝试请求，但需有尝试上限，
//     建议最多 3 次”——唯一官方明示可重试的码
//   - insufficient_scope 移动端授权范围与服务端调用的接口不匹配（确定性）
func retryableAPICode(code string) bool {
	return code == "server_error"
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
