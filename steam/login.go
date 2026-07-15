//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description steam：LoginProvider——AuthenticateUserTicket 会话票据校验换 SteamID
//2026/6/11
//***************************************************

package steam

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op），按平台 API 名命名。
const opAuthTicket = "authenticate_user_ticket"

// authTicketPath 会话票据校验接口。
//
// 文档：https://partner.steamgames.com/doc/webapi/ISteamUserAuth（2026-06-11 拉取）
//   - GET https://partner.steam-api.com/ISteamUserAuth/AuthenticateUserTicket/v1/
//   - 请求参数（query）：
//     key    Steamworks Web API publisher authentication key
//     appid  游戏 AppID（uint32）
//     ticket 客户端 GetAuthTicketForWebApi 返回的二进制票据转十六进制字符串
//     （“Convert the binary ticket data from GetAuthTicketForWebApi into a
//     hexadecimal string and pass that string in as this parameter.”）
//     identity 创建票据时传给 GetAuthTicketForWebApi 的标识串——传了则只有
//     携带同一 identity 创建的票据能通过校验
//   - 返回：票据有效时返回用户的 64-bit SteamID
//   - 安全：必须从安全服务器调用，key 绝不能进客户端；也可经
//     https://api.steampowered.com 用普通 Web API user key 调用（官方明确限频）
//
// 流程文档：https://partner.steamgames.com/doc/features/auth（2026-06-11 拉取）
// “Session Tickets and the Steamworks Web API”一节——客户端
// GetAuthTicketForWebApi → 等 GetTicketForWebApiResponse_t 回调 → 票据发给
// 安全服务器 → 服务器调本接口校验。
//
// 应答 JSON 包封：Steamworks Web API 默认返回 JSON、64 位数字以字符串返回
// （https://partner.steamgames.com/doc/webapi_overview/responses ，2026-06-11 拉取）。
// 本接口官方页未列出成功应答的字段级 schema（NEEDS-DOC，见 doc.go）——按同体系
// ISteamMicroTxn 官方正文确证的通用包封 {"response":{...}} 宽松解析，只硬依赖
// params.steamid 一个字段，其余字段全部透传 Raw。
const authTicketPath = "/ISteamUserAuth/AuthenticateUserTicket/v1/"

// authTicketResp 是 AuthenticateUserTicket 的应答包封。
// result 的层级官方未明示——response.result（ISteamMicroTxn 形态）与
// response.params.result（社区已知的本接口形态）两个位置都兼容。
type authTicketResp struct {
	Response struct {
		Result string                     `json:"result"`
		Params map[string]json.RawMessage `json:"params"`
		Error  *webAPIError               `json:"error"`
	} `json:"response"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端从 Steamworks SDK 拿到的会话票据 hex 字符串
// （ISteamUser::GetAuthTicketForWebApi 返回的二进制票据按官方要求转十六进制，
// 见 authTicketPath 注释），本方法调 AuthenticateUserTicket 校验并映射为标准化身份：
//
//   - OpenID     ← 应答 params.steamid（用户 64-bit SteamID，字符串形态）
//   - UnionID    恒为空（Steam 无跨应用统一 id 概念，SteamID 本身全局唯一）
//   - SessionKey 恒为空（Steam 无 session_key 概念）
//   - Raw        ← 应答 params 全部字段透传（官方未公开字段级 schema，社区已知
//     含 ownersteamid / vacbanned / publisherbanned，本实现不依赖这些字段——
//     家庭共享场景 ownersteamid 可能与 steamid 不同，业务需要时自取）
//
// 注意：Config.Identity 非空时会随请求携带 identity 参数——客户端创建票据时
// 必须传同一标识串，否则平台校验不通过。
func (s *Steam) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, opAuthTicket, "", "credential（会话票据 hex 字符串）为空")
	}
	// 官方要求票据是二进制数据的十六进制字符串——先做格式预校验，把"误传了
	// base64 / 原始二进制"这类接入错误在本地拦下（确定性失败，不浪费一次远端调用）。
	if _, err := hex.DecodeString(credential); err != nil {
		return nil, errs.New(PlatformName, opAuthTicket, "",
			"credential 不是合法的十六进制字符串（GetAuthTicketForWebApi 的二进制票据须转 hex 后传入）").
			WithCause(err)
	}

	query := url.Values{
		"key":    {s.cfg.WebAPIKey},
		"appid":  {strconv.FormatUint(uint64(s.cfg.AppID), 10)},
		"ticket": {credential},
	}
	if s.cfg.Identity != "" {
		query.Set("identity", s.cfg.Identity)
	}

	resp, err := s.hc.Get(ctx, httpx.JoinURL(s.cfg.BaseURL, authTicketPath), query, nil)
	if err != nil {
		// 传输层失败（网络错误/超时）——票据在远端未被消费，可安全重试。
		return nil, errs.Wrap(PlatformName, opAuthTicket, err).WithRetryable(true)
	}
	// 非 2xx：Steam 返回 HTML 错误页（实测 2026-06-11：403 + text/html），
	// 不强行 JSON 解析，按官方状态码语义分类。
	if !resp.OK() {
		return nil, errs.New(PlatformName, opAuthTicket, strconv.Itoa(resp.StatusCode),
			httpStatusHint(resp.StatusCode)+": "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	var body authTicketResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opAuthTicket, err).
			WithHTTPStatus(resp.StatusCode)
	}
	// 业务失败：response.error{errorcode, errordesc}（票据无效/过期等）。
	if e := body.Response.Error; e != nil {
		return nil, errs.New(PlatformName, opAuthTicket, string(e.ErrorCode), e.ErrorDesc).
			WithHTTPStatus(resp.StatusCode)
	}
	// result 校验（两个层级都兼容，见 authTicketResp 注释）；非 "OK" 即失败。
	result := body.Response.Result
	if result == "" {
		result = rawToString(body.Response.Params["result"])
	}
	if result != "" && !strings.EqualFold(result, "OK") {
		return nil, errs.New(PlatformName, opAuthTicket, result,
			"平台返回非 OK 结果: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}

	steamID := rawToString(body.Response.Params["steamid"])
	if steamID == "" {
		// 200 且无 error 却缺 steamid——官方承诺有效票据返回 SteamID，视为协议异常。
		return nil, errs.New(PlatformName, opAuthTicket, "",
			"应答缺少 steamid 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}

	// params 全部字段透传 Raw（含 result/steamid，业务按需取用）。
	raw := make(map[string]string, len(body.Response.Params))
	for k, v := range body.Response.Params {
		raw[k] = rawToString(v)
	}
	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   steamID,
		Raw:      raw,
	}, nil
}
