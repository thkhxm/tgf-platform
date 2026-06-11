//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：LoginProvider——auth_code 换 user_id/open_id + access_token（+ 可选 user.info.share 补信息）
//2026/6/11
//***************************************************

package alipay

import (
	"context"
	"encoding/json"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op），按平台 API 名命名。
const (
	opOAuthToken    = "oauth_token"
	opUserInfoShare = "user_info_share"
)

// 接口名（公共参数 method）。
const (
	// methodOAuthToken 换取授权访问令牌接口 alipay.system.oauth.token。
	//
	// 文档：https://opendocs.alipay.com/apis/api_9/alipay.system.oauth.token
	// （2026-06-11 经本机代理直连拉取正文核对，本文件各接口引注同此方式，下同）
	//   - 统一网关 POST gateway.do，公共参数 + RSA2 签名（见 callGateway 注释）
	//   - 业务请求参数为「平铺表单参数」而非 biz_content（官方 cURL 示例
	//     -F 'grant_type=...' -F 'code=...'，与 trade.query 的 biz_content 形态不同）：
	//     grant_type（authorization_code = 用授权码换令牌）/ code（授权码，
	//     grant_type=authorization_code 时必填）/ refresh_token（刷新令牌场景）
	//   - 成功响应节点 alipay_system_oauth_token_response（注意：不含 code/msg
	//     公共字段，响应示例确认）：access_token（访问令牌）/ expires_in（有效期，
	//     单位秒）/ refresh_token / re_expires_in（刷新令牌有效期，秒）/
	//     user_id 与 open_id 二选一（user_id 以 2088 开头 16 位数字，新商户建议
	//     用 open_id 替代）/ auth_start（授权开始时间，可选）
	//   - 错误走 error_response 节点：isv.code-invalid（授权码错误/过期）/
	//     isv.grant-type-invalid / isv.unmatched-app-id / isp.unknow-error（重试）等
	//
	// 关键坑：code（auth_code）是一次性凭据，消费过即作废——网络歧义失败后重试
	// 同一 code 会得到确定性 isv.code-invalid，故本实现不开 HTTP 层重试。
	methodOAuthToken = "alipay.system.oauth.token"

	// methodUserInfoShare 支付宝会员授权信息查询接口 alipay.user.info.share。
	//
	// 文档：https://opendocs.alipay.com/apis/api_2/alipay.user.info.share
	// （2026-06-11 拉取）
	//   - 参数：auth_token（必填，即 oauth.token 换到的 access_token，官方 cURL
	//     示例置于表单体）；无业务请求参数
	//   - 成功响应节点 alipay_user_info_share_response（含 code=10000/msg 公共
	//     字段）：avatar / city / nick_name / province / gender（F 女 M 男）+
	//     user_id 与 open_id 二选一
	//   - 业务错误码：SYSTEM_ERROR（系统繁忙，可用同样请求重试）
	methodUserInfoShare = "alipay.user.info.share"
)

// oauthTokenResp alipay.system.oauth.token 的业务响应节点
// （字段名以官方文档为准，见 methodOAuthToken 注释；expires_in / re_expires_in
// 官方声明 String 且示例带引号，用 flexString 容错数字形态）。
type oauthTokenResp struct {
	gatewayCommonResp
	AccessToken  string     `json:"access_token"`
	ExpiresIn    flexString `json:"expires_in"`
	RefreshToken string     `json:"refresh_token"`
	ReExpiresIn  flexString `json:"re_expires_in"`
	UserID       string     `json:"user_id"`
	OpenID       string     `json:"open_id"`
	AuthStart    string     `json:"auth_start"`
}

// userInfoShareResp alipay.user.info.share 的业务响应节点
// （字段名以官方文档为准，见 methodUserInfoShare 注释）。
type userInfoShareResp struct {
	gatewayCommonResp
	UserID   string `json:"user_id"`
	OpenID   string `json:"open_id"`
	Avatar   string `json:"avatar"`
	City     string `json:"city"`
	NickName string `json:"nick_name"`
	Province string `json:"province"`
	Gender   string `json:"gender"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端从支付宝 SDK 拿到的一次性授权码 auth_code（小程序
// my.getAuthCode / App 端「用户登录授权」流程返回的 code），本方法调
// alipay.system.oauth.token（grant_type=authorization_code）换取身份并映射为
// 标准化身份：
//
//   - OpenID   ← open_id（新商户形态）优先，缺省回退 user_id（2088 开头 16 位，
//     存量商户形态）——官方明确两字段二选一返回
//   - UnionID  恒为空（支付宝无跨应用统一 id 概念）
//   - SessionKey 恒为空（支付宝无 session_key 概念）
//   - Raw      ← access_token / expires_in / refresh_token / re_expires_in /
//     auth_start / user_id / open_id 透传；Config.FetchUserInfo 开启时追加
//     nick_name / avatar / province / city / gender
//
// 安全注意：Raw 中的 access_token / refresh_token 属凭据类数据（与合约对
// SessionKey 的纪律相同）——只允许留在服务端受控存储，严禁下发客户端或打日志。
func (a *Alipay) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, opOAuthToken, "", "credential（auth_code）为空")
	}

	node, status, err := a.callGateway(ctx, opOAuthToken, methodOAuthToken, map[string]string{
		"grant_type": "authorization_code",
		"code":       credential,
	})
	if err != nil {
		return nil, err
	}
	var body oauthTokenResp
	if err := json.Unmarshal(node, &body); err != nil {
		return nil, errs.Wrap(PlatformName, opOAuthToken, err).WithHTTPStatus(status)
	}
	// 防御：常规错误走 error_response（callGateway 已拦截），但若节点内出现
	// code != 10000 也按业务错误处理（oauth.token 成功节点无 code 字段）。
	if e := bizError(opOAuthToken, status, body.gatewayCommonResp); e != nil {
		return nil, e
	}
	if body.AccessToken == "" || (body.UserID == "" && body.OpenID == "") {
		// 验签通过却缺关键字段——按官方文档这不该发生，视为协议异常。
		return nil, errs.New(PlatformName, opOAuthToken, "",
			"应答缺少 access_token / user_id / open_id 字段: "+truncate(string(node), 256)).
			WithHTTPStatus(status)
	}

	openID := body.OpenID
	if openID == "" {
		openID = body.UserID
	}
	identity := &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   openID,
		Raw: map[string]string{
			"access_token":  body.AccessToken,
			"expires_in":    string(body.ExpiresIn),
			"refresh_token": body.RefreshToken,
			"re_expires_in": string(body.ReExpiresIn),
			"auth_start":    body.AuthStart,
			"user_id":       body.UserID,
			"open_id":       body.OpenID,
		},
	}

	if a.cfg.FetchUserInfo {
		if err := a.fillUserInfo(ctx, body.AccessToken, &body, identity); err != nil {
			return nil, err
		}
	}
	return identity, nil
}

// fillUserInfo 调 alipay.user.info.share 补取昵称/头像等（协议见
// methodUserInfoShare 注释），并交叉核对身份防串号。
func (a *Alipay) fillUserInfo(ctx context.Context, accessToken string, token *oauthTokenResp, identity *platform.PlatformIdentity) error {
	node, status, err := a.callGateway(ctx, opUserInfoShare, methodUserInfoShare, map[string]string{
		"auth_token": accessToken,
	})
	if err != nil {
		return err
	}
	var body userInfoShareResp
	if err := json.Unmarshal(node, &body); err != nil {
		return errs.Wrap(PlatformName, opUserInfoShare, err).WithHTTPStatus(status)
	}
	if e := bizError(opUserInfoShare, status, body.gatewayCommonResp); e != nil {
		return e
	}
	// 防串号：user.info.share 返回的 user_id / open_id 必须与 oauth.token 一致
	// （同一 access_token 查自己的信息，不一致即协议异常或实现 bug，宁可失败
	// 不可错绑身份）。两接口可能各返回不同形态 id，只比对双方都非空的同名字段。
	if body.UserID != "" && token.UserID != "" && body.UserID != token.UserID {
		return errs.New(PlatformName, opUserInfoShare, "",
			"user.info.share 返回的 user_id 与 oauth.token 不一致（疑似串号）: "+body.UserID+" != "+token.UserID).
			WithHTTPStatus(status)
	}
	if body.OpenID != "" && token.OpenID != "" && body.OpenID != token.OpenID {
		return errs.New(PlatformName, opUserInfoShare, "",
			"user.info.share 返回的 open_id 与 oauth.token 不一致（疑似串号）: "+body.OpenID+" != "+token.OpenID).
			WithHTTPStatus(status)
	}
	identity.Raw["nick_name"] = body.NickName
	identity.Raw["avatar"] = body.Avatar
	identity.Raw["province"] = body.Province
	identity.Raw["city"] = body.City
	identity.Raw["gender"] = body.Gender
	return nil
}
