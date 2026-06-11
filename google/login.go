//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：LoginProvider——Google ID token（JWT）服务端本地验签 → sub 身份映射
//2026/6/11
//***************************************************

package google

import (
	"context"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opVerifyIDToken = "verify_id_token"

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端从 Google Sign-In SDK 拿到的 ID token（JWT）。本方法在
// 服务端**本地**完成校验（不调 tokeninfo——官方明确 tokeninfo 仅供调试，生产
// 必须本地验签）：
//
// 校验项（官方步骤，缺一不可）
// 文档：https://developers.google.com/identity/sign-in/web/backend-auth（2026-06-11 拉取）
// 与 https://developers.google.com/identity/openid-connect/openid-connect（2026-06-11 拉取）：
//  1. 签名由 Google 公钥（JWKS 端点 https://www.googleapis.com/oauth2/v3/certs ，
//     RS256，定期轮换、按 Cache-Control 缓存）验证；
//  2. aud 等于本应用的某个 client ID（Config.ClientIDs 白名单——防止签给
//     恶意应用的 token 被用来冒充本应用用户）；
//  3. iss 等于 accounts.google.com 或 https://accounts.google.com（两种形态
//     都合法）；
//  4. exp 未过期；
//  5. （可选）Config.HostedDomain 配置时校验 hd claim——仅限定 Google
//     Workspace 组织账号的业务用。
//
// 身份映射：
//   - OpenID     ← sub（官方明确「This ID is unique to each Google Account,
//     making it suitable for use as a primary key」；email 可被用户改，不可作主键）
//   - UnionID    恒为空（Google 无跨应用统一 id 概念）
//   - SessionKey 恒为空（Google 无 session_key 概念）
//   - Raw        ← iss / aud / azp / email / email_verified / name / picture /
//     given_name / family_name / locale / hd / iat / exp 透传（profile/email
//     字段仅在用户授权对应 scope 时存在）
func (g *Google) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if credential == "" {
		return nil, errs.New(PlatformName, opVerifyIDToken, "", "credential（ID token）为空")
	}
	if len(g.cfg.ClientIDs) == 0 {
		return nil, errs.New(PlatformName, opVerifyIDToken, "",
			"未配置登录能力：Config.ClientIDs 为空（aud 白名单）")
	}

	claims, err := g.verifyGoogleJWT(ctx, opVerifyIDToken, credential)
	if err != nil {
		return nil, err
	}

	// aud 白名单（官方步骤 2；多端接同一后端时 token 的 aud 是其中某端的 client ID）。
	matched := false
	for _, id := range g.cfg.ClientIDs {
		if claims.Aud.contains(id) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, errs.New(PlatformName, opVerifyIDToken, "",
			"aud 不在本应用 client ID 白名单内: "+truncate(strings.Join(claims.Aud, ","), 128))
	}

	// hd（官方步骤 5，可选）：限定 Workspace 组织账号。官方明确「The absence of
	// this claim indicates that the account does not belong to a Google hosted
	// domain」——配置了 HostedDomain 而 token 无 hd 即拒绝。
	if g.cfg.HostedDomain != "" && claims.Hd != g.cfg.HostedDomain {
		return nil, errs.New(PlatformName, opVerifyIDToken, "",
			"hd 与限定的 hosted domain 不符: "+truncate(claims.Hd, 64)+" != "+g.cfg.HostedDomain)
	}

	if claims.Sub == "" {
		// 验签通过却没有 sub——按官方协议不该发生，视为协议异常。
		return nil, errs.New(PlatformName, opVerifyIDToken, "", "token 缺少 sub claim")
	}

	raw := map[string]string{
		"iss": claims.Iss,
		"aud": strings.Join(claims.Aud, ","),
		"iat": strconv.FormatInt(claims.Iat, 10),
		"exp": strconv.FormatInt(claims.Exp, 10),
	}
	// 可选字段只在有值时透传，避免 Raw 充斥空串。
	setIfNotEmpty(raw, "azp", claims.Azp)
	setIfNotEmpty(raw, "email", claims.Email)
	if claims.Email != "" {
		raw["email_verified"] = strconv.FormatBool(claims.EmailVerified)
	}
	setIfNotEmpty(raw, "name", claims.Name)
	setIfNotEmpty(raw, "picture", claims.Picture)
	setIfNotEmpty(raw, "given_name", claims.GivenName)
	setIfNotEmpty(raw, "family_name", claims.FamilyName)
	setIfNotEmpty(raw, "locale", claims.Locale)
	setIfNotEmpty(raw, "hd", claims.Hd)

	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   claims.Sub,
		Raw:      raw,
	}, nil
}

// setIfNotEmpty 仅当 v 非空时写入 map。
func setIfNotEmpty(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}
