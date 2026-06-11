//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：LoginProvider——Sign in with Apple identityToken（JWT）服务端校验
//2026/6/11
//***************************************************

package apple

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op），按平台 API/动作命名。
const (
	opVerifyIdentityToken = "verify_identity_token"
	opFetchJWKS           = "fetch_jwks"
)

// appleIssuer identityToken 的 iss 声明要求值。
// 文档：https://developer.apple.com/documentation/SignInWithApple/verifying-a-user
// （2026-06-11 拉取，原文："Verify that the iss field contains
// https://appleid.apple.com"）。
const appleIssuer = "https://appleid.apple.com"

// idTokenHeader 是 identityToken 的 JOSE header（取验签所需字段）。
type idTokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是客户端从 Apple SDK（ASAuthorizationAppleIDCredential.identityToken）
// 拿到的 identityToken（JWT），本方法在服务端按官方步骤校验后映射为标准化身份。
//
// 官方校验步骤（文档：
// https://developer.apple.com/documentation/SignInWithApple/verifying-a-user ，
// 2026-06-11 拉取，五条原文逐条落地）：
//
//  1. "Verify the JWS E256 signature using the server's public key"
//     —— 公钥从 https://appleid.apple.com/auth/keys（JWKS）按 header kid 取；
//     该端点 2026-06-11 实抓返回的全部是 RS256 RSA key，与原文的 E256 不一致，
//     本实现按 JWK 自描述动态选择 RS256/ES256（见 jwks.go 注释）；
//  2. "Verify the nonce for the authentication" —— 经 Config.NonceCheck 钩子
//     （期望值在业务的客户端会话里，合约签名无法传入；钩子为 nil 时跳过）；
//  3. "Verify that the iss field contains https://appleid.apple.com"；
//  4. "Verify that the aud field is the developer's client_id" —— 即 Config.ClientID；
//  5. "Verify that the time is earlier than the exp value of the token"。
//
// 身份映射：
//
//   - OpenID     ← sub（Apple 的稳定用户标识，同一开发者账号下跨 App 一致）
//   - UnionID    恒为空（Apple 无 union id 概念）
//   - SessionKey 恒为空（Apple 无 session_key 概念）
//   - Raw        ← token 全部标量声明透传（email / email_verified /
//     is_private_email / real_user_status / auth_time / nonce 等，有什么透传什么）
//
// 安全注意：identityToken 是一次性登录凭据，校验后不要存储；Raw 中可能含
// 用户邮箱等隐私数据，按业务合规要求处置，严禁打日志。
func (a *Apple) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	if a.cfg.ClientID == "" {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "",
			"未配置 Config.ClientID，无法校验 aud——登录能力不可用")
	}
	if credential == "" {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "credential（identityToken）为空")
	}

	headerSeg, payloadSeg, sigSeg, err := splitCompact(credential)
	if err != nil {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "identityToken 不是合法 JWT: "+err.Error())
	}
	var header idTokenHeader
	if err := decodeSegmentJSON(headerSeg, &header); err != nil {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "identityToken header 解析失败: "+err.Error())
	}
	if header.Kid == "" {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "identityToken header 缺少 kid")
	}

	// —— 步骤 1：JWKS 取公钥 + 验签 ——
	key, err := a.jwks.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	// 算法混淆防御：header 声明的 alg 必须与 JWK 自描述一致（JWK 给出 alg 时），
	// 且只接受 RS256 / ES256 两种白名单值（拒绝 none / HS256 降级攻击）。
	if key.Alg != "" && !strings.EqualFold(header.Alg, key.Alg) {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "",
			fmt.Sprintf("identityToken alg=%q 与 JWKS 公钥 alg=%q 不一致（疑似算法混淆攻击）", header.Alg, key.Alg))
	}
	signingInput := []byte(headerSeg + "." + payloadSeg)
	sigRaw, err := b64uDecode(sigSeg)
	if err != nil {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "identityToken 签名段 base64url 非法: "+err.Error())
	}
	switch {
	case key.Kty == "RSA" && strings.EqualFold(header.Alg, "RS256"):
		pub, err := key.rsaPublicKey()
		if err != nil {
			return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "JWKS RSA 公钥构造失败: "+err.Error())
		}
		if err := sign.RSASHA256Verify(pub, signingInput, sigRaw); err != nil {
			return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "identityToken 签名校验失败（token 被篡改或伪造）")
		}
	case key.Kty == "EC" && strings.EqualFold(header.Alg, "ES256"):
		pub, err := key.ecPublicKey()
		if err != nil {
			return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "JWKS EC 公钥构造失败: "+err.Error())
		}
		if !es256Verify(pub, signingInput, sigRaw) {
			return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "identityToken 签名校验失败（token 被篡改或伪造）")
		}
	default:
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "",
			fmt.Sprintf("不支持的签名算法组合（alg=%q, kty=%q）——仅接受 RS256/RSA 与 ES256/EC", header.Alg, key.Kty))
	}

	// —— 解析声明（验签通过后才解析语义） ——
	claims, err := decodeClaims(payloadSeg)
	if err != nil {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "identityToken 声明解析失败: "+err.Error())
	}

	// —— 步骤 3：iss ——
	if iss, _ := claims["iss"].(string); iss != appleIssuer {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "",
			fmt.Sprintf("iss 声明非法: %q（应为 %q）", claims["iss"], appleIssuer))
	}
	// —— 步骤 4：aud（JWT 规范允许 string 或 string 数组，两种都核对） ——
	if !audContains(claims["aud"], a.cfg.ClientID) {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "",
			fmt.Sprintf("aud 声明 %v 与 ClientID %q 不匹配（token 不是发给本应用的）", claims["aud"], a.cfg.ClientID))
	}
	// —— 步骤 5：exp ——
	exp, ok := claimInt64(claims["exp"])
	if !ok {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "exp 声明缺失或非法")
	}
	if a.now().Unix() >= exp {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "",
			"identityToken 已过期（exp="+strconv.FormatInt(exp, 10)+"）")
	}
	// —— 步骤 2：nonce（钩子注入期望值校验；钩子为 nil 时跳过） ——
	if a.cfg.NonceCheck != nil {
		nonce, _ := claims["nonce"].(string)
		if err := a.cfg.NonceCheck(nonce); err != nil {
			return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "nonce 校验失败: "+err.Error())
		}
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errs.New(PlatformName, opVerifyIdentityToken, "", "sub 声明缺失——无法确定用户标识")
	}

	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   sub,
		Raw:      stringifyClaims(claims),
	}, nil
}

// decodeClaims 解码 JWT payload 段为通用声明表（数字用 json.Number 保精度）。
func decodeClaims(payloadSeg string) (map[string]any, error) {
	raw, err := b64uDecode(payloadSeg)
	if err != nil {
		return nil, fmt.Errorf("base64url 解码失败: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %w", err)
	}
	return claims, nil
}

// audContains 报告 aud 声明（string 或 []any，RFC 7519 §4.1.3）是否包含 clientID。
func audContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// claimInt64 把声明值（json.Number）转 int64。
func claimInt64(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}

// stringifyClaims 把声明表的标量值转成 string 透传进 PlatformIdentity.Raw；
// 嵌套对象/数组 JSON 序列化后透传（不丢信息，也不强行抽象）。
func stringifyClaims(claims map[string]any) map[string]string {
	out := make(map[string]string, len(claims))
	for k, v := range claims {
		switch t := v.(type) {
		case string:
			out[k] = t
		case json.Number:
			out[k] = t.String()
		case bool:
			out[k] = strconv.FormatBool(t)
		case nil:
			out[k] = ""
		default:
			if b, err := json.Marshal(t); err == nil {
				out[k] = string(b)
			}
		}
	}
	return out
}

// retryableStatus 报告 HTTP 状态码是否属暂时性失败：429（限频）/ 5xx。
// 其余 4xx 是确定性失败（参数/凭据错误），重试无意义。
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}
