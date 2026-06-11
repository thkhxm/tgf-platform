//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：ID Token 本地验签——OIDC 发现 + JWKS 公钥缓存 + JWT RS256/PS256 校验
//2026/6/11
//***************************************************

package huawei

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
)

// 操作名（errs.Error.Op）。
const (
	opVerifyIDToken = "verify_id_token"
	opFetchJWKS     = "fetch_jwks"
)

// idTokenIssuer ID Token 的 iss 固定值。
// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/account-verify-id-token_hms_reference-0000001050050577
// （2026-06-11 拉取："iss 固定值：https://accounts.huawei.com"）；
// openid-configuration（2026-06-11 现网实测）issuer 同值。
const idTokenIssuer = "https://accounts.huawei.com"

// jwksCache 是 JWKS 公钥缓存（kid → 公钥）。
// 官方本地验证步骤（文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-Guides/android-scenario-id-token-0000001116078504 ，
// 2026-06-11 拉取）：从 openid-configuration 取 jwks_uri → 调 jwks_uri 取 keys →
// 生成公钥 → 验签 → 校验 iss / aud / exp。
type jwksCache struct {
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// openidConfiguration 是 OIDC 发现文档（只取本实现需要的字段）。
type openidConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// jwksDoc 是 JWKS 文档。RSA JWK 字段（kty/kid/alg/n/e）为 RFC 7517/7518 标准形态，
// 与 2026-06-11 现网实测的 https://oauth-login.cloud.huawei.com/oauth2/v3/certs
// 返回结构一致。
type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// publicKeyByKid 返回 kid 对应的公钥；缓存过期或 kid 未命中时刷新一次再找
// （密钥轮换兜底），仍未命中返回错误。
func (h *Huawei) publicKeyByKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	h.jwks.mu.Lock()
	defer h.jwks.mu.Unlock()

	fresh := h.jwks.keys != nil && h.now().Sub(h.jwks.fetchedAt) < h.cfg.JWKSCacheTTL
	if fresh {
		if pub, ok := h.jwks.keys[kid]; ok {
			return pub, nil
		}
	}
	// 缓存过期或 kid 未命中 → 刷新（持锁串行刷新，避免并发风暴打到平台）。
	keys, err := h.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	h.jwks.keys = keys
	h.jwks.fetchedAt = h.now()
	if pub, ok := keys[kid]; ok {
		return pub, nil
	}
	return nil, errs.New(PlatformName, opFetchJWKS, "",
		"JWKS 中不存在 kid="+truncate(kid, 80)+"（已强制刷新仍未命中）")
}

// fetchJWKS 按官方步骤取公钥：openid-configuration → jwks_uri → keys。
func (h *Huawei) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	// 第一步：OIDC 发现文档取 jwks_uri。
	resp, err := h.hc.Get(ctx, httpx.JoinURL(h.cfg.OAuthBaseURL, openidConfigurationPath), nil, nil)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opFetchJWKS, err).WithRetryable(true)
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opFetchJWKS, strconv.Itoa(resp.StatusCode),
			"openid-configuration HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	var oc openidConfiguration
	if err := resp.JSON(&oc); err != nil {
		return nil, errs.Wrap(PlatformName, opFetchJWKS, err).WithHTTPStatus(resp.StatusCode)
	}
	if oc.JWKSURI == "" {
		return nil, errs.New(PlatformName, opFetchJWKS, "", "openid-configuration 缺少 jwks_uri 字段")
	}

	// 第二步：jwks_uri 取 keys。
	resp, err = h.hc.Get(ctx, oc.JWKSURI, nil, nil)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opFetchJWKS, err).WithRetryable(true)
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opFetchJWKS, strconv.Itoa(resp.StatusCode),
			"jwks_uri HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	var doc jwksDoc
	if err := resp.JSON(&doc); err != nil {
		return nil, errs.Wrap(PlatformName, opFetchJWKS, err).WithHTTPStatus(resp.StatusCode)
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := jwkToRSAPublicKey(k.N, k.E)
		if err != nil {
			// 单把坏 key 不致命，跳过（剩余 key 仍可用）。
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errs.New(PlatformName, opFetchJWKS, "",
			"JWKS 中没有可用的 RSA 公钥: "+truncate(resp.String(), 256))
	}
	return keys, nil
}

// jwkToRSAPublicKey 把 RFC 7518 的 RSA JWK（n/e，base64url 无填充）转为 *rsa.PublicKey。
func jwkToRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("JWK n 不是合法 base64url: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("JWK e 不是合法 base64url: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, fmt.Errorf("JWK n/e 长度非法（n=%d e=%d 字节）", len(nBytes), len(eBytes))
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 1 {
		return nil, fmt.Errorf("JWK e 取值非法: %d", e)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// idTokenClaims 是 ID Token 的标准声明（只列校验与映射需要的字段，全量声明经
// VerifyLogin 透传 Raw）。字段语义文档：
// https://developer.huawei.com/consumer/cn/doc/HMSCore-References/account-verify-id-token_hms_reference-0000001050050577
// （2026-06-11 拉取）——sub 即用户的 UnionId；aud 为应用 ID。
type idTokenClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	// Aud 官方文档声明为 String；按 JWT 规范（RFC 7519 §4.1.3）aud 也可能是数组，
	// 防御性兼容两种形态（见 audContains）。
	Aud json.RawMessage `json:"aud"`
	Exp int64           `json:"exp"`
	Iat int64           `json:"iat"`
}

// verifyIDToken 本地校验 ID Token 并返回声明：
//
//  1. JWT 三段拆分，header 解析 alg / kid；
//  2. alg 只接受 RS256 / PS256——参考文档明确"ID Token 使用 RS256 算法进行签名"，
//     openid-configuration（2026-06-11 现网实测）id_token_signing_alg_values_supported
//     为 ["RS256","PS256"]；拒绝其余取值（防 alg 混淆攻击，如 HS256 用公钥当 HMAC 密钥）；
//  3. 按 kid 取 JWKS 公钥验签（签名原文 = header.payload 的原始 base64url 串）；
//  4. 校验 iss == https://accounts.huawei.com、aud 含本应用 ClientID、exp 未过期
//     （官方本地验证三步，见 jwksCache 注释的文档引用）。
func (h *Huawei) verifyIDToken(ctx context.Context, idToken string) (*idTokenClaims, map[string]any, error) {
	header, payload, sig, signedPart, err := splitJWT(idToken)
	if err != nil {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "", err.Error())
	}

	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(header, &hdr); err != nil {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "", "JWT header 解析失败").WithCause(err)
	}
	if hdr.Alg != "RS256" && hdr.Alg != "PS256" {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "",
			"不支持的签名算法 "+truncate(hdr.Alg, 32)+"（官方仅 RS256/PS256）")
	}
	if hdr.Kid == "" {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "", "JWT header 缺少 kid")
	}

	pub, err := h.publicKeyByKid(ctx, hdr.Kid)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(signedPart)
	switch hdr.Alg {
	case "RS256":
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
	case "PS256":
		err = rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, nil)
	}
	if err != nil {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "", "ID Token 签名校验失败").WithCause(err)
	}

	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "", "JWT payload 解析失败").WithCause(err)
	}
	if claims.Iss != idTokenIssuer {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "",
			"iss 不匹配: "+truncate(claims.Iss, 80)+" != "+idTokenIssuer)
	}
	if !audContains(claims.Aud, h.cfg.ClientID) {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "",
			"aud 不含本应用 ClientID（疑似其他应用的 ID Token）")
	}
	if claims.Exp <= h.now().Unix() {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "",
			"ID Token 已过期（exp="+strconv.FormatInt(claims.Exp, 10)+"）")
	}
	if claims.Sub == "" {
		return nil, nil, errs.New(PlatformName, opVerifyIDToken, "", "ID Token 缺少 sub 声明")
	}

	// 全量声明转 map 供 Raw 透传。
	var all map[string]any
	if err := json.Unmarshal(payload, &all); err != nil {
		all = nil // 标准声明已校验，全量透传失败不致命
	}
	return &claims, all, nil
}

// splitJWT 拆分 JWT 三段并解码，返回 header / payload / 签名字节与签名原文
// （header.payload 的原始 base64url 串字节——必须用原始串验签，绝不可重编码）。
func splitJWT(token string) (header, payload, sig, signedPart []byte, err error) {
	dot1 := -1
	dot2 := -1
	for i := 0; i < len(token); i++ {
		if token[i] != '.' {
			continue
		}
		if dot1 < 0 {
			dot1 = i
		} else if dot2 < 0 {
			dot2 = i
		} else {
			return nil, nil, nil, nil, fmt.Errorf("JWT 段数超过 3 段")
		}
	}
	if dot1 < 0 || dot2 < 0 || dot1 == 0 || dot2 == dot1+1 || dot2 == len(token)-1 {
		return nil, nil, nil, nil, fmt.Errorf("JWT 格式非法（应为 header.payload.signature 三段）")
	}
	if header, err = base64.RawURLEncoding.DecodeString(token[:dot1]); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("JWT header 不是合法 base64url: %w", err)
	}
	if payload, err = base64.RawURLEncoding.DecodeString(token[dot1+1 : dot2]); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("JWT payload 不是合法 base64url: %w", err)
	}
	if sig, err = base64.RawURLEncoding.DecodeString(token[dot2+1:]); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("JWT signature 不是合法 base64url: %w", err)
	}
	return header, payload, sig, []byte(token[:dot2]), nil
}

// audContains 报告 aud 声明（string 或 []string）是否包含 clientID。
func audContains(raw json.RawMessage, clientID string) bool {
	if len(raw) == 0 || clientID == "" {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == clientID
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, a := range list {
			if a == clientID {
				return true
			}
		}
	}
	return false
}
