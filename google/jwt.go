//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：JWKS 公钥缓存 + Google JWT（RS256）本地验签 + 通用 claims
//2026/6/11
//***************************************************

package google

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf-platform/core/sign"
)

// JWT 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, google.ErrJWTXxx) 区分失败原因。
var (
	// ErrJWTMalformed token 不是合法的三段式 JWT，或 header / claims 解码失败。
	ErrJWTMalformed = errors.New("google: JWT 格式非法")
	// ErrJWTUnexpectedAlg JWT header 的 alg 不是 RS256。
	// Google OAuth2 / OIDC 只用 RS256 签发（https://developers.google.com/identity/protocols/oauth2/service-account ，
	// 2026-06-11 拉取：「The only signing algorithm supported by the Google OAuth 2.0
	// Authorization Server is RSA using SHA-256」）——alg 白名单同时挡掉
	// alg=none / HS256 这类经典 JWT 伪造手法。
	ErrJWTUnexpectedAlg = errors.New("google: JWT alg 不是 RS256")
	// ErrJWTUnknownKeyID JWT header 的 kid 在 Google JWKS 中不存在（已强制刷新仍未命中）。
	ErrJWTUnknownKeyID = errors.New("google: JWT kid 在 JWKS 中不存在")
	// ErrJWTSignatureMismatch 签名比对失败（payload 被篡改或非 Google 签发）。
	ErrJWTSignatureMismatch = errors.New("google: JWT 签名比对失败")
	// ErrJWTExpired exp 已过（超出时钟漂移容忍）。
	ErrJWTExpired = errors.New("google: JWT 已过期")
	// ErrJWTIssuedInFuture iat 在未来（超出时钟漂移容忍），疑似伪造或时钟异常。
	ErrJWTIssuedInFuture = errors.New("google: JWT iat 在未来")
	// ErrJWTIssuerMismatch iss 不是 Google（accounts.google.com 两种形态之外）。
	ErrJWTIssuerMismatch = errors.New("google: JWT iss 不是 Google")
)

// jwksCache 内部刷新参数。
const (
	// jwksMinRefreshInterval kid 未命中触发强制刷新的最小间隔——防垃圾 kid
	// 打爆 JWKS 端点（Google 对调试端点有限频，正式端点也不该被滥打）。
	jwksMinRefreshInterval = 30 * time.Second
	// jwksDefaultMaxAge 应答没带 Cache-Control max-age 时的兜底缓存时长。
	// 官方要求按 Cache-Control 决定重取时机（https://developers.google.com/identity/sign-in/web/backend-auth ，
	// 2026-06-11 拉取），实测该端点 max-age 以小时计；1 小时是保守兜底。
	jwksDefaultMaxAge = time.Hour
)

// jwk 是 JWKS 应答中的单把公钥。
// 字段形态 2026-06-11 实抓 https://www.googleapis.com/oauth2/v3/certs 确认：
// {"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"...","n":"<base64url>","e":"AQAB"}]}。
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksDoc 是 JWKS 端点应答。
type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// jwksCache 是 Google JWKS 公钥缓存：按 Cache-Control max-age 缓存，
// kid 未命中（密钥轮换）时强制刷新（限频）。并发安全。
type jwksCache struct {
	hc  *httpx.Client
	url string
	now func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time // 缓存有效期（fetchedAt + max-age）
	lastFetch time.Time // 最近一次实际拉取时刻（强刷限频用）
}

// publicKey 取 kid 对应的 RSA 公钥。缓存命中直接返回；缓存过期或 kid 未命中
// 时重新拉取（强刷有 jwksMinRefreshInterval 限频，限频期间命中旧 key 仍可用——
// 旧 key 验签在数学上依然成立，轮换只是停发新签名）。
func (c *jwksCache) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	fresh := c.keys != nil && now.Before(c.expiresAt)
	if fresh {
		if pub, ok := c.keys[kid]; ok {
			return pub, nil
		}
	}
	// 缓存过期，或 kid 未命中（可能是密钥轮换）→ 重新拉取（限频）。
	if now.Sub(c.lastFetch) >= jwksMinRefreshInterval {
		if err := c.fetchLocked(ctx); err != nil {
			// 拉取失败但手里有旧 key → 降级用旧 key（见方法注释）；没有才报错。
			if pub, ok := c.keys[kid]; ok {
				return pub, nil
			}
			return nil, err
		}
	}
	if pub, ok := c.keys[kid]; ok {
		return pub, nil
	}
	return nil, errs.New(PlatformName, "jwks", "", "kid 未命中: "+truncate(kid, 64)).
		WithCause(ErrJWTUnknownKeyID)
}

// fetchLocked 拉取并解析 JWKS（调用方须已持锁）。
func (c *jwksCache) fetchLocked(ctx context.Context) error {
	c.lastFetch = c.now()
	resp, err := c.hc.Get(ctx, c.url, nil, nil)
	if err != nil {
		return errs.Wrap(PlatformName, "jwks", err).WithRetryable(true)
	}
	if !resp.OK() {
		return errs.New(PlatformName, "jwks", strconv.Itoa(resp.StatusCode),
			"JWKS 端点 HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	var doc jwksDoc
	if err := resp.JSON(&doc); err != nil {
		return errs.Wrap(PlatformName, "jwks", err).WithHTTPStatus(resp.StatusCode)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		// 只收验签用 RSA 键；alg 缺省按 RS256 容忍（Google 实际都带 alg）。
		if !strings.EqualFold(k.Kty, "RSA") || (k.Use != "" && k.Use != "sig") ||
			(k.Alg != "" && k.Alg != "RS256") || k.Kid == "" {
			continue
		}
		pub, err := jwkToRSAPublicKey(k)
		if err != nil {
			continue // 单把键损坏不拖垮整组
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errs.New(PlatformName, "jwks", "", "JWKS 应答中没有可用的 RS256 公钥: "+truncate(resp.String(), 256))
	}
	c.keys = keys
	maxAge := jwksDefaultMaxAge
	if d, ok := parseCacheControlMaxAge(resp.Header.Get("Cache-Control")); ok {
		maxAge = d
	}
	c.expiresAt = c.now().Add(maxAge)
	return nil
}

// parseCacheControlMaxAge 从 Cache-Control 头解析 max-age（秒）。
func parseCacheControlMaxAge(v string) (time.Duration, bool) {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if rest, ok := strings.CutPrefix(strings.ToLower(part), "max-age="); ok {
			if sec, err := strconv.ParseInt(rest, 10, 64); err == nil && sec > 0 {
				return time.Duration(sec) * time.Second, true
			}
		}
	}
	return 0, false
}

// jwkToRSAPublicKey 把 JWK 的 n / e（base64url，大端）还原为 *rsa.PublicKey。
func jwkToRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, errors.New("google: JWK n 不是合法 base64url: " + err.Error())
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, errors.New("google: JWK e 不是合法 base64url: " + err.Error())
	}
	if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errors.New("google: JWK n/e 长度非法")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 1 {
		return nil, errors.New("google: JWK e 取值非法")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// ---------------------------------------------------------------------------
// Google JWT（RS256）本地验签
// ---------------------------------------------------------------------------

// jwtHeader 是 JWT 第一段（header）。
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// audience 兼容 aud 的两种 JSON 形态：单字符串（Google ID token 实际形态）
// 与字符串数组（JWT 规范允许）。
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = audience{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = audience(arr)
	return nil
}

// contains 报告 aud 是否包含 v。
func (a audience) contains(v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
}

// googleJWTClaims 是 Google 签发 JWT 的 claims 并集（ID token 与 Pub/Sub push
// OIDC token 共用；字段以官方文档为准）：
//   - ID token 字段：https://developers.google.com/identity/sign-in/web/backend-auth
//     （2026-06-11 拉取，tokeninfo 示例：iss/sub/azp/aud/iat/exp + 授权 profile/email
//     scope 后的 email/email_verified/name/picture/given_name/family_name/locale；
//     hd 为 Workspace 账号的 hosted domain）；
//   - Pub/Sub push OIDC token 字段：https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions
//     （2026-06-11 拉取，示例 claims：aud/azp/email/sub/email_verified/exp/iat/iss）。
type googleJWTClaims struct {
	Iss           string   `json:"iss"`
	Sub           string   `json:"sub"`
	Azp           string   `json:"azp"`
	Aud           audience `json:"aud"`
	Iat           int64    `json:"iat"`
	Exp           int64    `json:"exp"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	GivenName     string   `json:"given_name"`
	FamilyName    string   `json:"family_name"`
	Locale        string   `json:"locale"`
	Hd            string   `json:"hd"`
}

// verifyGoogleJWT 完成 Google JWT 的通用校验：RS256 验签（JWKS 公钥）+
// iss（accounts.google.com 两种形态）+ exp（含时钟漂移容忍）+ iat 不在未来。
// aud / email / hd 等按能力差异化的 claim 由调用方继续校验。
//
// 校验依据（officially required steps）：
// https://developers.google.com/identity/openid-connect/openid-connect（2026-06-11 拉取）
// 「Validation of an ID token requires several steps」：
//  1. 签名由 jwks_uri 端点的证书验证；
//  2. iss 等于 https://accounts.google.com 或 accounts.google.com；
//  3. aud 等于本应用 client ID（调用方校验）；
//  4. exp 未过期。
func (g *Google) verifyGoogleJWT(ctx context.Context, op, token string) (*googleJWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errs.New(PlatformName, op, "", "token 不是三段式 JWT").
			WithCause(ErrJWTMalformed)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errs.New(PlatformName, op, "", "JWT header 不是合法 base64url").
			WithCause(ErrJWTMalformed)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errs.New(PlatformName, op, "", "JWT header 解析失败: "+truncate(string(headerJSON), 128)).
			WithCause(ErrJWTMalformed)
	}
	// alg 白名单：Google 只用 RS256（见 ErrJWTUnexpectedAlg 注释）。
	if header.Alg != "RS256" {
		return nil, errs.New(PlatformName, op, "", "JWT alg 非法: "+truncate(header.Alg, 32)).
			WithCause(ErrJWTUnexpectedAlg)
	}
	if header.Kid == "" {
		return nil, errs.New(PlatformName, op, "", "JWT header 缺少 kid").
			WithCause(ErrJWTMalformed)
	}
	pub, err := g.jwks.publicKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errs.New(PlatformName, op, "", "JWT 签名段不是合法 base64url").
			WithCause(ErrJWTMalformed)
	}
	// 签名输入是「header.payload」的原始字节（JWS 规范，service-account 文档
	// 同样表述：input = {Base64url encoded header}.{Base64url encoded claim set}）。
	signingInput := token[:len(parts[0])+1+len(parts[1])]
	if err := sign.RSASHA256Verify(pub, []byte(signingInput), sigBytes); err != nil {
		return nil, errs.New(PlatformName, op, "", "JWT 签名比对失败").
			WithCause(ErrJWTSignatureMismatch)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errs.New(PlatformName, op, "", "JWT claims 段不是合法 base64url").
			WithCause(ErrJWTMalformed)
	}
	var claims googleJWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, errs.New(PlatformName, op, "", "JWT claims 解析失败: "+truncate(string(claimsJSON), 256)).
			WithCause(ErrJWTMalformed)
	}

	// iss：两种形态都合法（官方明确，见方法注释）。
	if claims.Iss != "accounts.google.com" && claims.Iss != "https://accounts.google.com" {
		return nil, errs.New(PlatformName, op, "", "iss 非法: "+truncate(claims.Iss, 64)).
			WithCause(ErrJWTIssuerMismatch)
	}
	now := g.now()
	// exp：未过期（含时钟漂移容忍）。exp 缺失（0）按非法处理——Google 签发的
	// token 必带 exp。
	if claims.Exp <= 0 || now.After(time.Unix(claims.Exp, 0).Add(g.cfg.ClockSkew)) {
		return nil, errs.New(PlatformName, op, "",
			"token 已过期（exp="+strconv.FormatInt(claims.Exp, 10)+"）").
			WithCause(ErrJWTExpired)
	}
	// iat 不在未来：官方四步未列，但 iat 是 Google token 的固定 claim，
	// 未来时间只可能是伪造或时钟异常——工程防御，容忍同样的时钟漂移。
	if claims.Iat > 0 && time.Unix(claims.Iat, 0).After(now.Add(g.cfg.ClockSkew)) {
		return nil, errs.New(PlatformName, op, "",
			"token iat 在未来（iat="+strconv.FormatInt(claims.Iat, 10)+"）").
			WithCause(ErrJWTIssuedInFuture)
	}
	return &claims, nil
}
