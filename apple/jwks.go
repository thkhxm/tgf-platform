//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：Sign in with Apple JWKS 公钥拉取 + 缓存 + JWK→公钥构造
//2026/6/11
//***************************************************

package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
)

// jwk 是 JWKS 中的单把公钥（RFC 7517）。
//
// Apple JWKS 端点 https://appleid.apple.com/auth/keys 2026-06-11 实抓返回
// {"keys":[{"kty":"RSA","kid":"...","use":"sig","alg":"RS256","n":"...","e":"AQAB"} ×3]}
// ——当前全部是 RS256 RSA key。官方校验步骤的原文是 "Verify the JWS E256
// signature using the server's public key"
// （https://developer.apple.com/documentation/SignInWithApple/verifying-a-user ，
// 2026-06-11 拉取），与实抓的 RS256 不一致——本实现以 JWK 自描述（kty/alg）
// 为准动态选择验签算法，RSA(RS256) 与 EC(ES256) 双支持，两边都覆盖。
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA 参数（kty=RSA）：模数 / 指数，base64url 大端字节。
	N string `json:"n"`
	E string `json:"e"`
	// EC 参数（kty=EC）：曲线名 / 坐标，base64url 大端字节。
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksResp 是 JWKS 端点应答。
type jwksResp struct {
	Keys []jwk `json:"keys"`
}

// jwksMinRefreshInterval 未知 kid 触发强制刷新的最小间隔——防止攻击者用
// 随机 kid 的伪造 token 打爆 Apple JWKS 端点（也保护本服务不被拖死）。
const jwksMinRefreshInterval = time.Minute

// jwksCache 是带 TTL 的 JWKS 公钥缓存，并发安全。
// 缓存命中直接返回；TTL 过期或遇到未知 kid 时刷新（后者受最小间隔限流）。
type jwksCache struct {
	hc  *httpx.Client
	url string
	ttl time.Duration

	mu          sync.Mutex
	keys        map[string]jwk // kid → jwk
	fetchedAt   time.Time      // 上次成功拉取时刻
	lastAttempt time.Time      // 上次尝试拉取时刻（含失败，用于限流）
	now         func() time.Time
}

func newJWKSCache(hc *httpx.Client, url string, ttl time.Duration) *jwksCache {
	return &jwksCache{hc: hc, url: url, ttl: ttl, now: time.Now}
}

// key 返回 kid 对应的 JWK。缓存新鲜且命中直接返回；未命中且距上次拉取超过
// 最小间隔时强制刷新一次（覆盖 Apple 轮换密钥的场景）。
func (c *jwksCache) key(ctx context.Context, kid string) (*jwk, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	fresh := !c.fetchedAt.IsZero() && now.Sub(c.fetchedAt) < c.ttl
	if fresh {
		if k, ok := c.keys[kid]; ok {
			return &k, nil
		}
	}
	// 缓存过期，或新鲜但未命中（可能是密钥轮换）→ 刷新；
	// 未命中触发的刷新受最小间隔限流，限流期间只能用旧缓存。
	if now.Sub(c.lastAttempt) >= jwksMinRefreshInterval || c.fetchedAt.IsZero() {
		c.lastAttempt = now
		if err := c.refreshLocked(ctx); err != nil {
			// 拉取失败但旧缓存里有这把 key → 容忍陈旧继续用（可用性优先；
			// 签名校验本身保证安全性，陈旧只影响已轮换下线的 key）。
			if k, ok := c.keys[kid]; ok {
				return &k, nil
			}
			return nil, err
		}
	}
	if k, ok := c.keys[kid]; ok {
		return &k, nil
	}
	return nil, errs.New(PlatformName, opFetchJWKS, "",
		"JWKS 中找不到 kid="+kid+" 的公钥（token 伪造或 Apple 密钥已轮换下线）")
}

// refreshLocked 拉取 JWKS 并重建缓存；调用方必须已持有 c.mu。
//
// 端点：GET https://appleid.apple.com/auth/keys
// 文档：https://developer.apple.com/documentation/SignInWithApple/verifying-a-user
// （2026-06-11 拉取；应答结构 2026-06-11 对该端点实抓核对）。
func (c *jwksCache) refreshLocked(ctx context.Context) error {
	resp, err := c.hc.Get(ctx, c.url, nil, nil)
	if err != nil {
		return errs.Wrap(PlatformName, opFetchJWKS, err).WithRetryable(true)
	}
	if !resp.OK() {
		return errs.New(PlatformName, opFetchJWKS, strconv.Itoa(resp.StatusCode),
			"JWKS 端点 HTTP 状态异常").
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	var body jwksResp
	if err := resp.JSON(&body); err != nil {
		return errs.Wrap(PlatformName, opFetchJWKS, err).WithHTTPStatus(resp.StatusCode)
	}
	if len(body.Keys) == 0 {
		return errs.New(PlatformName, opFetchJWKS, "", "JWKS 应答不含任何公钥")
	}
	keys := make(map[string]jwk, len(body.Keys))
	for _, k := range body.Keys {
		keys[k.Kid] = k
	}
	c.keys = keys
	c.fetchedAt = c.now()
	return nil
}

// rsaPublicKey 从 RSA JWK 构造 *rsa.PublicKey（n/e 为 base64url 大端字节，RFC 7518 §6.3）。
func (k *jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	nb, err := b64uDecode(k.N)
	if err != nil {
		return nil, fmt.Errorf("JWK n 解码失败: %w", err)
	}
	eb, err := b64uDecode(k.E)
	if err != nil {
		return nil, fmt.Errorf("JWK e 解码失败: %w", err)
	}
	if len(nb) == 0 || len(eb) == 0 || len(eb) > 8 {
		return nil, fmt.Errorf("JWK RSA 参数非法（len(n)=%d, len(e)=%d）", len(nb), len(eb))
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() <= 1 {
		return nil, fmt.Errorf("JWK RSA 指数非法: %s", e)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
}

// ecPublicKey 从 EC JWK 构造 *ecdsa.PublicKey（仅支持 P-256，对应 ES256）。
func (k *jwk) ecPublicKey() (*ecdsa.PublicKey, error) {
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("JWK EC 曲线不支持: %q（ES256 仅支持 P-256）", k.Crv)
	}
	xb, err := b64uDecode(k.X)
	if err != nil {
		return nil, fmt.Errorf("JWK x 解码失败: %w", err)
	}
	yb, err := b64uDecode(k.Y)
	if err != nil {
		return nil, fmt.Errorf("JWK y 解码失败: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	// 坐标必须落在曲线上（防无效曲线攻击）。
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("JWK EC 公钥坐标不在 P-256 曲线上")
	}
	return pub, nil
}
