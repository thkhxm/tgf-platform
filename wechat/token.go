//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：access_token 来源——内置 stable_token 管理器（可被 Config.AccessTokenFunc 替换）
//2026/6/11
//***************************************************

package wechat

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
)

// 操作名（errs.Error.Op）。
const opStableToken = "stable_token"

// stableTokenPath 获取稳定版接口调用凭据。
//
// 文档：https://developers.weixin.qq.com/minigame/dev/api-backend/access-token/api_getstableaccesstoken.html
// （2026-06-11 拉取）
//   - POST https://api.weixin.qq.com/cgi-bin/stable_token
//   - 请求体（JSON）：grant_type=client_credential / appid / secret /
//     force_refresh（可选，默认 false 普通模式）
//   - 成功响应：access_token / expires_in（单位秒，7200 之内；若沿用旧 token
//     返回所剩有效时间）
//   - 普通模式下「有效期内重复调用不会更新 access_token」「平台会提前 5 分钟
//     更新」——多实例各自调用拿到同一 token，天然多实例安全，故内置管理器
//     选它而非 /cgi-bin/token（getAccessToken，官方亦推荐稳定版替代）。
//   - 频率限制：1 万次/分钟、50 万次/天。
//
// 错误响应为通用 errcode/errmsg 包封（getAccessToken 文档页错误码表，2026-06-11
// 拉取：-1 系统繁忙 / 40013 invalid appid / 40125 secret 错误 / 40164 IP 不在
// 白名单 / 40243 AppSecret 已冻结 等）。
const stableTokenPath = "/cgi-bin/stable_token"

// tokenSafetyMargin 缓存提前过期余量：官方普通模式会提前 5 分钟更新 token，
// 本地缓存比 expires_in 早 60s 失效即可平滑衔接。
const tokenSafetyMargin = 60 * time.Second

// tokenCache 内置 access_token 缓存（仅 Config.AccessTokenFunc 为 nil 时使用）。
type tokenCache struct {
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// stableTokenReq stable_token 请求体（字段名以官方文档为准，见 stableTokenPath 注释）。
type stableTokenReq struct {
	GrantType string `json:"grant_type"`
	AppID     string `json:"appid"`
	Secret    string `json:"secret"`
}

// stableTokenResp stable_token 应答（成功与错误字段平铺共存）。
type stableTokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`

	// 错误字段（微信通用包封）。
	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// accessToken 返回接口调用凭证：优先 Config.AccessTokenFunc，否则用内置
// stable_token 管理器（带本地缓存，提前 tokenSafetyMargin 刷新）。
func (w *WeChat) accessToken(ctx context.Context) (string, error) {
	if w.cfg.AccessTokenFunc != nil {
		return w.cfg.AccessTokenFunc(ctx)
	}

	w.token.mu.Lock()
	defer w.token.mu.Unlock()
	if w.token.token != "" && w.now().Before(w.token.expiresAt) {
		return w.token.token, nil
	}

	resp, err := w.hc.PostJSON(ctx, httpx.JoinURL(w.cfg.BaseURL, stableTokenPath), stableTokenReq{
		GrantType: "client_credential",
		AppID:     w.cfg.AppID,
		Secret:    w.cfg.AppSecret,
	}, nil)
	if err != nil {
		return "", errs.Wrap(PlatformName, opStableToken, err).WithRetryable(true)
	}
	var body stableTokenResp
	if err := resp.JSON(&body); err != nil {
		return "", errs.Wrap(PlatformName, opStableToken, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.ErrCode != 0 {
		return "", errs.New(PlatformName, opStableToken, strconv.FormatInt(body.ErrCode, 10), body.ErrMsg).
			WithHTTPStatus(resp.StatusCode).
			// -1 = system error 官方明确「稍候再试」；其余（appid/secret 错、IP
			// 白名单、Secret 冻结）是确定性失败。
			WithRetryable(body.ErrCode == -1 || retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return "", errs.New(PlatformName, opStableToken, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.AccessToken == "" || body.ExpiresIn <= 0 {
		return "", errs.New(PlatformName, opStableToken, "",
			"应答缺少 access_token / expires_in 字段: "+resp.SafeSummary()).
			WithHTTPStatus(resp.StatusCode)
	}

	w.token.token = body.AccessToken
	w.token.expiresAt = w.now().Add(time.Duration(body.ExpiresIn)*time.Second - tokenSafetyMargin)
	return body.AccessToken, nil
}

// invalidateToken 作废本地 token 缓存（业务接口返回 40001「access_token 无效或
// 不为最新」时调用，下次请求会重新获取）。Config.AccessTokenFunc 注入时无效果。
func (w *WeChat) invalidateToken() {
	if w.cfg.AccessTokenFunc != nil {
		return
	}
	w.token.mu.Lock()
	w.token.token = ""
	w.token.expiresAt = time.Time{}
	w.token.mu.Unlock()
}
