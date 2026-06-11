//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：getAccessToken——小游戏级 access_token 获取与进程内缓存
//2026/6/11
//***************************************************

package douyin

import (
	"context"
	"strconv"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
)

// 操作名（errs.Error.Op）。
const opGetAccessToken = "get_access_token"

// accessTokenPath getAccessToken 接口。
//
// 文档：https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/server/interface-request-credential/get-access-token
// （2026-06-11 curl 拉取正文）
//   - POST https://minigame.zijieapi.com/mgplatform/api/apps/v2/token
//   - 请求头：content-type: application/json（固定值，必填）
//   - 请求体（JSON）：appid（必填，小游戏 ID）/ secret（必填，APP Secret）/
//     grant_type（获取 access_token 时值为 client_credential）
//   - 成功应答：{"err_no":0,"err_tips":"success","data":{"access_token":"0801121***","expires_in":7200}}
//   - 错误码（HTTP 200 + err_no）：0 成功 / -1 系统错误 / 40015 appid 错误 /
//     40017 secret 错误 / 40020 grant_type 不是 client_credential
//   - token 是小游戏级 token（不要按用户分配），有效期 2 小时；重复获取会导致
//     上一次的 token 有效期缩短为 5 分钟——必须缓存复用，官方建议每小时更新一次。
const accessTokenPath = "/mgplatform/api/apps/v2/token"

// accessTokenResp 是 v2/token 接口的应答（字段名以官方文档为准，见 accessTokenPath 注释）。
type accessTokenResp struct {
	ErrNo   int64  `json:"err_no"`
	ErrTips string `json:"err_tips"`
	Data    struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	} `json:"data"`
}

// accessToken 返回缓存的小游戏 access_token；缓存缺失或临近过期
// （TokenRefreshMargin 余量内）时向平台重新获取。
//
// 缓存纪律（官方硬约束，见 accessTokenPath 注释）：重复获取会把上一个 token 的
// 有效期缩短为 5 分钟，所以绝不能每请求都取——本方法持锁串行刷新，并发调用方
// 共享同一次刷新结果。
func (d *Douyin) accessToken(ctx context.Context) (string, error) {
	d.tokenMu.Lock()
	defer d.tokenMu.Unlock()
	if d.token != "" && d.now().Add(d.cfg.TokenRefreshMargin).Before(d.tokenExpireAt) {
		return d.token, nil
	}

	body := map[string]string{
		"appid":      d.cfg.AppID,
		"secret":     d.cfg.AppSecret,
		"grant_type": "client_credential",
	}
	resp, err := d.hc.PostJSON(ctx, httpx.JoinURL(d.cfg.MinigameBaseURL, accessTokenPath), body, nil)
	if err != nil {
		// 传输层失败（网络错误/超时）——可重试。
		return "", errs.Wrap(PlatformName, opGetAccessToken, err).WithRetryable(true)
	}
	var tr accessTokenResp
	if err := resp.JSON(&tr); err != nil {
		return "", errs.Wrap(PlatformName, opGetAccessToken, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 平台业务错误（HTTP 200 + err_no 非 0，错误码表见 accessTokenPath 注释）。
	if tr.ErrNo != 0 {
		return "", errs.New(PlatformName, opGetAccessToken, strconv.FormatInt(tr.ErrNo, 10), tr.ErrTips).
			WithHTTPStatus(resp.StatusCode).
			// -1 系统错误属暂时性；40015/40017/40020 是确定性配置错误。
			WithRetryable(tr.ErrNo == -1 || retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return "", errs.New(PlatformName, opGetAccessToken, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if tr.Data.AccessToken == "" || tr.Data.ExpiresIn <= 0 {
		// 200 且 err_no==0 却缺关键字段——按官方文档这不该发生，视为协议异常。
		return "", errs.New(PlatformName, opGetAccessToken, "",
			"应答缺少 data.access_token / data.expires_in 字段: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}

	d.token = tr.Data.AccessToken
	d.tokenExpireAt = d.now().Add(time.Duration(tr.Data.ExpiresIn) * time.Second)
	return d.token, nil
}

// invalidateToken 作废缓存的 access_token（下游接口报 token 失效时调用，
// 下次取 token 时强制刷新）。
func (d *Douyin) invalidateToken() {
	d.tokenMu.Lock()
	d.token = ""
	d.tokenMu.Unlock()
}
