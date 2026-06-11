//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：ContentAuditProvider——gameMsgSecCheck 文本审核 + mediaCheckAsync 多媒体异步审核
//2026/6/11
//***************************************************

package wechat

import (
	"context"
	"errors"
	"net/url"
	"strconv"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const (
	opMsgSecCheck     = "msg_sec_check"
	opMediaCheckAsync = "media_check_async"
)

// ErrAuditImageUnsupported AuditImage 的哨兵错误：微信 2.0 内容安全不提供
// 「原始字节同步图片审核」（详见 AuditImage 注释），业务用
// errors.Is(err, wechat.ErrAuditImageUnsupported) 识别后改走 AuditMediaAsync。
var ErrAuditImageUnsupported = errors.New(
	"wechat: 微信不提供原始字节同步图片审核，请改用 AuditMediaAsync（URL + 消息推送异步结果）")

// msgSecCheckPath 小游戏专用文本内容安全识别（gameMsgSecCheck）。
//
// 文档：https://developers.weixin.qq.com/minigame/dev/api-backend/wxa-sec-check/api_gamemsgseccheck.html
// （2026-06-11 拉取；原 https://developers.weixin.qq.com/minigame/dev/api-backend/open-api/sec-check/security.msgSecCheck.html
// 已 301 至此——小游戏建议用本游戏专用接口而非小程序通用 msgSecCheck）
//   - POST https://api.weixin.qq.com/wxa/game/content_spam/msg_sec_check?access_token=ACCESS_TOKEN
//   - 请求体（JSON）：openid（必填，内容发布者）/ version（必填，固定 2）/
//     scene（必填，1 资料 2 评论 3 论坛 4 社交日志 5 聊天）/
//     content（必填，≤2500 字，UTF-8）/ nickname（可选）
//   - 响应：errcode / errmsg / trace_id / result{suggest, label, replaced_content}
//     / detail[]；suggest 取值 risky（拦截）、pass（通过）（官方正文措辞为
//     「三种值」但仅列出这两种，疑笔误——本实现对 review 与未知值统一保守归
//     SuggestionReview）
//   - result.label 枚举：100 正常 / 10001 营销广告 / 20001 时政 / 20002 色情 /
//     20003 辱骂 / 20006 违法犯罪 / 20012 低俗 / 21000 其他
//   - 错误码：0 成功 / 40001 access_token 无效 / 40003 openid 非法 / 40129
//     场景值错误 / 43104 appid 与 openid 不匹配 / 44002 包体为空 / 47001 JSON
//     解析错误 / 750030 版本号错误 / 750031 游戏未配置 / 750032 分钟级限频 /
//     750033 当日限额
//   - 官方建议超时设 1s 以上（接口同步返回，一般耗时 500ms 内）
const msgSecCheckPath = "/wxa/game/content_spam/msg_sec_check"

// mediaCheckAsyncPath 多媒体内容安全识别 2.0（异步）。
//
// 文档：https://developers.weixin.qq.com/minigame/dev/api-backend/wxa-sec-check/api_mediacheckasync.html
// （2026-06-11 拉取）
//   - POST https://api.weixin.qq.com/wxa/media_check_async?access_token=ACCESS_TOKEN
//   - 请求体（JSON）：media_url（必填，可被检测服务器下载的图片/音频 URL；
//     图片 jpg/jpeg/png/bmp/gif 取首帧，音频 mp3/aac/ac3/wma/flac/vorbis/opus/wav）/
//     media_type（必填，1 音频 2 图片）/ version（必填，固定 2）/
//     scene（必填，1 资料 2 评论 3 论坛 4 社交日志——无聊天场景）/
//     openid（必填，且用户需在近两小时访问过小程序）
//   - 同步响应仅 errcode / errmsg / trace_id；检测结果 30 分钟内以
//     Event=wxa_media_check 经消息推送送达（用 VerifyWebhook 验签 +
//     ParseMediaCheckEvent 解析）
//   - 1.0 同步接口已于 2021-09-01 停止更新（官方原文），故本包不提供字节流
//     同步审核——这正是 AuditImage 恒返回 ErrAuditImageUnsupported 的原因
//   - 频率限制：2000 次/分钟、20 万次/天；单文件 ≤10M
const mediaCheckAsyncPath = "/wxa/media_check_async"

// MediaCheckEventName mediaCheckAsync 异步结果推送的事件名（Event 字段取值，
// 文档见 mediaCheckAsyncPath 注释）。
const MediaCheckEventName = "wxa_media_check"

// 多媒体类型枚举（media_check_async Body.media_type，文档同上）。
const (
	MediaTypeAudio = 1 // 音频
	MediaTypeImage = 2 // 图片
)

// auditLabelNames result.label 枚举 → 可读名（官方枚举表，见 msgSecCheckPath
// 注释；mediaCheckAsync 的 label 枚举是其子集）。
var auditLabelNames = map[int]string{
	100:   "正常",
	10001: "营销广告",
	20001: "时政",
	20002: "色情",
	20003: "辱骂",
	20006: "违法犯罪",
	20012: "低俗",
	21000: "其他",
}

// msgSecCheckReq gameMsgSecCheck 请求体（字段名以官方文档为准）。
type msgSecCheckReq struct {
	OpenID  string `json:"openid"`
	Version int    `json:"version"`
	Scene   int    `json:"scene"`
	Content string `json:"content"`
}

// auditResultBody 审核综合结果（gameMsgSecCheck result 字段）。
type auditResultBody struct {
	Suggest         string `json:"suggest"`
	Label           int    `json:"label"`
	ReplacedContent string `json:"replaced_content"`
}

// msgSecCheckResp gameMsgSecCheck 应答。
type msgSecCheckResp struct {
	ErrCode int64           `json:"errcode"`
	ErrMsg  string          `json:"errmsg"`
	TraceID string          `json:"trace_id"`
	Result  auditResultBody `json:"result"`
}

// AuditText 实现 platform.ContentAuditProvider 的文本审核：调小游戏专用
// gameMsgSecCheck（协议见 msgSecCheckPath 注释），场景取 Config.AuditScene。
//
// suggest → 标准化建议的映射：
//   - "pass"  → SuggestionPass（Pass=true）
//   - "risky" → SuggestionReject（官方语义「拦截」）
//   - "review" 及未知值 → SuggestionReview（保守处理：官方正文只列 pass/risky
//     两种，未知值绝不放行，也不武断判违规）
func (w *WeChat) AuditText(ctx context.Context, openID, text string) (*platform.AuditResult, error) {
	if openID == "" {
		return nil, errs.New(PlatformName, opMsgSecCheck, "", "openid 为空（官方必填，内容发布者标识）")
	}
	if text == "" {
		return nil, errs.New(PlatformName, opMsgSecCheck, "", "待审核文本为空")
	}

	token, err := w.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	query := url.Values{"access_token": {token}}
	target, err := mergeQueryURL(httpx.JoinURL(w.cfg.BaseURL, msgSecCheckPath), query)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opMsgSecCheck, err)
	}
	resp, err := w.hc.PostJSON(ctx, target, msgSecCheckReq{
		OpenID:  openID,
		Version: 2, // 官方固定值 2
		Scene:   w.cfg.AuditScene,
		Content: text,
	}, nil)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opMsgSecCheck, err).WithRetryable(true)
	}

	var body msgSecCheckResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, opMsgSecCheck, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.ErrCode != 0 {
		return nil, w.platformErr(opMsgSecCheck, body.ErrCode, body.ErrMsg, resp.StatusCode)
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, opMsgSecCheck, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.Result.Suggest == "" {
		return nil, errs.New(PlatformName, opMsgSecCheck, "",
			"应答缺少 result.suggest 字段: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}

	return buildAuditResult(body.Result, body.TraceID), nil
}

// AuditImage 实现 platform.ContentAuditProvider 的图片审核——**微信不支持此
// 调用形态**，恒返回携带 ErrAuditImageUnsupported 的错误：
//
// 微信 2.0 内容安全只提供 mediaCheckAsync（提交可下载 URL，结果 30 分钟内经
// 消息推送异步返回），不提供「原始字节同步审核」；1.0 同步接口官方已于
// 2021-09-01 停止更新（文档见 mediaCheckAsyncPath 注释）。按工程纪律
// （全局规则 §2.11）不用已废弃接口将就实现。
//
// 替代链路：AuditMediaAsync 提交检测 → VerifyWebhook 验签结果推送 →
// ParseMediaCheckEvent + MediaCheckEvent.ToAuditResult 得到标准化结果。
func (w *WeChat) AuditImage(_ context.Context, _ string, _ []byte) (*platform.AuditResult, error) {
	return nil, errs.New(PlatformName, opMediaCheckAsync, "",
		"微信 2.0 内容安全仅支持 URL+异步推送形态（1.0 同步接口已于 2021-09-01 停止更新），"+
			"请改用 AuditMediaAsync + VerifyWebhook + ParseMediaCheckEvent").
		WithCause(ErrAuditImageUnsupported)
}

// mediaCheckAsyncReq media_check_async 请求体（字段名以官方文档为准）。
type mediaCheckAsyncReq struct {
	MediaURL  string `json:"media_url"`
	MediaType int    `json:"media_type"`
	Version   int    `json:"version"`
	Scene     int    `json:"scene"`
	OpenID    string `json:"openid"`
}

// mediaCheckAsyncResp media_check_async 同步应答。
type mediaCheckAsyncResp struct {
	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
	TraceID string `json:"trace_id"`
}

// AuditMediaAsync 提交图片/音频异步内容安全检测（协议见 mediaCheckAsyncPath
// 注释），返回 trace_id 供与异步结果推送（MediaCheckEvent.TraceID）匹配。
//
//   - mediaURL：可被微信检测服务器下载的资源 URL（业务需先把待审字节上传到
//     自有可公网访问的存储）；
//   - mediaType：MediaTypeAudio（1）/ MediaTypeImage（2）；
//   - scene：1 资料 / 2 评论 / 3 论坛 / 4 社交日志（注意无聊天场景，与
//     msgSecCheck 枚举不同）；
//   - openID：官方要求该用户需在近两小时内访问过小程序。
func (w *WeChat) AuditMediaAsync(ctx context.Context, openID, mediaURL string, mediaType, scene int) (string, error) {
	if openID == "" {
		return "", errs.New(PlatformName, opMediaCheckAsync, "", "openid 为空（官方必填，且需近两小时访问过小程序）")
	}
	if mediaURL == "" {
		return "", errs.New(PlatformName, opMediaCheckAsync, "", "media_url 为空")
	}
	if mediaType != MediaTypeAudio && mediaType != MediaTypeImage {
		return "", errs.New(PlatformName, opMediaCheckAsync, "", "media_type 非法（官方枚举：1 音频 / 2 图片）")
	}
	if scene < SceneProfile || scene > SceneSocialLog {
		return "", errs.New(PlatformName, opMediaCheckAsync, "", "scene 非法（官方枚举：1 资料 / 2 评论 / 3 论坛 / 4 社交日志）")
	}

	token, err := w.accessToken(ctx)
	if err != nil {
		return "", err
	}
	query := url.Values{"access_token": {token}}
	target, err := mergeQueryURL(httpx.JoinURL(w.cfg.BaseURL, mediaCheckAsyncPath), query)
	if err != nil {
		return "", errs.Wrap(PlatformName, opMediaCheckAsync, err)
	}
	resp, err := w.hc.PostJSON(ctx, target, mediaCheckAsyncReq{
		MediaURL:  mediaURL,
		MediaType: mediaType,
		Version:   2, // 官方固定值 2
		Scene:     scene,
		OpenID:    openID,
	}, nil)
	if err != nil {
		return "", errs.Wrap(PlatformName, opMediaCheckAsync, err).WithRetryable(true)
	}

	var body mediaCheckAsyncResp
	if err := resp.JSON(&body); err != nil {
		return "", errs.Wrap(PlatformName, opMediaCheckAsync, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.ErrCode != 0 {
		return "", w.platformErr(opMediaCheckAsync, body.ErrCode, body.ErrMsg, resp.StatusCode)
	}
	if !resp.OK() {
		return "", errs.New(PlatformName, opMediaCheckAsync, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if body.TraceID == "" {
		return "", errs.New(PlatformName, opMediaCheckAsync, "",
			"应答缺少 trace_id 字段: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode)
	}
	return body.TraceID, nil
}

// MediaCheckEvent 是 mediaCheckAsync 异步检测结果推送的消息体（JSON 数据格式；
// 字段名以官方文档为准，见 mediaCheckAsyncPath 注释——「异步检测结果推送」节）。
// 业务在 VerifyWebhook 验签通过后用 ParseMediaCheckEvent 解析（安全模式需先
// DecryptWebhookEvent 解出明文）。
type MediaCheckEvent struct {
	ToUserName   string `json:"ToUserName"`   // 小程序 username
	FromUserName string `json:"FromUserName"` // 平台推送服务 UserName
	CreateTime   int64  `json:"CreateTime"`   // 发送时间（Unix 秒）
	MsgType      string `json:"MsgType"`      // 固定 "event"
	Event        string `json:"Event"`        // 固定 "wxa_media_check"
	AppID        string `json:"appid"`        // 小程序 appid
	TraceID      string `json:"trace_id"`     // 任务 id（与 AuditMediaAsync 返回值匹配）
	Version      int    `json:"version"`      // 接口版本
	// ErrCode 仅当为 0 时结果有效；-1008 表示媒体下载失败（检查 media_url）。
	ErrCode int64           `json:"errcode"`
	ErrMsg  string          `json:"errmsg"`
	Result  auditResultBody `json:"result"` // 综合结果（suggest/label）
}

// ParseMediaCheckEvent 解析异步检测结果推送的明文 JSON。Event 不是
// wxa_media_check 或 errcode 非 0（结果无效）时返回错误。
func ParseMediaCheckEvent(data []byte) (*MediaCheckEvent, error) {
	var ev MediaCheckEvent
	if err := httpx.DecodeJSON(data, &ev); err != nil {
		return nil, errs.Wrap(PlatformName, opMediaCheckAsync, err)
	}
	if ev.Event != MediaCheckEventName {
		return nil, errs.New(PlatformName, opMediaCheckAsync, "",
			"非 "+MediaCheckEventName+" 事件: Event="+truncate(ev.Event, 64))
	}
	if ev.ErrCode != 0 {
		// 官方：errcode 仅当为 0 时结果有效；-1008 下载错误。
		return nil, errs.New(PlatformName, opMediaCheckAsync,
			strconv.FormatInt(ev.ErrCode, 10), "异步检测结果无效: "+ev.ErrMsg)
	}
	return &ev, nil
}

// ToAuditResult 把异步检测结果映射为标准化审核结果（映射规则同 AuditText）。
func (ev *MediaCheckEvent) ToAuditResult() *platform.AuditResult {
	return buildAuditResult(ev.Result, ev.TraceID)
}

// buildAuditResult 把官方 result 结构映射为标准化审核结果。
func buildAuditResult(r auditResultBody, traceID string) *platform.AuditResult {
	out := &platform.AuditResult{
		Platform: PlatformName,
		TraceID:  traceID,
		Raw: map[string]string{
			"suggest": r.Suggest,
			"label":   strconv.Itoa(r.Label),
		},
	}
	if r.ReplacedContent != "" {
		out.Raw["replaced_content"] = r.ReplacedContent
	}
	switch r.Suggest {
	case "pass":
		out.Pass = true
		out.Suggestion = platform.SuggestionPass
	case "risky":
		out.Suggestion = platform.SuggestionReject
	default:
		// "review" 及未知取值：保守归待人工复核（绝不放行，也不武断判违规）。
		out.Suggestion = platform.SuggestionReview
	}
	// 命中标签（100=正常不算命中）：格式 "码:可读名"，未知码只透传数字。
	if r.Label != 0 && r.Label != 100 {
		label := strconv.Itoa(r.Label)
		if name, ok := auditLabelNames[r.Label]; ok {
			label += ":" + name
		}
		out.Labels = []string{label}
	}
	return out
}

// platformErr 把微信通用 errcode 包封映射为平台错误并完成可重试分类：
//   - -1（系统繁忙，官方「稍候再试」）、750032（分钟级限频）→ 可重试；
//   - 40001（access_token 无效或不为最新）→ 作废本地 token 缓存后可重试
//     （重取新 token 后重试有意义）；
//   - 其余（参数/凭据/配额日上限）→ 确定性失败。
func (w *WeChat) platformErr(op string, errCode int64, errMsg string, httpStatus int) *errs.Error {
	retryable := errCode == -1 || errCode == 750032 || retryableStatus(httpStatus)
	if errCode == 40001 {
		w.invalidateToken()
		retryable = true
	}
	return errs.New(PlatformName, op, strconv.FormatInt(errCode, 10), errMsg).
		WithHTTPStatus(httpStatus).
		WithRetryable(retryable)
}

// mergeQueryURL 把查询参数拼到 URL 上（access_token 等放 query string，
// 与官方「HTTPS 调用」形态一致）。
func mergeQueryURL(rawURL string, query url.Values) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, vs := range query {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
