//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：ContentAuditProvider——文本 antidirt / 图片链接检测
//2026/6/11
//***************************************************

package douyin

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/httpx"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const (
	opAuditText  = "audit_text"
	opAuditImage = "audit_image"
)

// ErrImageBytesUnsupported AuditImage 的 []byte 入参在抖音平台不受支持。
// 抖音图片检测接口只接受图片 URL（官方文档 image 字段为「检测的图片链接」，
// 见 auditImagePath 注释），平台未提供以二进制提交图片的检测通道——
// 请改用扩展方法 AuditImageURL(ctx, openID, imageURL)。
var ErrImageBytesUnsupported = errors.New(
	"douyin: 图片检测仅支持图片 URL，不支持图片字节——请使用 AuditImageURL")

// endpoint 路径。
const (
	// auditTextPath 文本内容安全检测接口。
	//
	// 文档：https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/server/content-safety/content-safety-check
	// （2026-06-11 curl 拉取正文）
	//   - POST https://developer.toutiao.com/api/v2/tags/text/antidirt
	//   - 请求头：content-type: application/json（固定值，必填）/
	//     X-Token（必填，调 https://minigame.zijieapi.com/mgplatform/api/apps/v2/token
	//     生成的 token，见 token.go）
	//   - 请求体：{"tasks":[{"content":"要检测的文本"}]}（content：检测的文本内容）
	//   - 应答：{"log_id":"...","data":[{"code":0,"task_id":"...","data_id":null,
	//     "cached":false,"predicts":[{"prob":1,"model_name":"antidirt","target":"default"}],
	//     "msg":"ok"}]}；错误时返回 code / error_id / exception / message
	//   - predicts 字段语义（官方字段描述）：prob——概率，值为 0 或者 1，当值为 1 时
	//     表示检测的文本包含违法违规内容；hit——是否命中；target——服务/目标；
	//     model_name——模型/标签
	//   - 错误码（HTTP 200 + code）：0 成功 / 401 AccessToken 失效或为空 /
	//     400 tasks 数组为空
	auditTextPath = "/api/v2/tags/text/antidirt"

	// auditImagePath 图片检测接口。
	//
	// 文档：https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/server/content-safety/image-detection
	// （2026-06-11 curl 拉取正文）
	//   - POST https://developer.toutiao.com/api/v2/tags/image
	//   - 请求头：content-type: application/json（固定值，必填）/ X-Token（同上）
	//   - 请求体：{"targets":["ad","porn"],"tasks":[{"image":"<图片 URL>"}]}
	//     （image：检测的图片链接；targets：检测目标）
	//   - 应答结构同文本检测；官方示例的 predicts 含
	//     {"prob":1,"model_name":"image_ocr","target":"ad"} 与小数 prob
	//     （0.0005...，model_name image_porn）等
	//   - 错误码（HTTP 200 + code）：0 成功 / 401 AccessToken 失效或者为空 /
	//     400 Tasks 或者 Target 不能为空
	//
	// NEEDS-DOC：图片检测 prob 的字段描述沿用文本检测的「值为 0 或者 1」，但官方
	// 示例出现小数 prob 且未给出判违规阈值——本包按「hit==true 或 prob>=1 即违规」
	// 判定，小数 prob 不判违规、原样透传 Raw（见 doc.go NEEDS-DOC 第 3 条）。
	auditImagePath = "/api/v2/tags/image"
)

// defaultImageTargets 图片检测默认的检测目标（官方请求示例值：广告 + 色情）。
var defaultImageTargets = []string{"ad", "porn"}

// auditResp 是内容安全检测接口的应答（文本/图片同构，字段名以官方文档为准，
// 见 auditTextPath / auditImagePath 注释）。
type auditResp struct {
	LogID string `json:"log_id"`
	Data  []struct {
		Code     int64  `json:"code"`
		TaskID   string `json:"task_id"`
		Msg      string `json:"msg"`
		Predicts []struct {
			Prob      float64 `json:"prob"`
			ModelName string  `json:"model_name"`
			Target    string  `json:"target"`
			Hit       bool    `json:"hit"`
		} `json:"predicts"`
	} `json:"data"`

	// 错误字段（错误时返回）。
	Code      int64  `json:"code"`
	ErrorID   string `json:"error_id"`
	Exception string `json:"exception"`
	Message   string `json:"message"`
}

// AuditText 实现 platform.ContentAuditProvider 的文本检测。
//
// openID 为内容发布者的平台用户标识——抖音文本检测接口不接收用户标识，该参数
// 仅为满足合约签名，实现内不使用（与微信 msgSecCheck 要求 openid 不同）。
//
// 判定映射（predicts 语义见 auditTextPath 注释）：任一 predict 的 hit==true 或
// prob>=1 即违规 → Suggestion=SuggestionReject；否则 SuggestionPass。抖音该接口
// 无「建议人工复核」档位，不产生 SuggestionReview。
func (d *Douyin) AuditText(ctx context.Context, openID, text string) (*platform.AuditResult, error) {
	if text == "" {
		return nil, errs.New(PlatformName, opAuditText, "", "text 为空")
	}
	payload := map[string]any{
		"tasks": []map[string]string{{"content": text}},
	}
	return d.audit(ctx, opAuditText, auditTextPath, payload)
}

// AuditImage 实现 platform.ContentAuditProvider 的图片检测——但抖音平台不支持
// 图片字节入参（接口只接受图片 URL，见 ErrImageBytesUnsupported），本方法恒返回
// 携带 ErrImageBytesUnsupported 的错误。请改用 AuditImageURL。
func (d *Douyin) AuditImage(ctx context.Context, openID string, image []byte) (*platform.AuditResult, error) {
	return nil, errs.New(PlatformName, opAuditImage, "",
		"抖音图片检测仅支持图片 URL（官方文档 image 字段为「检测的图片链接」），请使用 AuditImageURL").
		WithCause(ErrImageBytesUnsupported)
}

// AuditImageURL 图片检测（平台扩展能力，不属于合约接口）。
//
// imageURL 是待检测图片的可公网访问链接（官方请求示例即外链 URL）；
// targets 是检测目标，空则用官方示例的默认值 ["ad","porn"]。
// openID 同 AuditText，仅为风格统一，实现内不使用。
// 判定映射同 AuditText（图片小数 prob 的处理见 auditImagePath 注释的 NEEDS-DOC）。
func (d *Douyin) AuditImageURL(ctx context.Context, openID, imageURL string, targets ...string) (*platform.AuditResult, error) {
	if imageURL == "" {
		return nil, errs.New(PlatformName, opAuditImage, "", "imageURL 为空")
	}
	if len(targets) == 0 {
		targets = defaultImageTargets
	}
	payload := map[string]any{
		"targets": targets,
		"tasks":   []map[string]string{{"image": imageURL}},
	}
	return d.audit(ctx, opAuditImage, auditImagePath, payload)
}

// audit 调内容安全检测接口并把应答归一为 *platform.AuditResult
// （endpoint 协议见 auditTextPath / auditImagePath 注释）。
func (d *Douyin) audit(ctx context.Context, op, path string, payload map[string]any) (*platform.AuditResult, error) {
	token, err := d.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set("X-Token", token)

	resp, err := d.hc.PostJSON(ctx, httpx.JoinURL(d.cfg.ToutiaoBaseURL, path), payload, header)
	if err != nil {
		// 传输层失败——检测接口幂等，可安全重试。
		return nil, errs.Wrap(PlatformName, op, err).WithRetryable(true)
	}
	var body auditResp
	if err := resp.JSON(&body); err != nil {
		return nil, errs.Wrap(PlatformName, op, err).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	// 顶层错误（HTTP 200 + code 非 0：401 token 失效 / 400 参数空，见错误码表）。
	if len(body.Data) == 0 {
		if body.Code != 0 || body.Message != "" || body.Exception != "" {
			if body.Code == 401 {
				// token 失效：作废缓存，下次强制刷新。
				d.invalidateToken()
			}
			msg := body.Message
			if msg == "" {
				msg = body.Exception
			}
			if body.ErrorID != "" {
				msg += " (error_id=" + body.ErrorID + ")"
			}
			return nil, errs.New(PlatformName, op, strconv.FormatInt(body.Code, 10), msg).
				WithHTTPStatus(resp.StatusCode).
				// 401 token 失效刷新后可重试。
				WithRetryable(body.Code == 401 || retryableStatus(resp.StatusCode))
		}
		return nil, errs.New(PlatformName, op,
			"", "应答缺少 data 检测结果: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}
	if !resp.OK() {
		return nil, errs.New(PlatformName, op, strconv.Itoa(resp.StatusCode),
			"HTTP 状态异常: "+truncate(resp.String(), 256)).
			WithHTTPStatus(resp.StatusCode).
			WithRetryable(retryableStatus(resp.StatusCode))
	}

	// 单任务提交，取第一条检测结果；task 级 code 非 0 视为该任务检测失败。
	task := body.Data[0]
	if task.Code != 0 {
		return nil, errs.New(PlatformName, op, strconv.FormatInt(task.Code, 10),
			"检测任务失败: "+task.Msg+" (log_id="+body.LogID+")").
			WithHTTPStatus(resp.StatusCode)
	}

	// 判定：任一 predict 的 hit==true 或 prob>=1 即违规（语义见 endpoint 注释；
	// 图片小数 prob 的处理纪律见 NEEDS-DOC）。命中标签 = "model_name/target"。
	var labels []string
	raw := map[string]string{"task_id": task.TaskID, "msg": task.Msg}
	for _, p := range task.Predicts {
		raw[p.ModelName+"/"+p.Target] = strconv.FormatFloat(p.Prob, 'f', -1, 64)
		if p.Hit || p.Prob >= 1 {
			labels = append(labels, p.ModelName+"/"+p.Target)
		}
	}
	pass := len(labels) == 0
	suggestion := platform.SuggestionPass
	if !pass {
		// 抖音该接口无「建议人工复核」档位：命中即拦截。
		suggestion = platform.SuggestionReject
	}
	return &platform.AuditResult{
		Platform:   PlatformName,
		Pass:       pass,
		Suggestion: suggestion,
		Labels:     labels,
		TraceID:    body.LogID,
		Raw:        raw,
	}, nil
}
