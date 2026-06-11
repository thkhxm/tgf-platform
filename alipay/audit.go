//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：ContentAuditProvider——alipay.security.risk.content.detect 文本风险检测
//2026/6/11
//***************************************************

package alipay

import (
	"context"
	"encoding/json"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const (
	opContentDetect = "content_detect"
	opAuditImage    = "audit_image"
)

// methodContentDetect 小程序内容风险检测服务 alipay.security.risk.content.detect。
//
// 文档：https://opendocs.alipay.com/apis/api_49/alipay.security.risk.content.detect
// （2026-06-11 经本机代理直连拉取正文核对）
//   - 统一网关 POST gateway.do，公共参数 + RSA2 签名（见 callGateway 注释）
//   - 业务参数走 biz_content（JSON 串）：content（必填，待识别文本，≤2000 字符；
//     官方注意事项：勿传入双引号等可能引起 JSON 格式化错误的特殊字符——本实现
//     经 json.Marshal 规范转义；官方「目前暂仅针对国家涉政风险文案进行拦截，
//     拦截规则将逐步升级」）
//   - 成功响应节点 alipay_security_risk_content_detect_response（code=10000）：
//     action（处置结果，REJECTED 拦截 / PASSED 放过——官方仅此两档）、
//     unique_id（业务唯一识别码，可用来对应异步识别结果）
//   - 适用范围官方注明「仅限于正在使用小程序的商户」
//   - 业务错误码：SYSTEM_ERROR（系统繁忙，可重试）/ INVALID_PARAMETER /
//     JSON_FORMAT_ERROR / PARAMETER_LENGTH_ERROR
const methodContentDetect = "alipay.security.risk.content.detect"

// action 官方枚举（仅两档，见 methodContentDetect 注释）。
const (
	actionPassed   = "PASSED"
	actionRejected = "REJECTED"
)

// contentDetectBiz content.detect 的 biz_content。
type contentDetectBiz struct {
	Content string `json:"content"`
}

// contentDetectResp content.detect 的业务响应节点。
type contentDetectResp struct {
	gatewayCommonResp
	Action   string `json:"action"`
	UniqueID string `json:"unique_id"`
}

// AuditText 实现 platform.ContentAuditProvider 的文本审核：调
// alipay.security.risk.content.detect，以平台应答的 action 判定。
//
// openID 参数被忽略——官方业务参数仅 content 一项，不接收发布者标识
// （与微信 msgSecCheck 要求 openid 不同）。
//
// 结果映射（官方仅 PASSED/REJECTED 两档，无「建议人工复核」档）：
//   - PASSED   → Pass=true,  Suggestion=SuggestionPass
//   - REJECTED → Pass=false, Suggestion=SuggestionReject
//   - 其他取值 → 协议异常，返回错误（宁可失败不可误放行）
//   - Labels 恒为空（官方响应无风险标签字段）；TraceID ← unique_id
func (a *Alipay) AuditText(ctx context.Context, openID, text string) (*platform.AuditResult, error) {
	_ = openID // 官方接口无发布者标识参数，见方法注释。
	if text == "" {
		return nil, errs.New(PlatformName, opContentDetect, "", "text 为空")
	}
	bizJSON, err := json.Marshal(contentDetectBiz{Content: text})
	if err != nil {
		return nil, errs.Wrap(PlatformName, opContentDetect, err)
	}
	node, status, err := a.callGateway(ctx, opContentDetect, methodContentDetect, map[string]string{
		"biz_content": string(bizJSON),
	})
	if err != nil {
		return nil, err
	}
	var body contentDetectResp
	if err := json.Unmarshal(node, &body); err != nil {
		return nil, errs.Wrap(PlatformName, opContentDetect, err).WithHTTPStatus(status)
	}
	if e := bizError(opContentDetect, status, body.gatewayCommonResp); e != nil {
		return nil, e
	}

	result := &platform.AuditResult{
		Platform: PlatformName,
		TraceID:  body.UniqueID,
		Raw: map[string]string{
			"action":    body.Action,
			"unique_id": body.UniqueID,
		},
	}
	switch body.Action {
	case actionPassed:
		result.Pass = true
		result.Suggestion = platform.SuggestionPass
	case actionRejected:
		result.Pass = false
		result.Suggestion = platform.SuggestionReject
	default:
		// 官方枚举仅两档——未知处置视为协议异常，宁可失败不可误放行。
		return nil, errs.New(PlatformName, opContentDetect, "",
			"未知 action: "+truncate(body.Action, 64)).
			WithHTTPStatus(status)
	}
	return result, nil
}

// AuditImage 实现 platform.ContentAuditProvider 的图片审核——支付宝开放平台
// 没有对第三方开放的图片内容风险检测 server API（NEEDS-DOC：2026-06-11 检索
// opendocs.alipay.com，alipay.security.risk.content.detect 业务参数仅 content
// 文本一项），本方法恒返回明确错误，绝不假装审核通过。若官方后续开放图片
// 检测接口，按其文档补实现。
func (a *Alipay) AuditImage(ctx context.Context, openID string, image []byte) (*platform.AuditResult, error) {
	return nil, errs.New(PlatformName, opAuditImage, "",
		"支付宝开放平台无图片内容风险检测 server API（2026-06-11 检索官方文档确认，"+
			"alipay.security.risk.content.detect 仅支持文本）——请改用其他审核渠道")
}
