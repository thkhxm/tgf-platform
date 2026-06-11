//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description line：LINE 平台 SDK——实现 tgf/platform 合约的 LoginProvider + WebhookVerifier
//2026/6/11
//***************************************************

// Package line 是 github.com/thkhxm/tgf/v2/platform 合约的 LINE 平台实现。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 把客户端（LINE SDK / LIFF 的
//     liff.getIDToken()）拿到的 ID token 提交到 LINE 官方校验接口
//     POST https://api.line.me/oauth2/v2.1/verify 做服务端校验
//     （官方文档：https://developers.line.biz/en/reference/line-login/#verify-id-token ，
//     2026-06-11 拉取），取 payload 的 sub 作为 OpenID。
//   - platform.WebhookVerifier：VerifyWebhook 校验 LINE Messaging API webhook
//     回调的 x-line-signature 签名（base64(HMAC-SHA256(channel secret, body))），
//     并按合约硬要求完成事件时间戳窗口校验 + 防重放去重，读过的 Body 在返回前
//     重置供业务 handler 再读。
//
// # 设计取舍：服务端校验走官方 verify 接口，不做本地 JWKS 验签
//
// LINE 官方文档（https://developers.line.biz/en/docs/line-login/verify-id-token/ ，
// 2026-06-11 拉取）给出两条等价路径：自行写验证代码（HS256 用 channel secret、
// ES256 拉 JWK 公钥）或直接调用官方 verify 接口。本实现选官方接口——平台侧
// 完成签名 / iss / exp / aud（与 client_id 比对）/ nonce / user_id 全套校验，
// 协议演进永远与平台同步，且无需在本地区分 HS256（web login）与 ES256
// （native app / LIFF）两种签名形态。
//
// # 未实现的能力（NEEDS-DOC，绝不编造）
//
// platform.PaymentProvider —— LINE 生态的支付是独立商户产品 LINE Pay
// （文档站 pay.line.me，需商户签约后获取独立的 LINE Pay ChannelId / ChannelSecret，
// 与 LINE Login / Messaging API 的 channel 凭据不是同一体系）。本环境未能抓到
// LINE Pay v3 API（Request/Confirm/Capture 等）的官方文档正文，按工程纪律
// （全局规则 §2.8 / §2.11）不凭记忆实现，标记 NEEDS-DOC。需要用户提供：
// LINE Pay 商户后台可见的 v3 API 官方文档页或官方 sample request/response。
//
// platform.ContentAuditProvider —— 未检索到 LINE 对第三方开放的内容安全审核
// server API，本包不实现（合约允许平台只实现其支持的子集）。
//
// # 凭据与 channel 类型（重要，别拿错）
//
// LINE 的「channel」分多种类型，凭据各自独立：
//
//   - LINE Login channel：Config.ChannelID 填它的 Channel ID——即 verify 接口
//     的 client_id（官方文档原文 "Expected channel ID. Unique identifier for
//     your channel issued by the LINE Platform. Found in the LINE Developers
//     Console."）；
//   - Messaging API channel：Config.ChannelSecret 填它的 Channel secret——
//     webhook 验签的 HMAC 密钥。若登录与 webhook 用的是不同 channel，两个字段
//     分别取各自 channel 的值。
//
// 对接 tgf 配置系统的命名约定：config.Current().Platform.LineChannelID /
// LineChannelSecret（tgf 侧字段待登记；Secret 类字段须登记 sensitiveEnvKeys
// 启动日志脱敏）。本包绝不直读环境变量、绝不落盘。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答，不打真实 LINE API（verify 接口的
// 错误响应字段结构 {"error","error_description"} 已于 2026-06-11 对真实
// endpoint https://api.line.me/oauth2/v2.1/verify 发送非法 id_token 实测核对，
// HTTP 400 + {"error":"invalid_request","error_description":"JWS format error"}）。
// 真凭据端到端验证（dev 环境用真 ID token 验一次、收一条真 webhook）留给持有
// 凭据的使用方执行。
package line
