//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description facebook：Facebook 平台 SDK——实现 tgf/platform 合约的 LoginProvider + PaymentProvider + WebhookVerifier
//2026/6/11
//***************************************************

// Package facebook 是 github.com/thkhxm/tgf/v2/platform 合约的 Facebook 平台实现。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 用客户端拿到的「用户 access token」调
//     Graph API /debug_token 校验（鉴权用 app access token 的 "app_id|app_secret"
//     形式 + appsecret_proof），核验 is_valid 且 app_id 归属本应用后取 user_id
//     （App-Scoped User ID）作 OpenID；可选地再调 /me 补取昵称（Config.FetchUserInfo）。
//   - platform.PaymentProvider：VerifyPayment 对 Instant Games（Facebook 小游戏）
//     purchaseAsync 返回的 signedRequest 做本地 HMAC-SHA256 验签（密钥 App Secret，
//     无需访问平台网络），核对 app_id / product_id / 金额 后判定 Paid，并按官方
//     文档识别 In-App Test Payment 的 mock 交易置 Sandbox。
//   - platform.WebhookVerifier：VerifyWebhook 校验 Graph API Webhooks 回调：
//     GET 订阅核验请求校验 hub.verify_token；POST 事件通知校验 X-Hub-Signature-256
//     （HMAC-SHA256，密钥 App Secret），并完成时间戳窗口（entry[].time，载荷
//     可得时）与防重放去重，读过的 Body 在返回前重置供业务 handler 再读。
//
// # 未实现的能力（NEEDS-DOC，绝不编造）
//
// platform.ContentAuditProvider —— 未检索到 Facebook 对第三方开放的、与微信
// security.msgSecCheck 同类的内容安全审核 server API（Meta 的内容审核体系不以
// 开放 API 形式提供给开发者调用），本包不实现（合约允许平台只实现其支持的子集）。
// 如用户能提供官方文档证明存在此类 API，再行补齐。
//
// # 凭据
//
// Config.AppID / AppSecret 即 Meta App Dashboard（Settings > Basic）的 App ID /
// App Secret，由业务侧从 tgf 配置系统传入（config.Current().Platform.FacebookAppID /
// FacebookAppSecret，Secret 已登记启动日志脱敏）。本包绝不直读环境变量、绝不落盘。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答 / 本地构造 signedRequest，不打真实
// Graph API。真凭据端到端验证（dev 环境换一次真 user token、用 In-App Test
// Payment 跑一笔 mock 购买、收一条真 webhook）留给持有凭据的使用方执行。
package facebook
