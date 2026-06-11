//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：TikTok 平台 SDK——实现 tgf/platform 合约的 LoginProvider + WebhookVerifier
//2026/6/11
//***************************************************

// Package tiktok 是 github.com/thkhxm/tgf/v2/platform 合约的 TikTok 平台实现。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 用客户端拿到的一次性授权 code 调
//     TikTok OAuth v2 token 接口换取 open_id / access_token（Login Kit 与
//     TikTok Minis（小游戏）共用同一 endpoint，区别仅在是否携带 redirect_uri，
//     见 Config.RedirectURI）；可选地再调 user/info 取 union_id（Config.FetchUserInfo）。
//   - platform.WebhookVerifier：VerifyWebhook 校验 TikTok webhook 回调的
//     TikTok-Signature 签名（HMAC-SHA256，密钥 client_secret），并按合约硬要求
//     完成时间戳窗口校验 + 防重放去重，读过的 Body 在返回前重置供业务 handler 再读。
//
// # 未实现的能力（NEEDS-DOC，绝不编造）
//
// platform.PaymentProvider —— TikTok Minis 存在服务端支付 API（官方文档
// https://developers.tiktok.com/doc/minis-payment-apis ，2026-06-11 检索）：
//
//   - POST https://open.tiktokapis.com/v2/minis/trade_order/create/
//     （已确认字段：token_type / token_amount / order_info{order_id, product_name}）
//   - POST https://open.tiktokapis.com/v2/minis/trade_order/query/
//     （请求 {"trade_order_id": "..."}；响应 data{trade_order_id, trade_order_status}）
//
// 但 developers.tiktok.com 拒绝本环境直连抓取，经搜索引擎仅能确认上述片段，
// 以下关键细节**无法从官方文档完整取得**，按工程纪律（设计文档第四节 / 全局规则
// §2.8 §2.11）不凭猜测实现 VerifyPayment，标记 NEEDS-DOC：
//
//  1. trade_order_status 的完整枚举，以及「支付成功 / 已核销」对应的取值
//     （目前仅确认存在 "PENDING"）——把未知状态硬映射成 Paid 真/假都是将就实现；
//  2. trade_order 接口 Authorization Bearer 所要求的 token 种类——用户 access token
//     （act.*）还是 client access token（历史在 TikTok IAP 上吃过 token 种类用错的亏，
//     绝不猜）；
//  3. trade_order/create 完整字段表与 token_amount 的单位语义。
//
// 需要用户提供：developers.tiktok.com/doc/minis-payment-apis 页面完整内容
// （登录开发者后台可见），或一组官方 sample request/response。
//
// 另：官方明确（https://developers.tiktok.com/doc/mini-games-monetization ，
// 2026-06-11 检索）发放虚拟商品**必须**以 minis.trade_order.redeem.success
// 服务端 webhook 为准——该回调的验签已由本包 VerifyWebhook 覆盖，业务可先走
// 「verified webhook → 发货」链路，不阻塞接入。
//
// platform.ContentAuditProvider —— 未检索到 TikTok 对第三方开放的内容安全审核
// server API，本包不实现（合约允许平台只实现其支持的子集）。
//
// # 凭据
//
// Config.ClientKey / ClientSecret 即 TikTok 开发者后台的 Client key / Client secret，
// 由业务侧从 tgf 配置系统传入（config.Current().Platform.TiktokAppID /
// TiktokAppSecret，Secret 已登记启动日志脱敏）。注意 TikTok 后台另有一个数字
// “App ID”，与 Client key 不是同一个东西——TiktokAppID 配置项应填 Client key。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答，不打真实 TikTok API。真凭据端到端
// 验证（dev 环境换一次真 code、收一条真 webhook）留给持有凭据的使用方执行。
package tiktok
