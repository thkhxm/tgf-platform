//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description tiktok：TikTok Mini Game 平台 SDK——实现 tgf/platform 合约的 Login + Payment + Webhook
//2026/6/11
//***************************************************

// Package tiktok 是 github.com/thkhxm/tgf/v2/platform 合约的 TikTok（Mini Game /
// Minis / Login Kit）平台实现。
//
// 本包所有 endpoint / 鉴权 / 字段 / 单位均以 2026-06-11 经本机代理直连
// developers.tiktok.com 拉取的官方文档正文为准，各调用点注释附文档 URL + 拉取日期。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 用客户端拿到的一次性授权 code 调
//     TikTok OAuth v2 token 接口（POST /v2/oauth/token/）换取 open_id /
//     access_token。Login Kit 与 TikTok Minis（小游戏 tt.login / TTMinis.game.login）
//     共用同一 endpoint，区别仅在 Minis 流程省略 redirect_uri（见 Config.RedirectURI）；
//     可选地再调 GET /v2/user/info/ 补取 union_id（Config.FetchUserInfo）。
//     文档：https://developers.tiktok.com/doc/minis-oauth 、
//     https://developers.tiktok.com/doc/minis-user-data（2026-06-11 拉取）。
//
//   - platform.PaymentProvider：VerifyPayment 调 Minis 查单接口
//     （POST /v2/minis/trade_order/query/）以平台应答判定支付状态——官方状态枚举
//     仅 PENDING / SUCCESS，Paid 仅当 SUCCESS。配套提供平台特有方法
//     CreateTradeOrder（POST /v2/minis/trade_order/create/，IAP 下单第一步）与
//     ParseWebhookEvent / TradeOrderContent（解析 minis.trade_order.redeem.success
//     等支付回调）。关键纪律（官方正文确认）：这两个接口鉴权用「付款用户的
//     OAuth access token」（act.* 前缀），不是应用 client token；token_amount
//     单位是平台虚拟币 Beans 的个数，不是法币最小单位。
//     文档：https://developers.tiktok.com/doc/minis-payment-apis 、
//     https://developers.tiktok.com/doc/mini-games-monetization（2026-06-11 拉取）。
//
//   - platform.WebhookVerifier：VerifyWebhook 校验 TikTok webhook 回调的
//     TikTok-Signature 签名（signed_payload = t + "." + 原始 body，HMAC-SHA256，
//     密钥 client_secret——拼接方式已经官方正文逐字确认），并按合约硬要求完成
//     时间戳窗口校验 + 防重放去重，读过的 Body 在返回前重置供业务 handler 再读。
//     文档：https://developers.tiktok.com/doc/webhooks-verification 、
//     https://developers.tiktok.com/doc/webhooks-overview（2026-06-11 拉取）。
//
// # 未实现的能力
//
// platform.ContentAuditProvider —— TikTok Minis Server API 套件（官方总览
// https://developers.tiktok.com/doc/minis-server-apis-overview ，2026-06-11 拉取）
// 只含 OAuth / User Data / Payment / Subscription 四类，无对第三方开放的内容
// 安全审核 server API，本包不实现（合约允许平台只实现其支持的子集）。
//
// 另有两个已有官方文档、但与合约无对应切面的支付辅助接口未封装（业务需要时
// 按 https://developers.tiktok.com/doc/minis-payment-apis 自行调用）：
// get_tier_infos（查询 Beans 充值档位）与 check_redeem_amounts（校验定价合规）。
//
// # IAP 全链路（官方流程）
//
// 文档：https://developers.tiktok.com/doc/mini-games-monetization（2026-06-11 拉取）：
//
//  1. 客户端 TTMinis.game.login 取 code → 服务端 VerifyLogin 换 open_id +
//     用户 access_token（act.*，须妥善保存并用 refresh_token 续期）；
//  2. 服务端 CreateTradeOrder（用户 token + Beans 数 + 业务订单号）→ trade_order_id；
//  3. 客户端 TTMinis.game.pay({trade_order_id})；
//  4. 支付成功后平台投递 minis.trade_order.redeem.success webhook ——
//     VerifyWebhook 验签 + ParseWebhookEvent / TradeOrderContent 解析 → 幂等发货
//     （官方明确发货以本 webhook 为准）；
//  5. 对账 / 补单：VerifyPayment（查单）确认 trade_order_status == SUCCESS。
//
// # 凭据
//
// Config.ClientKey / ClientSecret 即 TikTok 开发者后台的 Client key / Client secret，
// 由业务侧从 tgf 配置系统传入（config.Current().Platform.TiktokAppID = Client key、
// TiktokAppSecret = Client secret，Secret 已登记启动日志脱敏）。注意 TikTok 后台
// 另有一个数字 “App ID”，与 Client key 不是同一个东西——TiktokAppID 配置项应填
// Client key。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答，不打真实 TikTok API。真凭据端到端
// 验证（dev/沙箱环境换一次真 code、下一笔沙箱单、收一条真 webhook）留给持有
// 凭据的使用方执行；沙箱说明见 mini-games-monetization 文档（沙箱支付不扣
// Beans，支付成功后正常投递 webhook）。
package tiktok
