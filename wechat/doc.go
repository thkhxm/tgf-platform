//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：微信小游戏平台 SDK——实现 tgf/platform 合约的 Login + Payment + Audit + Webhook
//2026/6/11
//***************************************************

// Package wechat 是 github.com/thkhxm/tgf/v2/platform 合约的微信小游戏平台实现。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 用客户端 wx.login 拿到的一次性 code 调
//     jscode2session 换取 openid / session_key / unionid。
//     文档：https://developers.weixin.qq.com/minigame/dev/api-backend/login/api_code2session.html
//     （2026-06-11 拉取；原 open-api/login/auth.code2Session.html 已 301 至此）。
//   - platform.PaymentProvider：VerifyPayment 调米大师虚拟支付「查询订单状态」
//     （pay_v2.queryOrder）以服务端应答判定订单是否已支付。
//     文档：https://developers.weixin.qq.com/minigame/dev/api-backend/midas-payment/order/api_pay_v2.queryorder.html
//     （2026-06-11 拉取）。注意：该接口**不返回金额与币种**（响应字段表只有
//     errcode/errmsg/product_id/pay_state/deliver_state/pay_finish_time/
//     out_trade_no/mch_order_no/transaction_id），故 PaymentResult.Amount 恒为 0、
//     Currency 恒为空——业务发货前须按 product_id 对照后台商品配置自行核对金额。
//   - platform.ContentAuditProvider：
//     AuditText 调小游戏专用文本审核 gameMsgSecCheck。
//     文档：https://developers.weixin.qq.com/minigame/dev/api-backend/wxa-sec-check/api_gamemsgseccheck.html
//     （2026-06-11 拉取；原 sec-check/security.msgSecCheck.html 已 301 至此）。
//     AuditImage **恒返回 ErrAuditImageUnsupported**：微信 2.0 内容安全只提供
//     mediaCheckAsync（传可下载 URL，结果 30 分钟内经消息推送异步返回），不提供
//     「原始字节同步审核」；1.0 同步接口已于 2021-09-01 停止更新（官方原文，
//     见 mediaCheckAsync 文档页）。替代用法：AuditMediaAsync 提交异步检测 →
//     VerifyWebhook 验签消息推送 → ParseMediaCheckEvent 解析结果。
//     文档：https://developers.weixin.qq.com/minigame/dev/api-backend/wxa-sec-check/api_mediacheckasync.html
//     （2026-06-11 拉取）。
//   - platform.WebhookVerifier：VerifyWebhook 校验微信消息推送（开发者服务器
//     URL 验证 GET + 事件推送 POST，明文模式 signature / 安全模式 msg_signature），
//     并按合约硬要求完成时间戳窗口校验 + 防重放去重；读过的 Body 在返回前重置。
//     文档：https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html
//     （2026-06-11 拉取）。
//
// # 扩展能力（合约之外、官方文档完整可得，按需取用）
//
//   - AuditMediaAsync：提交图片/音频异步检测（media_check_async）；
//   - ParseMediaCheckEvent / MediaCheckEvent.ToAuditResult：解析异步检测结果推送；
//   - DecryptWebhookEvent：安全模式 Encrypt 密文解密（AES-256-CBC，
//     AESKey=Base64_Decode(EncodingAESKey+"=")，IV=AESKey 前 16 字节，PKCS#7 K=32；
//     文档：https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/2.0/api/Before_Develop/Technical_Plan.html
//     2026-06-11 拉取；IV 取值经官方加解密示例代码包
//     https://wximg.gtimg.com/shake_tv/mpwiki/cryptoDemo.zip 的 WXBizMsgCrypt.py
//     确认（AES.new(key, MODE_CBC, key[:16])，2026-06-11 下载）；
//   - VerifyPayEventSig：支付类订阅事件（minigame_coin_deliver_completed /
//     minigame_pay_refund_succ_notify 等）的 PayEventSig 验签。
//     文档：https://developers.weixin.qq.com/minigame/dev/guide/open-ability/virtual-payment/event.html
//     （2026-06-11 拉取）。
//
// # NEEDS-DOC（缺官方正文的细节，绝不编造）
//
//  1. 米大师 queryOrder 的专属业务错误码表：官方页只给出响应字段与 env 枚举，
//     错误码让查「通用错误码」——本包对非 0 errcode 统一按通用语义分类（-1 可重试、
//     40001 失效 token 重取后可重试、其余确定性失败）。若需要对米大师特有错误码
//     （如订单不存在）做精细分支，需用户提供其控制台展示的错误码表。
//  2. 旧版指南页 https://developers.weixin.qq.com/minigame/dev/guide/open-ability/midas/
//     已 404（文档站改版），本包以新版 api-backend/midas-payment/* 各页为准。
//
// # 凭据
//
// Config.AppID / AppSecret 对接 tgf 配置项 config.Current().Platform.WechatAppID /
// WechatAppSecret（Secret 已登记启动日志脱敏）。支付还需 OfferID / AppKey
// （MP-支付基础配置，现网与沙箱 AppKey 不同）；webhook 需 PushToken（MP-开发管理-
// 消息推送配置的 Token），安全模式解密另需 EncodingAESKey。本包绝不直读环境变量、
// 绝不落盘。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答，不打真实微信 API。真凭据端到端验证
// （dev 环境换一次真 code、查一笔沙箱订单、收一条真实消息推送）留给持有凭据的
// 使用方执行。
package wechat
