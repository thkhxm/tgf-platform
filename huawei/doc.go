//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description huawei：华为 HMS 平台 SDK——实现 tgf/platform 合约的 LoginProvider + PaymentProvider + WebhookVerifier
//2026/6/11
//***************************************************

// Package huawei 是 github.com/thkhxm/tgf/v2/platform 合约的华为 HMS 平台实现。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 校验客户端从华为 Account Kit 拿到的登录
//     凭据并换取标准化身份。凭据形态由 Config.CredentialType 选择（三种均来自官方文档）：
//     id_token（默认，JWKS 本地验签——官方明确商用环境必须本地验证）、
//     access_token（调 getTokenInfo 解析出 open_id / union_id）、
//     code（oauth2/v3/token 换 token 后再 getTokenInfo）。
//   - platform.PaymentProvider：VerifyPayment 调华为 IAP 服务端「验证购买 Token」
//     接口（Order 服务 /applications/purchases/tokens/verify，或订阅场景的
//     Subscription 服务 /sub/applications/v2/purchases/get），用应用级 AT 鉴权，
//     并按官方硬要求用 IAP 公钥对应答 purchaseTokenData 验签后映射为 PaymentResult。
//   - platform.WebhookVerifier：VerifyWebhook 校验华为 IAP「关键事件通知 v2」
//     回调：版本/结构校验 + notifyTime 时间戳窗口 + 防重放去重；SUBSCRIPTION 事件
//     用 IAP 公钥对 statusUpdateNotification 验签。注意：ORDER 事件按官方文档
//     不携带签名字段（表 1 仅 version/notificationType/purchaseToken/productId），
//     其真实性必须由业务拿通知里的 purchaseToken 调 VerifyPayment 以华为服务端
//     应答为准核实后再发货——这正是官方设计的安全闭环。
//
// # 未实现的能力（合约允许实现子集）
//
// platform.ContentAuditProvider —— 华为 HMS Core 没有与微信 msgSecCheck 对位的、
// 面向应用 UGC 的内容安全审核 server API；华为云「内容审核 Moderation」是独立云
// 服务（独立开通、独立 AK/SK 凭据体系，与 AppGallery Connect 应用凭据不通用），
// 不属于本平台实现的范围。如业务需要，应单独接入华为云 SDK（NEEDS-DOC：若用户
// 确认要走华为云内容审核，需提供其控制台的接入文档与 AK/SK）。
//
// # 凭据
//
// Config.ClientID / ClientSecret 即 AppGallery Connect「应用中 OAuth 2.0 客户端 ID
// （凭据）」的 Client ID / Client Secret（Client ID 同时就是 App ID，
// 文档：https://developer.huawei.com/consumer/cn/doc/HMSCore-References/obtain-application-level-at-0000001051066052 ，
// 2026-06-11 拉取："client id 指的是您的 APP ID"）。
// Config.IAPPublicKey 是 AppGallery Connect「查询支付服务信息」中的 IAP 公钥
// （base64 的 X.509/PKIX DER），支付应答验签与订阅事件通知验签必需。
// tgf 配置系统（config.Current().Platform）当前尚无 Huawei 字段，接入方可在
// config.PlatformConfig 增补 HuaweiClientID / HuaweiClientSecret / HuaweiIAPPublicKey
// 后传入（Secret 类记得登记 tgf/config.go sensitiveEnvKeys 脱敏）；本包绝不直读
// 环境变量、绝不落盘。
//
// # 文档时效性说明
//
// 任务最初给到的两个文档 URL 已被华为重组下线（getDocumentById 返回
// document not found）：
//   - HMSCore-Guides/server-dev-0000001050048870（Account Kit 旧版服务端开发）
//     → 现行内容拆分为 HMSCore-References/account-obtain-token_hms_reference-* /
//     account-verify-id-token_hms_reference-* / account-gettokeninfo-* 等参考页；
//   - HMSCore-References/verifying-purchase-token-0000001050033088
//     → 该编号现对应 HMSCore-Guides/verifying-signature-returned-result-0000001050033088
//     （对返回结果验签），验证购买 Token 的现行 API 参考是
//     HMSCore-References/api-order-verify-purchase-token-0000001050746113。
//
// 本包全部 endpoint / 参数 / 单位均来自 2026-06-11 经华为文档站内容接口
// （svc-drcn.developer.huawei.com documentPortal/getDocumentById）拉取的现行官方
// 正文，各调用点注释附文档 URL + 拉取日期；oauth-login.cloud.huawei.com 的
// openid-configuration 与 JWKS 公钥端点已于同日现网实测可达。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答，不打真实华为 API（公开的
// openid-configuration / certs 端点除外，已现网实测）。真凭据端到端验证
// （dev 环境换一次真 id_token / 验一笔沙盒支付 / 收一条真通知）留给持有
// AppGallery Connect 凭据的使用方执行。
package huawei
