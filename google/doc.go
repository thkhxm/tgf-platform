//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：Google 平台 SDK——实现 tgf/platform 合约的 LoginProvider + PaymentProvider + WebhookVerifier
//2026/6/11
//***************************************************

// Package google 是 github.com/thkhxm/tgf/v2/platform 合约的 Google 平台实现，
// 覆盖 Google Sign-In（ID token 服务端校验）、Google Play 一次性内购校验
// （Play Developer API purchases.products.get）与 Play RTDN 回调验真
// （Cloud Pub/Sub push 的 OIDC token 验签 + messageId 去重）。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 在服务端本地校验客户端上送的
//     Google ID token（JWT，RS256）——从 Google JWKS 端点取公钥验签，
//     校验 iss / aud / exp，身份取 sub 映射为 PlatformIdentity.OpenID。
//     文档：https://developers.google.com/identity/sign-in/web/backend-auth（2026-06-11 拉取）
//     与 https://developers.google.com/identity/openid-connect/openid-connect（2026-06-11 拉取）。
//   - platform.PaymentProvider：VerifyPayment 用 service account（JWT-bearer
//     流换 OAuth access token）调 Play Developer API purchases.products.get，
//     以应答的 purchaseState 判定 Paid（0=Purchased 才发货）。
//     文档：https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products/get（2026-06-11 拉取）。
//   - platform.WebhookVerifier：VerifyWebhook 校验 Play RTDN（经 Cloud Pub/Sub
//     push 投递）的 Authorization Bearer OIDC JWT——验签 + aud + email +
//     email_verified，并按官方建议以 messageId 做防重放去重；读过的 Body
//     在返回前重置供业务 handler 再读。
//     文档：https://developer.android.com/google/play/billing/rtdn-reference（2026-06-11 拉取）
//     与 https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions（2026-06-11 拉取）。
//
// # 未实现的能力与已知边界（NEEDS-DOC，绝不编造）
//
// platform.ContentAuditProvider —— Google / Google Play 没有面向第三方应用 UGC
// 的「平台内容安全审核」server API（微信 msgSecCheck 一类）；Cloud Vision
// SafeSearch / Text Moderation 属 Google Cloud 独立产品线（独立计费与凭据），
// 不属于平台合约语义，本包不实现（合约允许平台只实现其支持的子集）。
//
// 金额核对 —— purchases.products.get 的应答 ProductPurchase **不含金额/币种字段**
// （官方字段表确认，https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products ，
// 2026-06-11 拉取），故 VerifyPayment 返回的 PaymentResult.Amount=0 / Currency=""，
// 不与 receipt.Amount 做核对——货不对板防护依赖 ProductID 一致性（价格由 Play
// Console 商品配置锁定）。如业务必须核对实付金额，需另接 orders.get
// （https://developers.google.com/android-publisher/api-ref/rest/v3/orders/get ，
// 字段表未拉取核对，标 NEEDS-DOC，不凭记忆实现）。
//
// 订阅 —— 本包只实现一次性商品（purchases.products.get）。订阅校验是另一组接口
// （purchases.subscriptionsv2.get，状态机复杂得多），合约 PaymentReceipt 也无订阅
// 语义字段；RTDN 的 subscriptionNotification 验真已被 VerifyWebhook 覆盖，但
// 订阅状态回查不在本包范围。
//
// # 凭据（对接 tgf config.Platform.* 命名风格）
//
// tgf v2.1.0 的 config.PlatformConfig 尚无 Google 字段；按既有命名风格
// （WechatAppID / TiktokAppSecret），建议后续在 tgf 增加：
// GoogleClientID（登录 aud 白名单，多个逗号分隔）、GooglePackageName、
// GoogleServiceAccountEmail、GoogleServiceAccountPrivateKey（PEM，需登记
// sensitiveEnvKeys 脱敏）、GooglePubSubAudience、GooglePubSubServiceAccountEmail。
// 在此之前由业务侧自行从配置系统取值填入本包 Config。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答，不打真实 Google API。真凭据端到端
// 验证（真 ID token 校验一次、真 purchaseToken 查一单、收一条真 RTDN push）
// 留给持有凭据的使用方执行。
package google
