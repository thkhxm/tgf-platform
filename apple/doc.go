//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：Apple 平台 SDK——实现 tgf/platform 合约的 LoginProvider + PaymentProvider + WebhookVerifier
//2026/6/11
//***************************************************

// Package apple 是 github.com/thkhxm/tgf/v2/platform 合约的 Apple 平台实现。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 在服务端校验 Sign in with Apple 的
//     identityToken（JWT）——从 https://appleid.apple.com/auth/keys 拉取 JWKS
//     公钥验签，并按官方步骤校验 iss / aud(=ClientID) / exp / nonce（钩子），
//     取 sub 作 OpenID。
//     文档：https://developer.apple.com/documentation/SignInWithApple/verifying-a-user
//     （2026-06-11 拉取）。
//   - platform.PaymentProvider：VerifyPayment 调 App Store Server API 的
//     Get Transaction Info 端点（鉴权 JWT 用 .p8 私钥 ES256 签发），对返回的
//     signedTransactionInfo（JWS，x5c 证书链锚定 Apple Root CA - G3）做链路
//     验签后映射为标准化结果——以服务端应答为准判定 Paid，绝不信任客户端上报。
//     文档：https://developer.apple.com/documentation/appstoreserverapi/get-transaction-info
//     （2026-06-11 拉取）。
//   - platform.WebhookVerifier：VerifyWebhook 校验 App Store Server
//     Notifications V2 回调（POST body {"signedPayload": <JWS>}）的 x5c 链路
//     签名，并按合约硬要求完成 signedDate 时间戳窗口校验 + notificationUUID
//     防重放去重；读过的 Body 在返回前重置供业务 handler 再读。
//     文档：https://developer.apple.com/documentation/appstoreservernotifications/responsebodyv2
//     （2026-06-11 拉取）。
//
// # 未实现的能力（合约允许实现子集）
//
// platform.ContentAuditProvider —— Apple 不提供对第三方开放的内容安全审核
// server API（App Store 审核是人工/平台侧流程，无 REST 接口），本包不实现。
//
// Sign in with Apple 的 /auth/token（authorization code 换 refresh token）流程
// 本包未实现——VerifyLogin 走的是官方推荐的 identityToken 服务端校验路径，
// 已足够完成"凭据→身份"映射；code 换 token 需要用 TeamID 签发 client_secret
// JWT，属会话续期能力，超出 LoginProvider 合约范围（如业务需要再扩展）。
//
// # ES256 说明（core 能力缺口）
//
// Apple 全家桶（App Store Server API 鉴权 JWT、JWS 交易/通知验签）签名算法
// 一律是 ES256（ECDSA P-256 + SHA-256），而 core/sign 目前只有 HMAC / RSA /
// AES 原语——本包在 jwt.go 内用标准库自带实现了 ES256 签名/验签与 EC 私钥
// PEM 解析，后续建议上提到 core/sign 供其它平台复用（不影响本包行为）。
//
// # 凭据
//
// Config 各字段与 tgf 配置系统（config.Current().Platform）的对应关系：
//
//   - KeyID        ← Platform.AppleKeyID
//   - PrivateKeyP8 ← Platform.ApplePrivateKey（启动日志已脱敏）
//   - ClientID / IssuerID / BundleID —— tgf v2.1.0 的 PlatformConfig 暂无对应
//     字段（只有 AppleTeamID / AppleKeyID / ApplePrivateKey），需框架侧后续补
//     AppleClientID / AppleIssuerID / AppleBundleID 配置位；当前由业务自行传入。
//   - Platform.AppleTeamID 在本包已实现的流程中用不到（它用于 /auth/token 的
//     client_secret 签发），保留给未来扩展。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答 + 自造测试证书链，不打真实 Apple API。
// 真凭据端到端验证（真 identityToken 校验一次、沙箱环境查一笔真交易、收一条
// 真 App Store Server Notification）留给持有凭据的使用方执行。
package apple
