//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description alipay：支付宝开放平台 SDK——实现 tgf/platform 合约的 Login + Payment + Audit + Webhook
//2026/6/11
//***************************************************

// Package alipay 是 github.com/thkhxm/tgf/v2/platform 合约的支付宝（OpenAPI v2
// gateway.do + RSA2 公钥模式）平台实现。
//
// 本包所有 endpoint / 鉴权 / 字段 / 单位均以 2026-06-11 经本机代理直连
// opendocs.alipay.com 拉取的官方文档正文为准（快照存 alipay/.docs/），各调用点
// 注释附文档 URL + 拉取日期。
//
// # 协议形态（与微信/TikTok 的差异）
//
// 支付宝 OpenAPI v2 是「统一网关 + 公共参数 + RSA2 签名」模式：所有接口都打
// https://openapi.alipay.com/gateway.do ，由公共参数 method 区分接口；请求用
// 应用私钥做 SHA256WithRSA（RSA2）签名，应答用支付宝公钥对 xxx_response 节点
// 的原始 JSON 串验签。签名/验签规则文档：
//   - 自行实现签名：https://opendocs.alipay.com/common/057k53（2026-06-11 拉取）
//   - 自行实现验签：https://opendocs.alipay.com/common/02mse7（2026-06-11 拉取）
//
// 本实现只支持公钥模式 + RSA2（官方：新建应用仅支持 RSA2）。证书模式
// （app_cert_sn / alipay_root_cert_sn）未实现，需要时按 057k53「证书模式」一节
// 扩展（NEEDS-DOC：证书模式的 SN 计算规则官方正文只给了 Java SDK 源码指引）。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 用客户端授权拿到的一次性 auth_code 调
//     alipay.system.oauth.token（grant_type=authorization_code）换 user_id/open_id
//     与 access_token；可选再调 alipay.user.info.share 补昵称/头像等（Config.FetchUserInfo）。
//     文档：https://opendocs.alipay.com/apis/api_9/alipay.system.oauth.token 、
//     https://opendocs.alipay.com/apis/api_2/alipay.user.info.share（2026-06-11 拉取）。
//
//   - platform.PaymentProvider：VerifyPayment 调 alipay.trade.query 查交易状态，
//     仅 TRADE_SUCCESS / TRADE_FINISHED 视为已支付（官方状态枚举共四档：
//     WAIT_BUYER_PAY / TRADE_CLOSED / TRADE_SUCCESS / TRADE_FINISHED）；
//     total_amount 单位是人民币「元」（两位小数），实现换算为「分」填入
//     PaymentResult.Amount。
//     文档：https://opendocs.alipay.com/open/6f534d7f_alipay.trade.query（2026-06-11 拉取）。
//
//   - platform.ContentAuditProvider：AuditText 调 alipay.security.risk.content.detect
//     （小程序内容风险检测，官方仅 PASSED/REJECTED 两档处置）。AuditImage 无对应
//     官方 server API，恒返回明确错误（见下「未实现的能力」）。
//     文档：https://opendocs.alipay.com/apis/api_49/alipay.security.risk.content.detect
//     （2026-06-11 拉取）。
//
//   - platform.WebhookVerifier：VerifyWebhook 校验支付宝异步通知（POST 表单）的
//     RSA2 签名——除 sign / sign_type 外全部参数 url_decode 后按参数名字典排序拼
//     key=value&... 串，用支付宝公钥验 base64 签名；并按合约硬要求完成 notify_time
//     时间窗校验 + notify_id 防重放去重，读过的 Body 在返回前重置供业务 handler 再读。
//     文档：https://opendocs.alipay.com/common/02mse7（异步通知验签）、
//     https://opendocs.alipay.com/open/203/105286（异步通知参数表）（2026-06-11 拉取）。
//
// # 未实现的能力（NEEDS-DOC，诚实声明）
//
//   - AuditImage：2026-06-11 检索 opendocs.alipay.com，未找到对第三方开放的图片
//     内容风险检测 server API（alipay.security.risk.content.detect 业务参数仅
//     content 文本一项，且官方注明「目前暂仅针对国家涉政风险文案进行拦截」）。
//     AuditImage 恒返回明确错误，绝不假装审核通过。
//   - 证书模式签名/验签（公钥证书 + SN）：未实现，本包仅公钥模式。
//   - 下单类接口（alipay.trade.create / wap.pay 等）：不在 platform 合约范围内，
//     业务自行接入或后续按需扩展。
//
// # 沙箱
//
// Config.GatewayURL 换成 SandboxGatewayURL（https://openapi-sandbox.dl.alipaydev.com/gateway.do ，
// 官方沙箱 FAQ https://opendocs.alipay.com/common/097pw5 确认，2026-06-11 拉取）即指向
// 沙箱环境；沙箱应用的 AppID / 密钥从沙箱控制台获取，与生产不通用。
// PaymentResult.Sandbox 按网关域名是否含 "alipaydev" 判定。
//
// # 凭据
//
// Config.AppID / AppPrivateKeyPEM（应用私钥）/ AlipayPublicKeyPEM（支付宝公钥）
// 由业务侧从 tgf 配置系统传入，本包绝不直读环境变量、绝不落盘。注意三把钥匙
// 别拿混：签请求用「应用私钥」，验应答/通知用「支付宝公钥」（不是应用公钥——
// 应用公钥只在开放平台后台配置，代码用不到）。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 网关应答（mock 端按官方 RSA2 算法重算签名），
// 不打真实支付宝网关。真凭据端到端验证（沙箱换一次真 auth_code、查一笔真交易、
// 收一条真异步通知）留给持有凭据的使用方执行。
package alipay
