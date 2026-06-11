//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description douyin：抖音小游戏（国内）平台 SDK——实现 tgf/platform 合约的 Login/Payment/Audit/Webhook
//2026/6/11
//***************************************************

// Package douyin 是 github.com/thkhxm/tgf/v2/platform 合约的抖音小游戏（国内）平台实现。
//
// 本包覆盖的是「抖音小游戏」（字节小游戏，developer.open-douyin.com），与海外
// TikTok（tgf-platform/tiktok 包）是两套完全独立的开放平台与协议，凭据互不通用。
//
// # 已实现的能力切面（endpoint 协议全部来自 curl 抓取的官方文档正文，URL+拉取日期见各文件注释）
//
//   - platform.LoginProvider：VerifyLogin 用客户端 tt.login 拿到的一次性 code 调
//     jscode2session 换取 openid / session_key / unionid；匿名登录走扩展方法
//     VerifyLoginAnonymous（anonymous_code → anonymous_openid）。
//   - platform.PaymentProvider：VerifyPayment 用业务侧自定义订单号（下单时
//     tt.requestGamePayment 的 customId）调 queryPayState 主动回查订单支付状态，
//     status=="success" 才判 Paid。注意：该接口不返回金额/商品信息，金额核对请以
//     支付服务端回调包体的 amount_cent（单位人民币分）为准（见 ParseOrderCallback）。
//   - platform.ContentAuditProvider：AuditText 调文本内容安全检测（antidirt）；
//     AuditImage（[]byte 入参）平台不支持——抖音图片检测只接受图片 URL（官方文档
//     image 字段为「检测的图片链接」），传图片字节会返回 ErrImageBytesUnsupported，
//     请改用扩展方法 AuditImageURL(ctx, openID, imageURL)。
//   - platform.WebhookVerifier：VerifyWebhook 校验「虚拟支付服务端回调」的 SHA1
//     签名（token+timestamp+nonce+msg 自然序拼接），同时支持平台的 GET 可访问性
//     验证请求（echostr，见 WebhookEcho）与 POST 正式订单回调；按合约硬要求完成
//     时间戳窗口校验 + 防重放去重，读过的 Body 在返回前重置供业务 handler 再读。
//
// # 凭据
//
//   - Config.AppID / AppSecret：小游戏 ID（tt 开头）与 APP Secret（开发者后台->
//     开发管理->开发设置），对接 tgf 配置项 config.Current().Platform.TiktokAppID /
//     TiktokAppSecret——tgf 对该配置项的注释即「抖音/TikTok 小游戏 AppID」，国内抖音
//     小游戏项目填抖音后台的值（Secret 已登记启动日志脱敏）。
//   - Config.PayCallbackToken：虚拟支付「服务器回调 Token」（开发者平台 商业化->
//     虚拟支付->支付设置，由开发者自定义），是 VerifyWebhook 的验签密钥。注意它
//     既不是 AppSecret 也不是「支付密钥（签名密钥）」——三者是三个不同的凭据。
//
// # NEEDS-DOC（官方文档未覆盖的细节，绝不编造）
//
//  1. 支付服务端回调包体的 timestamp 字段官方仅注释「时间戳」，未明确单位。本包按
//     Unix 秒解析（同域的「支付签名生成算法」文档对 ts 字段明确标注“单位：秒”，
//     https://developer.open-douyin.com/docs/resource/zh-CN/mini-game/develop/api/javascript-api/payment/payment-signature-generation-algorithm
//     2026-06-11 拉取），真凭据端到端验证时务必复核一条真实回调的 timestamp 量级。
//  2. queryPayState 官方文档只给出输出字段 status（success/unsuccess），未给出错误
//     应答的 JSON 形态与错误码表。本包对非 status 应答做了防御性解析（err_no/errcode），
//     若实测发现其它错误形态需按真实应答补充。
//  3. 图片检测 predicts 的 prob 在官方示例中出现小数（0.0005、0.022），但字段描述
//     沿用文本检测的「值为 0 或者 1」。本包按「hit==true 或 prob>=1 即违规」判定，
//     小数 prob 不判违规、原样透传 Raw——业务如需更严阈值请基于 Raw 自行加严。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答，不打真实抖音 API。真凭据端到端验证
// （dev 环境换一次真 code、查一笔真订单、收一条真回调）留给持有凭据的使用方执行。
package douyin
