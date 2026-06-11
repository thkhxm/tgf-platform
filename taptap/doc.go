//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description taptap：TapTap 平台 SDK——实现 tgf/platform 合约的 LoginProvider
//2026/6/11
//***************************************************

// Package taptap 是 github.com/thkhxm/tgf/v2/platform 合约的 TapTap 平台实现。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 用客户端 SDK 登录后返回的 Access Token
//     （kid + mac_key，credential 传其 JSON 序列化）按官方 MAC Token 协议
//     （HMAC-SHA1 签算 Authorization 头）调 TapTap OAuth 账户接口，验证凭据
//     有效性并换取 openid / unionid。
//     文档：https://developer.taptap.cn/docs/sdk/taptap-login/taptap-oauth/
//     （2026-06-11 直连拉取，本目录 .docs/taptap-oauth.html 留有快照）。
//
// # credential 约定
//
// VerifyLogin 的 credential 参数是客户端 SDK（GetCurrentTapAccount）返回的
// Access Token 对象的 JSON 序列化，至少包含（字段名以官方文档为准）：
//
//	{"kid":"...","mac_key":"...","token_type":"mac","mac_algorithm":"hmac-sha-1"}
//
// 其中 kid 即 Authorization 头 MAC id 的值，mac_key 是 HMAC-SHA1 签算密钥
// （注意：mac_key 与开发者控制台的 Server Secret 是不同的值——官方文档明确
// 提示，凭据种类不要混用）。token_type / mac_algorithm 缺省时按 "mac" /
// "hmac-sha-1" 处理；显式给出其它取值时直接报错（防止平台未来升级算法后
// 被静默错签）。
//
// 官方明确单个 Access Token 最长有效期 30 天且可能提前失效（用户注销 / 解除
// 授权），并建议不要在服务端缓存 Access Token——每次需要时由客户端经 SDK 取
// 最新值上传。
//
// # 接口选择（scope 匹配规则，来自官方文档）
//
//   - 移动端授权仅 basic_info scope → 服务端只能调 /account/basic-info/v1；
//   - 移动端授权 public_profile scope → 基础信息与 /account/profile/v1 均可调。
//
// 本实现默认调基础信息接口（最低权限即可用，openid / unionid 已满足
// PlatformIdentity 的全部字段）；Config.UseProfileAPI 开启后改调详细信息接口，
// 额外把 name / avatar 透传进 PlatformIdentity.Raw——若移动端只授了 basic_info，
// 平台会返回 insufficient_scope 业务错误（此时 VerifyLogin 整体返回错误，
// 不静默降级）。
//
// # 未实现的能力（NEEDS-DOC，绝不编造）
//
// platform.PaymentProvider —— 本次抓取范围（taptap-login / anti-addiction 两份
// 官方文档）内没有 TapTap 国内的服务端支付校验 API。TapTap 国际版另有
// TapPayments 产品（developer.taptap.io），其 Server API 文档未抓取核对，
// 不凭记忆实现。需要补充：TapPayments（或国内对应产品）的订单查询/验签
// 官方文档页。
//
// platform.WebhookVerifier —— 未抓取到 TapTap 服务端回调（webhook）的验签
// 协议文档，不实现。需要补充：官方 webhook 验签文档页（如存在）。
//
// platform.ContentAuditProvider —— 未检索到 TapTap 对第三方开放的内容安全
// 审核 server API，不实现（合约允许平台只实现其支持的子集）。
//
// 防沉迷 / 实名认证（合规认证）——官方指南
// https://developer.taptap.cn/docs/sdk/anti-addiction/guide/（2026-06-11 直连
// 拉取，快照 .docs/anti-addiction.html）通篇为客户端 SDK 能力（Unity / Android /
// iOS 的 CheckPaymentLimit / SubmitPaymentResult / GetAgeRange 等），未提供任何
// 服务端 REST endpoint——服务端无从实现，也非合约能力，不做。
//
// # 凭据
//
// Config.ClientID 即 TapTap 开发者中心的 Client ID（请求参数 client_id，官方
// 要求“应与约定相同”）。注意：tgf config.PlatformConfig（H1）尚无 TapTap 字段，
// 建议框架侧后续补充 TaptapClientID 配置位（TapTap 服务端验证不需要 Server
// Secret，签算密钥 mac_key 来自客户端上传的 Access Token，故无 Secret 类配置）。
//
// # 响应包封形态（NEEDS-DOC，已防御处理）
//
// 官方 v4 文档（含 v3 与国际站同页）只给了响应字段表（openid / unionid /
// name / avatar）与错误统一格式（code / error / error_description），均未给出
// 完整 JSON 应答示例——无法确认线上应答是平铺还是 {"data":{...},"success":...}
// 包封（TDS 时代真实线上行为是包封）。本实现对两种形态都能解析（见
// login.go decodeAccountResp），真凭据端到端验证时务必复核实际形态。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答（mock 服务端按官方算法重算 MAC 验签），
// 不打真实 TapTap API。真凭据端到端验证（真机 SDK 登录拿一组 kid / mac_key，
// 换一次真 openid）留给持有凭据的使用方执行。
package taptap
