//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description steam：Steam 平台 SDK——实现 tgf/platform 合约的 LoginProvider + PaymentProvider
//2026/6/11
//***************************************************

// Package steam 是 github.com/thkhxm/tgf/v2/platform 合约的 Steam（Steamworks Web API）平台实现。
//
// # 已实现的能力切面
//
//   - platform.LoginProvider：VerifyLogin 用客户端经 ISteamUser::GetAuthTicketForWebApi
//     拿到的会话票据（hex 字符串）调 ISteamUserAuth/AuthenticateUserTicket/v1 校验，
//     成功返回用户的 64-bit SteamID（映射到 PlatformIdentity.OpenID）。
//     文档：https://partner.steamgames.com/doc/webapi/ISteamUserAuth（2026-06-11 拉取）、
//     https://partner.steamgames.com/doc/features/auth（2026-06-11 拉取）。
//   - platform.PaymentProvider：VerifyPayment 调 ISteamMicroTxn/QueryTxn/v3 查询订单
//     状态，仅 status == "Succeeded" 判定 Paid=true（业务据此发货）。另提供 Steam
//     专有方法 FinalizeTxn（ISteamMicroTxn/FinalizeTxn/v2，资金捕获）——Steam 微交易
//     闭环必需：InitTxn 下单 → 用户授权（Approved）→ FinalizeTxn 捕获 → Succeeded。
//     文档：https://partner.steamgames.com/doc/webapi/ISteamMicroTxn（2026-06-11 拉取）、
//     https://partner.steamgames.com/doc/features/microtransactions/implementation
//     （2026-06-11 拉取，附录 A 状态值 / 附录 B 错误码）。
//
// 沙箱：Config.Sandbox=true 时微交易走 ISteamMicroTxnSandbox 接口——官方明确该接口
// 与 ISteamMicroTxn 完全一致、仅不产生真实交易
// （https://partner.steamgames.com/doc/webapi/ISteamMicroTxnSandbox ，2026-06-11 拉取）。
//
// # 未实现的能力（平台不提供，非文档缺失）
//
//   - platform.WebhookVerifier —— Steam 微交易没有服务端 webhook 推送机制。官方对账
//     模式是轮询 ISteamMicroTxn/GetReport（实现指南正文：“Your purchasing server will
//     need to regularly call the ISteamMicroTxn/GetReport API ... at least once daily”，
//     https://partner.steamgames.com/doc/features/microtransactions/implementation ，
//     2026-06-11 拉取）。本包不实现 VerifyWebhook（合约允许平台只实现其支持的子集）。
//   - platform.ContentAuditProvider —— Steamworks 未提供面向第三方游戏的内容安全
//     审核 server API，本包不实现。
//
// # NEEDS-DOC（不编造，待真凭据端到端确认）
//
//   - AuthenticateUserTicket 成功应答的字段级 JSON schema：官方页只承诺“返回用户的
//     64-bit SteamID”，未列出 JSON 字段层级。本实现按 Steamworks Web API 通用包封
//     {"response":{"result"/"params"/"error"}}（同体系 ISteamMicroTxn 官方正文确证）
//     宽松解析，只硬依赖 params.steamid 一个字段；其余字段（社区已知有
//     ownersteamid / vacbanned / publisherbanned）不依赖、全部透传 PlatformIdentity.Raw。
//     持有真 publisher key + 真票据跑一次即可确认（见下"端到端验证"）。
//   - 实测（2026-06-11，无凭据探测真实 endpoint）：key 无效 → HTTP 403 + text/html
//     错误页（非 JSON）；缺 key → HTTP 400 + text/html。与官方
//     https://partner.steamgames.com/doc/webapi_overview/responses（2026-06-11 拉取）
//     的状态码语义一致（401/403 = key 错误且“Retrying will not help”）——本实现对
//     非 2xx 应答不强行 JSON 解析。
//
// # 凭据
//
// Config.WebAPIKey 是 Steamworks Web API publisher key（微交易接口要求带
// Microtransaction 权限的 publisher key；AuthenticateUserTicket 也接受普通 Web API
// user key 但走 https://api.steampowered.com 域且限频，见 Config.BaseURL）。
// 凭据应由业务侧从 tgf 配置系统传入；tgf config.PlatformConfig 目前尚未登记 Steam
// 字段，待登记建议命名 SteamAppID / SteamWebAPIKey（后者属 Secret 类，应同步登记
// sensitiveEnvKeys 启动日志脱敏）。本包绝不直读环境变量、绝不落盘。
//
// # 端到端验证（交付前必做，go build 通过不等于接通）
//
// 本包单测全部用 httptest mock 平台应答，不打真实 Steam API。真凭据端到端验证
// （dev 环境用真 publisher key + GetAuthTicketForWebApi 真票据换一次 SteamID、
// 沙箱跑一单 InitTxn→FinalizeTxn→QueryTxn）留给持有凭据的使用方执行。
package steam
