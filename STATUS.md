# 平台接入验证状态

> 本表记录每个平台 module 的实现与**验证**状态。
> ⚠️ **「真凭据验证」= 用平台真实/沙箱凭据跑通一次真实请求**（§2.8：`go build` 通过 ≠ 协议正确）。
> 未经真凭据验证的 module 标记为「⚠️ 未实测」，使用方接入前请自行用真凭据复核一次，
> 发现问题请按 [issue 流程](https://github.com/thkhxm/tgf/blob/master/doc/issue-workflow.md) 反馈。

> 全部协议均已在 2026-06-11 经本机代理 `curl` **直连官方文档**逐字段核对（每个 endpoint 代码注释附官方 URL+日期）。

## 能力矩阵（13 平台 + core）

| module | Login | Payment | Webhook | Audit | 单测 | 编译 | 真凭据验证 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `core`（stdlib 工具，非平台） | — | — | — | — | ✅ | ✅ | N/A |
| `tiktok` | ✅ | ✅ | ✅ | ✕ | ✅ | ✅ | ⚠️ 未实测 |
| `wechat` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ 未实测 |
| `douyin` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ 未实测 |
| `alipay` | ✅ | ✅ | ✅ | ✅(文本) | ✅ | ✅ | ⚠️ 未实测 |
| `huawei` | ✅ | ✅ | ✅ | ✕ | ✅ | ✅ | ⚠️ 未实测 |
| `xiaomi` | ✅ | ✅ | ✅ | NEEDS-DOC | ✅ | ✅ | ⚠️ 未实测 |
| `taptap` | ✅ | NEEDS-DOC | NEEDS-DOC | ✕ | ✅ | ✅ | ⚠️ 未实测 |
| `apple` | ✅ | ✅ | ✅ | ✕ | ✅ | ✅ | ⚠️ 未实测 |
| `google` | ✅ | ✅ | ✅(RTDN) | ✕ | ✅ | ✅ | ⚠️ 未实测 |
| `facebook` | ✅ | ✅ | ✅ | ✕ | ✅ | ✅ | ⚠️ 未实测 |
| `line` | ✅ | NEEDS-DOC | ✅ | ✕ | ✅ | ✅ | ⚠️ 未实测 |
| `telegram` | ✅ | ✅ | ✅ | ✕ | ✅ | ✅ | ⚠️ 未实测 |
| `steam` | ✅ | ✅ | ✕ | ✕ | ✅ | ✅ | ⚠️ 未实测 |

- ✕=该平台无对应 server API/无此机制（各 module `doc.go` 已说明）；NEEDS-DOC=需更多官方文档/后台凭据才能落地（已写明缺什么，未编造）。
- 单测均为 httptest mock；每个 module 的 `doc.go` 含官方 endpoint 清单+文档链接+协议纪律+NEEDS-DOC+真凭据验证步骤。
- tiktok / taptap / alipay 的详细说明见下方章节，其余平台见各自 `doc.go`。

## 各平台真凭据验证所需（接入时填 `.env`，绝不入库）

| 平台 | 凭据（沙箱即可） | 平台 | 凭据 |
|---|---|---|---|
| tiktok | Client Key + Secret + 沙箱 code | apple | Bundle ID(aud)；IAP 另需 Issuer/Key ID + .p8 |
| wechat | AppID + AppSecret(+米大师) | google | OAuth Client ID(aud)；IAP 另需 Service Account JSON |
| douyin | AppID + Secret(+担保支付 salt) | facebook | App ID + App Secret |
| alipay | AppID + 应用私钥 + 支付宝公钥 + 沙箱 | line | Channel ID + Channel Secret |
| huawei | App ID + Secret + IAP 公钥 | telegram | Bot Token |
| xiaomi | AppId + AppSecret(+支付密钥) | steam | Web API Key + App ID + 真 ticket |
| taptap | Client ID + Token + 真机 kid/mac_key | | |

> 含 Webhook 的平台：默认防重放为单机内存实现，多实例部署须经各平台 `Config.WebhookSeen` 注入共享存储（Redis `SET NX EX`）。

## tiktok（协议已直连官方文档核对，⚠️ 真凭据未实测）

**实现**：
- **Login**：Mini Game / Login Kit 登录（`POST /v2/oauth/token/` 换 open_id，Minis 省略
  redirect_uri——官方原文确认）、可选 `GET /v2/user/info/` 补 union_id；
- **Payment**：`CreateTradeOrder`（`POST /v2/minis/trade_order/create/`，IAP 下单）、
  `VerifyPayment`（`POST /v2/minis/trade_order/query/` 查单，状态枚举官方确认仅
  `PENDING`/`SUCCESS`，仅 SUCCESS 视为已支付）、`ParseWebhookEvent`/`TradeOrderContent`
  （解析 `minis.trade_order.redeem.success` / `redeem.refund_traceback` 回调）。
  关键纪律（官方正文确认）：两接口鉴权用**付款用户的 OAuth access token**（act.* 前缀，
  非 client token）；`token_amount` 单位是平台虚拟币 **Beans 个数**（非法币最小单位），
  故 `PaymentResult.Amount` 恒为 0，金额对账走下单值 + webhook；
- **Webhook**：`Tiktok-Signature` 验签（`signed_payload = t + "." + body`，HMAC-SHA256，
  key=client_secret——拼接方式已经官方正文逐字确认）+ 时间戳窗口 + 防重放去重。

ContentAuditProvider 未实现（官方 Minis Server API 总览仅含 OAuth/User Data/Payment/
Subscription 四类，无第三方内容安全 server API）。

**文档核对方式（2026-06-11）**：经本机代理 curl 直连 `developers.tiktok.com` 抓取
minis-oauth / minis-payment-apis / minis-server-apis-overview / minis-user-data /
minis-error-codes / webhooks-verification / webhooks-overview / webhooks-events /
mini-games-monetization 共 9 页正文，逐字段核对 endpoint/鉴权/参数/单位/状态枚举，
每个调用点注释附文档 URL + 拉取日期。早前「搜索摘录待复核」的三项缺口
（signed_payload 拼接、Minis 省略 redirect_uri、client_key/client_secret 命名）均已
经官方正文确认无误。

**剩余验证缺口（诚实声明）**：单测全部 httptest mock，未用真凭据打过真实 TikTok API。
接入前必做一次真凭据验证（任一持有凭据的项目可完成）：
- 真实 `code` 换 `open_id`（确认 200 + 字段）；
- 沙箱下一笔单：`CreateTradeOrder` → `TTMinis.game.pay` → 收 `redeem.success` webhook
  （沙箱支付不扣 Beans，官方确认正常投递 webhook）→ `VerifyPayment` 查单确认 SUCCESS；
- 真实 webhook 回调复核验签全链路；
- `refund_traceback` 事件 `refund_amount` 单位官方未明示（按上下文推断为 Beans），
  真回调时复核。

## taptap（协议已直连官方文档核对，⚠️ 真凭据未实测）

**实现**：
- **Login**：`VerifyLogin` 接收客户端 SDK Access Token 的 JSON（`kid` + `mac_key`），
  按官方 MAC Token 协议（HMAC-SHA1 签算 `Authorization: MAC id=...,ts=...,nonce=...,mac=...`）
  调 `GET https://open.tapapis.cn/account/basic-info/v1?client_id=xxx`（默认，basic_info
  scope 即可）或 `GET /account/profile/v1`（`Config.UseProfileAPI`，需 public_profile scope）
  验证凭据并换 `openid` / `unionid`（profile 额外把 name/avatar 透传进 Raw）。
  海外应用把 `Config.BaseURL` 换成 `https://open.tapapis.com`（官方明示流程不变）。

PaymentProvider / WebhookVerifier 未实现（本次抓取范围内无 TapTap 国内服务端支付/回调
验签文档；国际版 TapPayments Server API 未核对，标 NEEDS-DOC，见 `taptap/doc.go`）。
ContentAuditProvider 未实现（未检索到对第三方开放的内容安全 server API）。
防沉迷/合规认证：官方指南通篇是客户端 SDK 能力，无服务端 REST endpoint，服务端无从实现。

**文档核对方式（2026-06-11）**：经本机代理 curl 直连 `developer.taptap.cn` 抓取
`/docs/sdk/taptap-login/taptap-oauth/`（v4 当前版，另核 v3 与国际站同页）与
`/docs/sdk/anti-addiction/guide/` 正文（快照存 `taptap/.docs/`），MAC 签算串、HMAC-SHA1、
错误码表、scope 匹配规则均来自官方正文，每个调用点注释附文档 URL + 拉取日期。

**剩余验证缺口（诚实声明）**：单测全部 httptest mock（mock 服务端按官方算法重算 MAC
验签），未用真凭据打过真实 TapTap API。已知 NEEDS-DOC：官方 v4/v3/国际站文档均未给出
成功应答的完整 JSON 示例（仅字段表）——实现对「平铺」与「`{"data":...,"success":...}`
包封」两种形态均能解析，真凭据验证时务必复核实际形态。接入前必做一次真凭据验证：
- 真机 SDK 登录拿一组 `kid` / `mac_key`，换一次真 `openid`/`unionid`（确认 200 + 应答形态）；
- 若用 profile 接口，确认移动端授权 scope 含 `public_profile`。

## alipay（协议已直连官方文档核对，⚠️ 真凭据未实测）

**实现**（OpenAPI v2 统一网关 `gateway.do` + 公共参数 + RSA2 公钥模式，签名用
`core/sign.RSASHA256SignBase64`，应答对 `xxx_response` 节点**原文**验签）：
- **Login**：`VerifyLogin` 用 auth_code 调 `alipay.system.oauth.token`
  （grant_type=authorization_code，业务参数平铺表单而非 biz_content——官方 cURL
  示例确认）换 `user_id`/`open_id`（二选一返回，OpenID 优先取 open_id）+
  access_token；可选 `alipay.user.info.share` 补昵称/头像/省市/性别
  （`Config.FetchUserInfo`，含 user_id/open_id 串号交叉核对）；
- **Payment**：`VerifyPayment` 调 `alipay.trade.query`（biz_content 传
  out_trade_no / trade_no 二选一），官方状态枚举仅四档，`TRADE_SUCCESS` /
  `TRADE_FINISHED` 判已支付。关键单位纪律：`total_amount` 官方单位是人民币
  「元」（两位小数），实现按十进制字符串精确换算为「分」填 `PaymentResult.Amount`
  （绝不过 float）；响应无商品/币种字段，`ProductID` 恒空、`Currency` 恒 "CNY"
  （境内交易），业务发货前须按本地订单核对金额；
- **Audit**：`AuditText` 调 `alipay.security.risk.content.detect`（小程序内容
  风险检测，仅 PASSED/REJECTED 两档，无「人工复核」档；官方注明目前仅拦截国家
  涉政风险文案）。`AuditImage` 无官方 server API，恒返回明确错误（见 NEEDS-DOC）；
- **Webhook**：`VerifyWebhook` 按官方异步通知验签规则（除 sign / sign_type 外
  全部参数 url_decode 后字典排序拼 `k=v&...`，支付宝公钥验 base64 RSA2 签名；
  生活号需保留 sign_type——`Config.NotifyKeepSignType`）+ `app_id` 归属核对 +
  `notify_time` 时间窗 + `notify_id` 防重放去重，Body 读后重置。

**文档核对方式（2026-06-11）**：经本机代理 + r.jina.ai 直连 `opendocs.alipay.com`
抓取正文（快照存 `alipay/.docs/`）：`common/057k53`（自行实现签名：排序/排空值/
RSA2/网关地址）、`common/02mse7`（自行实现验签：同步对节点原文验签 + 异步通知
验签串规则）、`apis/api_9/alipay.system.oauth.token`、`apis/api_2/alipay.user.info.share`、
`open/6f534d7f_alipay.trade.query`、`apis/api_49/alipay.security.risk.content.detect`、
`open/203/105286`（异步通知参数表）、`common/097pw5`（沙箱网关地址）共 8 篇，
逐字段核对 endpoint/公共参数/签名规则/状态枚举/金额单位，每个调用点注释附文档
URL + 拉取日期。

**剩余验证缺口（诚实声明）**：单测全部 httptest mock（mock 网关按官方 RSA2 算法
独立重算请求验签与应答签名），未用真凭据打过真实支付宝网关。已知 NEEDS-DOC：
- `AuditImage`：未检索到对第三方开放的图片内容风险检测 server API，恒返回错误；
- 证书模式（公钥证书 + app_cert_sn/alipay_root_cert_sn）未实现，仅公钥模式；
- 公共参数 `timestamp` 官方只给格式未明示时区，按北京时间（UTC+8）取值；
- 异步通知重投是否更新 `notify_time`/`notify_id` 官方未明示——默认 5 分钟时间窗
  可能拒绝平台迟到重投，依赖重投兜底的业务需调大 `WebhookTolerance` 并复核；
- `alipay.system.oauth.token` 的 `expires_in` 官方声明 String 而实网可能返回
  number（实现已双形态容错），真凭据验证时复核实际形态。

**接入前必做一次真凭据验证（needs_user 凭据清单）**：
- **AppID**（开放平台应用 ID；沙箱用沙箱控制台的沙箱 AppID）；
- **应用私钥**（RSA2 ≥2048 位 PEM，PKCS#1/PKCS#8 均可——注意是「应用私钥」）；
- **支付宝公钥**（开放平台后台「支付宝公钥」一栏 PEM——不是应用公钥）；
- **沙箱环境**（https://open.alipay.com/develop/sandbox/app ，网关
  `https://openapi-sandbox.dl.alipaydev.com/gateway.do`）。
  验证路径：沙箱 App 拿真 auth_code 换一次 user_id/open_id → 沙箱下一笔单 →
  `VerifyPayment` 查单确认 TRADE_SUCCESS → 配置异步通知地址收一条真通知复核
  验签全链路。
