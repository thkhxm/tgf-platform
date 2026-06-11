# 平台接入验证状态

> 本表记录每个平台 module 的实现与**验证**状态。
> ⚠️ **「真凭据验证」= 用平台真实/沙箱凭据跑通一次真实请求**（§2.8：`go build` 通过 ≠ 协议正确）。
> 未经真凭据验证的 module 标记为「⚠️ 未实测」，使用方接入前请自行用真凭据复核一次，
> 发现问题请按 [issue 流程](https://github.com/thkhxm/tgf/blob/master/doc/issue-workflow.md) 反馈。

| 平台 module | 已实现能力 | 单测 | 编译 | 真凭据验证 | 备注 |
|---|---|---|---|---|---|
| `core` | httpx / sign / errs（stdlib-only 工具，非平台） | ✅ | ✅ | N/A | 无外部调用，单测即充分验证 |
| `tiktok` | LoginProvider、WebhookVerifier | ✅(mock) | ✅ | ⚠️ **未实测** | 见下方说明 |

## tiktok（⚠️ 未实测，待真凭据复核）

**实现**：Mini Game / Login Kit 登录（`POST /v2/oauth/token/` 换 open_id，Minis 省略 redirect_uri）、
可选 `GET /v2/user/info/` 补 union_id、Webhook 验签（`Tiktok-Signature` HMAC-SHA256）。
PaymentProvider 标 **NEEDS-DOC**（缺订单状态枚举/token 种类/金额单位，见 `tiktok/doc.go`）。
ContentAuditProvider 未实现（未发现 TikTok 对第三方开放的内容安全 server API）。

**验证缺口（诚实声明）**：
1. 本环境无法直连 `developers.tiktok.com`（被墙），协议细节来自搜索引擎对官方页的渲染摘录，
   每个 endpoint 已注释来源 + 拉取日期（2026-06-11），但**非直连官方文档**，权威性待复核。
2. Webhook `signed_payload` 的 `timestamp + "." + body` 拼接中 `"."` 分隔符取自搜索摘录，
   须用一条真实回调复核。
3. 凭据命名待确认：实现按 `client_key` + `client_secret`（TikTok 习惯名）。若 Minis 后台
   凭据名称/登录流程与此不同，需据官方文档调整。

**接入前必做的一次真凭据验证**（任一持有凭据的项目可完成）：
- 真实 `code` 换 `open_id`（确认 200 + 字段）；
- 真实 webhook 回调复核 `Tiktok-Signature` 拼串；
- 补全 Minis 支付 API 文档后实现并验证 PaymentProvider。
