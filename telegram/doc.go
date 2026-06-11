//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description telegram：包级文档——能力清单 / 协议来源 / NEEDS-DOC 说明
//2026/6/11
//***************************************************

// Package telegram 是 Telegram Mini App 平台对 tgf 合约层
// （github.com/thkhxm/tgf/v2/platform）的实现。
//
// # 已实现的合约能力
//
//   - platform.LoginProvider：VerifyLogin(ctx, initData)——服务端校验 Mini App
//     的 Telegram.WebApp.initData（HMAC-SHA256 验签 + auth_date 新鲜度），映射为
//     PlatformIdentity（OpenID = user.id）。纯本地密码学校验，不调任何远端 API。
//     算法文档：https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
//     （2026-06-11 拉取，curl 直连官方正文确认）。
//
//   - platform.PaymentProvider：VerifyPayment——以 Bot API getStarTransactions
//     的服务端应答为准核验 Telegram Stars（XTR）交易（receipt.TransactionID =
//     SuccessfulPayment.telegram_payment_charge_id），绝不信任客户端上报。
//     文档：https://core.telegram.org/bots/payments-stars 与
//     https://core.telegram.org/bots/api#getstartransactions（2026-06-11 拉取）。
//
//   - platform.WebhookVerifier：VerifyWebhook——校验 Bot API webhook 的
//     X-Telegram-Bot-Api-Secret-Token header（setWebhook secret_token 机制，
//     常量时间比较）+ 以 update_id 去重防重放。
//     文档：https://core.telegram.org/bots/api#setwebhook（2026-06-11 拉取）。
//
// # 未实现的合约能力（NEEDS-DOC，合约允许实现子集）
//
//   - platform.ContentAuditProvider：Telegram Bot API（2026-06-11 拉取的
//     https://core.telegram.org/bots/api 正文）不提供任何服务端内容安全审核
//     （文本/图片机审）API——平台侧没有 msgSecCheck 类能力，本实现不提供该接口。
//     业务如需 UGC 审核请接入独立内容安全服务商。
//
// # 协议要点（均来自 2026-06-11 拉取的官方正文）
//
//   - initData 验签：secret_key = HMAC_SHA256(data=bot_token, key="WebAppData")；
//     data_check_string = 除 hash 外的全部字段按 key 字母序排列、"key=<value>" 以
//     "\n" 连接；hex(HMAC_SHA256(data=data_check_string, key=secret_key)) == hash。
//   - Stars 支付流：sendInvoice(currency="XTR") → pre_checkout_query →
//     answerPreCheckoutQuery（10 秒内）→ successful_payment（发货依据）；
//     telegram_payment_charge_id 需存档（退款 refundStarPayment 要用）。
//   - Bot API 应答封装：{ok, result, description, error_code}；
//     endpoint：https://api.telegram.org/bot<token>/METHOD_NAME（测试环境
//     /bot<token>/test/METHOD_NAME）。
//   - webhook：Telegram 官方信封无签名/时间戳字段，唯一官方校验机制是
//     setWebhook 时指定 secret_token、回调携带 X-Telegram-Bot-Api-Secret-Token
//     header；投递语义 at-least-once（非 2xx 会重试），以 update_id
//     （“start from a certain positive number and increase sequentially…
//     allows you to ignore repeated updates”）做防重放去重。
//
// # 凭据安全
//
// BotToken 既是 Bot API 调用凭据也是 initData 验签密钥派生原料，属最高敏感级——
// 一律走 tgf 配置系统传入（tgf v2.1.0 的 config.PlatformConfig 尚无 Telegram
// 字段位，需后续版本补充 TelegramBotToken / TelegramWebhookSecretToken 并登记
// sensitiveEnvKeys 脱敏；在此之前由业务自有配置传入 Config），绝不入库、绝不打日志。
package telegram
