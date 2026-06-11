//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description xiaomi：包文档——能力矩阵 / 官方文档来源 / NEEDS-DOC 清单
//2026/6/11
//***************************************************

// Package xiaomi 是 tgf 平台合约层（github.com/thkhxm/tgf/v2/platform）的
// 小米游戏联运（小米游戏 SDK）实现。
//
// # 能力矩阵
//
//	| 合约接口                       | 状态     | 对应平台 API                          |
//	|--------------------------------|----------|---------------------------------------|
//	| platform.LoginProvider         | 已实现   | 5.3.3 用户 session 验证接口 loginvalidate |
//	| platform.PaymentProvider       | 已实现   | 5.3.2 主动查询订单支付状态 queryOrder.do  |
//	| platform.WebhookVerifier       | 已实现   | 5.3.1 订单支付结果通知（验签+窗口+防重放）|
//	| platform.ContentAuditProvider  | NEEDS-DOC| 未发现公开的小米联运内容安全 server API   |
//
// # 官方文档来源（全部 2026-06-11 经 dev.mi.com 官方文档接口拉取正文核对）
//
// 小米开放平台文档站（dev.mi.com）是 JS 渲染的 SPA，正文经其官方数据接口
// https://dev.mi.com/usercenter/doc/article/get/<pId> 获取（与浏览器页面同源同数据）：
//
//   - 《小米游戏SDK3.0接入指南》 https://dev.mi.com/distribute/doc/details?pId=1616
//     —— 5.3.1 订单支付结果通知接口 / 5.3.2 主动查询订单支付状态接口 /
//     5.3.3 用户session验证接口 / 5.3.4 接口格式说明 / 5.3.5 signature签名方法说明 /
//     6.2 服务器签名函数（HMAC-SHA1 参考实现）；
//   - 《小米游戏SDK2.0.2接入指南》 https://dev.mi.com/distribute/doc/details?pId=1662
//     —— 同协议交叉验证（5.3.x 字段、签名规则与 3.0 指南完全一致，且 endpoint 已为 https）；
//   - 《小米游戏渠道服务器升级通知》 https://dev.mi.com/distribute/doc/details?pId=1559
//     —— 官方明确两个服务端接口的 https 地址：
//     https://mis.migc.xiaomi.com/api/biz/service/queryOrder.do 与
//     https://mis.migc.xiaomi.com/api/biz/service/loginvalidate ；
//   - 《小米游戏SDK服务器端接入最佳安全实践》 https://dev.mi.com/distribute/doc/details?pId=1543
//     —— 每次登录必须 session 验证；订单校验务必核对 signature 以及 appId/cpOrderId/uid
//     是否匹配，全部匹配才能发货；同一订单号多次通知只处理一次发货。
//
// # NEEDS-DOC（缺官方正文支撑、需要使用方补充的细节）
//
//   - 任务给定的两个文档页 https://dev.mi.com/distribute/doc/details?pId=1521 与
//     https://dev.mi.com/console/doc/detail?pId=1581 经官方数据接口匿名拉取返回空
//     data（登录墙或已下线）；最新版《小米游戏SDK接入指南》（pId=1377，由已下线的
//     pId=102 跳转指向）同样匿名不可得。本实现以可匿名获取的 3.0/2.0.2 指南 +
//     官方升级通知为准；若小米后台下发的最新接入文档与 5.3.x 协议有出入（新增字段、
//     endpoint 迁移等），请提供该文档正文以便校正。
//   - payTime（格式 yyyy-MM-dd HH:mm:ss）官方未注明时区。本实现默认按北京时间
//     （UTC+8）解析，可经 Config.PayTimeLocation 覆盖；请以贵方后台实测回调为准。
//   - payFee 官方口径是「单位为分，即 0.01 米币」，米币与人民币的兑换比例未在
//     该文档载明。PaymentResult.Currency 默认填 "CNY"（可经 Config.Currency 覆盖），
//     金额按"分"原样透传，请业务侧按运营协议核对。
//   - 5.3.1 官方只给出通知重试节奏（前 10 次每分钟 1 次、之后每小时 1 次），未给出
//     重试总时长上限。webhook 时间戳窗口默认放宽到 24h（DefaultWebhookTolerance），
//     可按实际重试观测调整。
//   - 内容安全审核：未在小米开放平台公开文档中发现联运游戏的文本/图片审核 server
//     API，ContentAuditProvider 不实现；如贵方控制台提供该能力文档，请提供。
//
// # 凭据
//
// AppID / AppSecret 来自小米开发者站「应用提交流程」创建游戏后获得（文档 pId=1616
// 第 2 节：AppId、AppKey 用于客户端 SDK 初始化，AppSecret 用于服务器间通信签名）。
// 业务侧从 tgf 配置系统传入（命名约定 config.Platform.XiaomiAppID /
// XiaomiAppSecret，Secret 类字段须登记 sensitiveEnvKeys 启动日志脱敏），
// 本包绝不直读环境变量、绝不落盘。
package xiaomi
