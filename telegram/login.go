//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description telegram：LoginProvider——Mini App initData 验签（HMAC-SHA256）+ auth_date 新鲜度 + 身份映射
//2026/6/11
//***************************************************

package telegram

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
	"github.com/thkhxm/tgf/v2/platform"
)

// 操作名（errs.Error.Op）。
const opVerifyInitData = "verify_init_data"

// secretKeyConstant initData 验签密钥派生用的常量串。
// 文档：https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
// （2026-06-11 拉取）：“the secret key, which is the HMAC-SHA-256 signature of
// the bot's token with the constant string WebAppData used as a key”——即
// secret_key = HMAC_SHA256(key="WebAppData", data=bot_token)。
const secretKeyConstant = "WebAppData"

// initData 中的保留字段名。
const (
	fieldHash     = "hash"      // 验签比对目标，不参与 data_check_string
	fieldUser     = "user"      // WebAppUser JSON（登录身份来源）
	fieldAuthDate = "auth_date" // Unix 秒时间戳（新鲜度校验）
)

// webAppUser 是 initData user 字段的 JSON 结构（取登录身份映射需要的子集）。
//
// 字段定义文档：https://core.telegram.org/bots/webapps#webappuser（2026-06-11 拉取）：
//   - id Integer：“A unique identifier for the user or bot… It has at most 52
//     significant bits, so a 64-bit integer … is safe for storing this identifier.”
//     ——必须用 int64 承载，绝不能用 int32；
//   - first_name String（必有）/ last_name、username、language_code、photo_url
//     String（Optional）/ is_premium、allows_write_to_pm True（Optional）。
type webAppUser struct {
	ID              int64  `json:"id"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	Username        string `json:"username"`
	LanguageCode    string `json:"language_code"`
	IsPremium       bool   `json:"is_premium"`
	AllowsWriteToPm bool   `json:"allows_write_to_pm"`
	PhotoURL        string `json:"photo_url"`
}

// VerifyLogin 实现 platform.LoginProvider。
//
// credential 是 Mini App 客户端取到的 Telegram.WebApp.initData 原始 query string
// （客户端原样上送，服务端在这里完成验签）。本方法是纯本地密码学校验，
// 不调任何远端 API。
//
// 验签算法
// 文档：https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
// （2026-06-11 拉取，curl 直连官方正文确认）：
//
//  1. initData 是 query string（“a series of field-value pairs”），解析为字段集；
//  2. data_check_string = 除 hash 外的全部已收到字段，按 key 字母序排列，
//     以 "key=<value>" 格式、'\n'（0x0A）分隔拼接——例
//     'auth_date=<auth_date>\nquery_id=<query_id>\nuser=<user>'；
//     注意：官方仅在「第三方 Ed25519 校验」一节排除 signature 字段，
//     bot_token HMAC 校验路径按官方原文“all received fields”包含 signature；
//  3. secret_key = HMAC_SHA256(key="WebAppData", data=bot_token)；
//  4. hex(HMAC_SHA256(key=secret_key, data=data_check_string)) == hash 即通过
//     （常量时间比较，core/sign）；
//  5. 验签通过后校验 auth_date（“Unix time when the form was opened”）新鲜度，
//     超出 Config.AuthMaxAge 窗口拒绝（官方要求校验防过期，窗口数值为工程取值）。
//
// 身份映射（WebAppInitData / WebAppUser 字段定义同上文档）：
//
//   - OpenID     ← user.id（十进制字符串；Telegram 用户 id 至多 52 个有效位，int64 承载）
//   - UnionID    恒为空（Telegram 无 union id 概念，bot 维度 user.id 即唯一标识）
//   - SessionKey 恒为空（Telegram 无 session_key 概念）
//   - Raw        ← query_id / auth_date / start_param / chat_type / chat_instance
//     及 user 内的 username / first_name / last_name / language_code /
//     is_premium / allows_write_to_pm / photo_url 透传
//
// 注意：initData 在 Mini App 从键盘按钮 / inline 模式启动时为空、user 字段为
// Optional（官方 WebAppInitData 字段表）——缺 user 无法建立登录身份，本方法
// 直接拒绝，业务应引导从带用户上下文的入口（菜单按钮 / inline 按钮 / 直链 /
// 主 Mini App）启动。
func (t *Telegram) VerifyLogin(ctx context.Context, credential string) (*platform.PlatformIdentity, error) {
	_ = ctx // 纯本地校验，无 IO；保留参数以满足合约签名。
	if credential == "" {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "credential（initData）为空")
	}

	// 1. 解析 query string。url.ParseQuery 完成百分号解码——data_check_string
	// 用解码后的值（官方示例 user=<user> 是 JSON 原文，非 URL 编码形态）。
	values, err := url.ParseQuery(credential)
	if err != nil {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "initData 不是合法的 query string").WithCause(err)
	}
	// 防御：正常 initData 字段唯一，重复字段会让 data_check_string 构造产生
	// 歧义（排序后取哪个值），视为协议异常直接拒绝。
	for k, vs := range values {
		if len(vs) > 1 {
			return nil, errs.New(PlatformName, opVerifyInitData, "", "initData 字段重复: "+k)
		}
	}

	hashHex := values.Get(fieldHash)
	if hashHex == "" {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "initData 缺少 hash 字段")
	}

	// 2. data_check_string：除 hash 外全部字段按 key 字母序、"k=v" 以 '\n' 连接。
	keys := make([]string, 0, len(values))
	for k := range values {
		if k == fieldHash {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "initData 除 hash 外无任何字段")
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(values.Get(k))
	}

	// 3-4. 派生密钥并常量时间比对（算法出处见本方法注释；
	// sign.HMACSHA256 形参顺序是 (key, data)）。
	secretKey := sign.HMACSHA256([]byte(secretKeyConstant), []byte(t.cfg.BotToken))
	if !sign.VerifyHMACSHA256Hex(secretKey, []byte(b.String()), hashHex) {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "initData 验签失败（hash 不匹配，疑似伪造或 BotToken 配置错误）")
	}

	// 5. auth_date 新鲜度（验签通过后才检查——auth_date 参与签名，攻击者无法
	// 单独篡改；取绝对偏差，同时拦过旧与超前的异常时钟）。
	authDateStr := values.Get(fieldAuthDate)
	if authDateStr == "" {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "initData 缺少 auth_date 字段")
	}
	authSec, err := strconv.ParseInt(authDateStr, 10, 64)
	if err != nil {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "auth_date 非法: "+truncate(authDateStr, 32)).WithCause(err)
	}
	delta := t.now().Unix() - authSec
	if delta < 0 {
		delta = -delta
	}
	if float64(delta) > t.cfg.AuthMaxAge.Seconds() {
		return nil, errs.New(PlatformName, opVerifyInitData, "",
			"initData 已过期（auth_date 偏差 "+strconv.FormatInt(delta, 10)+"s，窗口 "+t.cfg.AuthMaxAge.String()+"）")
	}

	// 6. 解析 user 字段建立身份（“Complex data types are represented as
	// JSON-serialized objects”——user 是 JSON 化的 WebAppUser）。
	userJSON := values.Get(fieldUser)
	if userJSON == "" {
		return nil, errs.New(PlatformName, opVerifyInitData, "",
			"initData 缺少 user 字段（键盘按钮 / inline 模式启动的 Mini App 无用户上下文，无法登录）")
	}
	var u webAppUser
	if err := json.Unmarshal([]byte(userJSON), &u); err != nil {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "user 字段 JSON 解析失败").WithCause(err)
	}
	if u.ID == 0 {
		return nil, errs.New(PlatformName, opVerifyInitData, "", "user.id 缺失或为 0")
	}

	raw := map[string]string{
		"auth_date":          authDateStr,
		"first_name":         u.FirstName,
		"last_name":          u.LastName,
		"username":           u.Username,
		"language_code":      u.LanguageCode,
		"is_premium":         strconv.FormatBool(u.IsPremium),
		"allows_write_to_pm": strconv.FormatBool(u.AllowsWriteToPm),
		"photo_url":          u.PhotoURL,
	}
	// initData 顶层的会话上下文字段（存在才透传）。
	for _, k := range []string{"query_id", "start_param", "chat_type", "chat_instance"} {
		if v := values.Get(k); v != "" {
			raw[k] = v
		}
	}

	return &platform.PlatformIdentity{
		Platform: PlatformName,
		OpenID:   strconv.FormatInt(u.ID, 10),
		Raw:      raw,
	}, nil
}
