//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description wechat：WebhookVerifier——消息推送验签（明文 signature / 安全模式 msg_signature）+ 时间戳窗口 + 防重放 + 密文解密
//2026/6/11
//***************************************************

package wechat

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
	"github.com/thkhxm/tgf-platform/core/sign"
)

// 验签失败的哨兵错误——经 errs.Error 的 Unwrap 链暴露，业务用
// errors.Is(err, wechat.ErrWebhookXxx) 区分失败原因。
var (
	// ErrWebhookMissingParam 请求缺少 signature / msg_signature / timestamp /
	// nonce 等必需查询参数。
	ErrWebhookMissingParam = errors.New("wechat: webhook 缺少必需的签名查询参数")
	// ErrWebhookSignatureMismatch 签名比对失败（Token 不符或参数被篡改）。
	ErrWebhookSignatureMismatch = errors.New("wechat: webhook 签名比对失败")
	// ErrWebhookTimestampOutOfWindow 签名有效但时间戳超出容忍窗口（过旧或超前）。
	ErrWebhookTimestampOutOfWindow = errors.New("wechat: webhook 时间戳超出容忍窗口")
	// ErrWebhookReplayed 防重放拦截：同一签名在窗口内重复出现。
	ErrWebhookReplayed = errors.New("wechat: webhook 重复投递（防重放拦截）")
	// ErrWebhookMissingEncrypt 安全模式请求体中取不到 Encrypt 密文字段。
	ErrWebhookMissingEncrypt = errors.New("wechat: webhook 安全模式请求体缺少 Encrypt 字段")
)

// 操作名（errs.Error.Op）。
const (
	opVerifyWebhook     = "verify_webhook"
	opDecryptWebhook    = "decrypt_webhook"
	opVerifyPayEventSig = "verify_pay_event_sig"
)

// VerifyWebhook 实现 platform.WebhookVerifier：校验微信消息推送回调签名，
// 并按合约硬要求完成时间戳窗口校验 + 重放去重；读过的 Body 在返回前重置，
// 业务 handler 可正常再读。
//
// 微信消息推送协议（开发者服务器接收消息推送）
//
// 文档：https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html
// （2026-06-11 拉取）
//
// URL 验证（配置消息推送时微信发起的 GET）：
//   - 查询参数：signature / timestamp / nonce / echostr；
//   - signature 生成方式：将 Token、timestamp、nonce 三个参数**字典序排序**后
//     拼接成一个字符串做 sha1；
//   - 校验通过后业务须原样返回 echostr（本包只负责验签，回包由业务 handler 做，
//     可用 EchoStr 取值）。
//
// 事件推送（POST）：
//   - 明文模式：URL 带 signature/timestamp/nonce，验签算法与 GET 相同
//     （签名不覆盖包体）；
//   - 安全模式：URL 额外带 encrypt_type=aes 与 msg_signature，包体只含 Encrypt
//     密文（JSON {"Encrypt":...} 或 XML <Encrypt>，取决于 MP 配置的数据格式）；
//     msg_signature = sha1(sort(Token、timestamp、nonce、Encrypt))——官方原文
//     强调「不要使用 signature 验证！」；
//   - 加解密细节见 DecryptWebhookEvent。
//
// 行为按请求形态分派：
//   - GET（URL 验证）：校验 signature；通过后业务应回 echostr（EchoStr 取值）；
//   - POST + encrypt_type=aes（安全模式）：从包体取 Encrypt，校验 msg_signature；
//   - POST 其他（明文/兼容模式明文部分）：校验 signature。
//
// 防重放：官方协议无独立去重凭据，以验签通过的签名值为去重 key（安全模式签名
// 覆盖 timestamp+nonce+密文，明文模式覆盖 timestamp+nonce），窗口 2×WebhookTolerance。
// 注意：微信在业务 5 秒内未回包时会重发同一消息（官方重试机制），重发会被本
// 去重拦截——业务必须保证 handler 在时限内回包，依赖重发兜底的场景应经
// Config.WebhookSeen 注入自定义去重策略。
//
// 本方法只完成「请求确实来自微信且非重放」的校验。安全模式包体解密
// （DecryptWebhookEvent）、支付事件的 PayEventSig 校验（VerifyPayEventSig）、
// 事件内容核对与幂等发货由业务在验签通过后自行完成。
func (w *WeChat) VerifyWebhook(r *http.Request) error {
	if w.cfg.PushToken == "" {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"Config.PushToken 未配置（MP-开发管理-消息推送配置的 Token）")
	}
	q := r.URL.Query()
	timestamp := q.Get("timestamp")
	nonce := q.Get("nonce")
	if timestamp == "" || nonce == "" {
		return errs.New(PlatformName, opVerifyWebhook, "", "缺少 timestamp / nonce 查询参数").
			WithCause(ErrWebhookMissingParam)
	}

	var gotSig string
	var parts []string
	if r.Method == http.MethodPost && q.Get("encrypt_type") == "aes" {
		// 安全模式：必须用 msg_signature（官方原文「不要使用 signature 验证！」），
		// 签名材料含包体里的 Encrypt 密文。
		gotSig = q.Get("msg_signature")
		if gotSig == "" {
			return errs.New(PlatformName, opVerifyWebhook, "", "安全模式缺少 msg_signature 查询参数").
				WithCause(ErrWebhookMissingParam)
		}
		raw, err := readAndRestoreBody(r, w.cfg.WebhookMaxBodySize)
		if err != nil {
			return errs.Wrap(PlatformName, opVerifyWebhook, err)
		}
		encrypt, ok := extractEncrypt(raw)
		if !ok {
			return errs.New(PlatformName, opVerifyWebhook, "",
				"安全模式请求体缺少 Encrypt 字段: "+truncate(string(raw), 128)).
				WithCause(ErrWebhookMissingEncrypt)
		}
		parts = []string{w.cfg.PushToken, timestamp, nonce, encrypt}
	} else {
		// GET URL 验证 / POST 明文模式：signature 只覆盖 token+timestamp+nonce。
		gotSig = q.Get("signature")
		if gotSig == "" {
			return errs.New(PlatformName, opVerifyWebhook, "", "缺少 signature 查询参数").
				WithCause(ErrWebhookMissingParam)
		}
		if r.Method == http.MethodPost {
			// 明文模式签名不覆盖包体，但仍按合约把 Body 读出并重置，保证
			// 业务 handler 侧行为一致（也顺带做了体积上限防护）。
			if _, err := readAndRestoreBody(r, w.cfg.WebhookMaxBodySize); err != nil {
				return errs.Wrap(PlatformName, opVerifyWebhook, err)
			}
		}
		parts = []string{w.cfg.PushToken, timestamp, nonce}
	}

	// 字典序排序 → 拼接 → sha1（官方算法），常量时间比对。
	if !sign.ConstantTimeEqualString(sha1SortJoinHex(parts), strings.ToLower(gotSig)) {
		return errs.New(PlatformName, opVerifyWebhook, "", "签名比对失败").
			WithCause(ErrWebhookSignatureMismatch)
	}

	// 时间戳窗口（先验签再查新鲜度：timestamp 参与签名，攻击者无法单独篡改）。
	tsSec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errs.New(PlatformName, opVerifyWebhook, "", "时间戳非法: "+truncate(timestamp, 32)).
			WithCause(ErrWebhookMissingParam)
	}
	delta := w.now().Unix() - tsSec
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > w.cfg.WebhookTolerance {
		return errs.New(PlatformName, opVerifyWebhook, "",
			"时间戳超出容忍窗口 "+w.cfg.WebhookTolerance.String()+"（偏差 "+strconv.FormatInt(delta, 10)+"s）").
			WithCause(ErrWebhookTimestampOutOfWindow)
	}

	// 防重放去重——只对验签通过的请求记账（垃圾签名进不了去重表）。
	// 去重窗口取 2×容忍窗口：窗口边缘的合法请求过期出表后，其重放已被时间戳
	// 窗口拦截，两道闸无缝衔接。
	if w.seen(strings.ToLower(gotSig), 2*w.cfg.WebhookTolerance) {
		return errs.New(PlatformName, opVerifyWebhook, "", "重复投递（防重放拦截）").
			WithCause(ErrWebhookReplayed)
	}
	return nil
}

// EchoStr 返回 URL 验证请求（GET）携带的 echostr——VerifyWebhook 通过后业务
// 应把它原样写回响应体完成配置验证（官方流程，协议见 VerifyWebhook 注释）。
func EchoStr(r *http.Request) string {
	return r.URL.Query().Get("echostr")
}

// DecryptWebhookEvent 解密安全模式包体中的 Encrypt 密文，返回事件明文
// （JSON 或 XML，取决于 MP 配置的数据格式），并校验尾部 appid 与 Config.AppID
// 一致（官方要求开发者验证）。
//
// 算法（官方文档逐条对照）：
//
// 文档：https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/2.0/api/Before_Develop/Technical_Plan.html
// 与 https://developers.weixin.qq.com/miniprogram/dev/framework/server-ability/message-push.html
// （均 2026-06-11 拉取）
//  1. AESKey = Base64_Decode(EncodingAESKey + "=")——EncodingAESKey 长度固定
//     43 字符，补一个 "=" 后解出 32 字节 AESKey；
//  2. TmpMsg = Base64_Decode(Encrypt)；
//  3. FullStr = AES_Decrypt(TmpMsg)——AES-256-CBC；IV 为 AESKey 前 16 字节
//     （正文未明示，经官方加解密示例代码包
//     https://wximg.gtimg.com/shake_tv/mpwiki/cryptoDemo.zip 的 WXBizMsgCrypt.py
//     确认：AES.new(self.key, MODE_CBC, self.key[:16])，2026-06-11 下载）；
//     填充为 PKCS#7 且 **K=32**（官方原文「K 为秘钥字节数（采用 32）」——
//     填充长度可达 32，不能按 AES 块长 16 去填充校验）；
//  4. FullStr = random(16B) + msg_len(4B, 网络字节序) + msg + appid；
//  5. 校验尾部 appid 与自身一致后，截出 msg 明文。
func (w *WeChat) DecryptWebhookEvent(encryptB64 string) ([]byte, error) {
	if w.cfg.EncodingAESKey == "" {
		return nil, errs.New(PlatformName, opDecryptWebhook, "",
			"Config.EncodingAESKey 未配置（MP-消息推送配置，43 字符）")
	}
	aesKey, err := base64.StdEncoding.DecodeString(w.cfg.EncodingAESKey + "=")
	if err != nil || len(aesKey) != 32 {
		return nil, errs.New(PlatformName, opDecryptWebhook, "",
			"EncodingAESKey 非法（应为 43 字符 base64，补 = 后解出 32 字节）")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encryptB64)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opDecryptWebhook, err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errs.Wrap(PlatformName, opDecryptWebhook, err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errs.New(PlatformName, opDecryptWebhook, "",
			"密文长度非法（须为 16 的非零整数倍，实际 "+strconv.Itoa(len(ciphertext))+"）")
	}
	full := make([]byte, len(ciphertext))
	// IV = AESKey 前 16 字节（官方示例代码确认，见方法注释第 3 条）。
	cipher.NewCBCDecrypter(block, aesKey[:aes.BlockSize]).CryptBlocks(full, ciphertext)

	// 去 PKCS#7 填充（K=32，官方原文；不能复用按块长 16 校验的通用实现）。
	full, err = pkcs7UnpadK32(full)
	if err != nil {
		return nil, errs.New(PlatformName, opDecryptWebhook, "", err.Error())
	}

	// FullStr = random(16B) + msg_len(4B, BigEndian) + msg + appid。
	if len(full) < 20 {
		return nil, errs.New(PlatformName, opDecryptWebhook, "",
			"明文过短（不足 random16+msg_len4 头部）")
	}
	msgLen := binary.BigEndian.Uint32(full[16:20])
	if int(msgLen) > len(full)-20 {
		return nil, errs.New(PlatformName, opDecryptWebhook, "",
			"msg_len 越界: "+strconv.FormatUint(uint64(msgLen), 10))
	}
	msg := full[20 : 20+msgLen]
	appID := string(full[20+msgLen:])
	// 官方要求：开发者需验证尾部 appid 是否与自身相符（防其他应用密文串投）。
	if appID != w.cfg.AppID {
		return nil, errs.New(PlatformName, opDecryptWebhook, "",
			"密文尾部 appid 与配置不符（疑似串投）: "+truncate(appID, 64))
	}
	return msg, nil
}

// VerifyPayEventSig 校验支付类订阅事件的 PayEventSig（业务在 VerifyWebhook
// 验签通过、解出事件后，对 MiniGame.Payload 做第二道支付级验签）。
//
// 文档：https://developers.weixin.qq.com/minigame/dev/guide/open-ability/virtual-payment/event.html
// （2026-06-11 拉取）
//   - pay_event_sig = to_hex(hmac_sha256(app_key, event + "&" + payload))；
//   - event 为事件类型（如 minigame_coin_deliver_completed 代币发货完成、
//     minigame_pay_refund_succ_notify 退款成功）；
//   - payload 为 MiniGame.Payload 原文（固定为 JSON 序列化结果，与消息推送
//     配置的格式无关——哪怕配置 XML，Payload 内容仍是 JSON 字符串）；
//   - app_key 为 Payload 内 Env 对应环境的 AppKey（MP-支付基础配置）——
//     业务先解析 Payload 拿到 Env 再调本方法。
func (w *WeChat) VerifyPayEventSig(env int, event, payload, payEventSig string) error {
	appKey := w.cfg.AppKey
	if env == EnvSandbox {
		appKey = w.cfg.SandboxAppKey
	}
	if appKey == "" {
		return errs.New(PlatformName, opVerifyPayEventSig, "",
			"环境（env="+strconv.Itoa(env)+"）对应的 AppKey 未配置（MP-支付基础配置）")
	}
	if event == "" || payEventSig == "" {
		return errs.New(PlatformName, opVerifyPayEventSig, "", "event / payEventSig 为空")
	}
	if !sign.VerifyHMACSHA256Hex([]byte(appKey), []byte(event+"&"+payload), payEventSig) {
		return errs.New(PlatformName, opVerifyPayEventSig, "", "PayEventSig 比对失败").
			WithCause(ErrWebhookSignatureMismatch)
	}
	return nil
}

// sha1SortJoinHex 官方验签原语：字典序排序 → 无分隔拼接 → sha1 → 小写 hex。
func sha1SortJoinHex(parts []string) string {
	sorted := append([]string(nil), parts...)
	sort.Strings(sorted)
	sum := sha1.Sum([]byte(strings.Join(sorted, "")))
	return hex.EncodeToString(sum[:])
}

// encryptEnvelope 安全模式包体的 Encrypt 字段封装（JSON 与 XML 双格式，
// 取决于 MP 消息推送配置的数据格式）。
type encryptEnvelopeJSON struct {
	Encrypt string `json:"Encrypt"`
}
type encryptEnvelopeXML struct {
	Encrypt string `xml:"Encrypt"`
}

// extractEncrypt 从安全模式包体中提取 Encrypt 密文（先按 JSON、再按 XML 解析）。
func extractEncrypt(body []byte) (string, bool) {
	var j encryptEnvelopeJSON
	if err := json.Unmarshal(body, &j); err == nil && j.Encrypt != "" {
		return j.Encrypt, true
	}
	var x encryptEnvelopeXML
	if err := xml.Unmarshal(body, &x); err == nil && x.Encrypt != "" {
		return x.Encrypt, true
	}
	return "", false
}

// pkcs7UnpadK32 去除 K=32 的 PKCS#7 填充（微信消息加解密专用，官方原文
// 「K 为秘钥字节数（采用 32）」；填充长度 1..32，每个填充字节值等于填充长度）。
func pkcs7UnpadK32(data []byte) ([]byte, error) {
	const k = 32
	if len(data) == 0 {
		return nil, errors.New("PKCS#7 数据为空")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > k || padLen > len(data) {
		return nil, errors.New("PKCS#7 填充长度非法: " + strconv.Itoa(padLen))
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("PKCS#7 填充内容非法")
		}
	}
	return data[:len(data)-padLen], nil
}

// readAndRestoreBody 全量读取请求 body（上限 maxSize 字节）并重置 r.Body。
// body 为 nil 时按空 payload 处理（同样重置，保证 handler 侧行为一致）。
func readAndRestoreBody(r *http.Request, maxSize int64) ([]byte, error) {
	if r.Body == nil {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return nil, nil
	}
	// 多读 1 字节用于精确判定“恰好超限”。
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxSize+1))
	_ = r.Body.Close()
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if int64(len(raw)) > maxSize {
		return nil, errors.New("回调体超过上限 " + strconv.FormatInt(maxSize, 10) + " 字节")
	}
	return raw, nil
}
