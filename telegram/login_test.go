//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description telegram：VerifyLogin 单测——已知向量 / 篡改 / 缺字段 / 过期，表驱动
//2026/6/11
//***************************************************

package telegram

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// 单测用 bot token（假凭据，仅本测试使用）。
const testBotToken = "7000000001:AAFakeTokenForUnitTest_0123456789AB"

// knownVector 是用 Python（hmac/hashlib/urllib，独立于本 Go 实现）按官方算法
// （https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app ，
// 2026-06-11 拉取）预生成的已知向量——防止"用实现验证实现"的循环。
// 字段：query_id / user / auth_date=1749600000 / signature / start_param。
const knownVectorInitData = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A123456789%2C%22first_name%22%3A%22Tim%22%2C%22last_name%22%3A%22H%22%2C%22username%22%3A%22timh%22%2C%22language_code%22%3A%22zh-hans%22%2C%22is_premium%22%3Atrue%2C%22allows_write_to_pm%22%3Atrue%7D&auth_date=1749600000&signature=fakeEd25519SignatureBase64url&start_param=ref_abc&hash=5e5c2dab1884f9a66f9520b92105a3543b79df1df9d7a3180af22330ef7ca1c3"

// knownVectorAuthTime 已知向量的 auth_date 时刻（固定时钟基准）。
var knownVectorAuthTime = time.Unix(1749600000, 0)

// newTestTelegram 构造固定时钟的被测实例。
func newTestTelegram(t *testing.T, cfg Config, now time.Time) *Telegram {
	t.Helper()
	if cfg.BotToken == "" {
		cfg.BotToken = testBotToken
	}
	tg, err := New(cfg)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	tg.now = func() time.Time { return now }
	return tg
}

// buildInitData 按官方算法（文档同 knownVector 注释）构造合法 initData——
// 用标准库 crypto 原语直接实现，不复用被测代码路径。
func buildInitData(t *testing.T, botToken string, fields map[string]string) string {
	t.Helper()
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+fields[k])
	}
	dcs := strings.Join(pairs, "\n")
	mac := hmac.New(sha256.New, []byte("WebAppData"))
	mac.Write([]byte(botToken))
	secret := mac.Sum(nil)
	mac2 := hmac.New(sha256.New, secret)
	mac2.Write([]byte(dcs))
	h := hex.EncodeToString(mac2.Sum(nil))

	v := url.Values{}
	for k, val := range fields {
		v.Set(k, val)
	}
	v.Set("hash", h)
	return v.Encode()
}

// defaultFields 返回一组合法字段（auth_date 固定 1749600000）。
func defaultFields() map[string]string {
	return map[string]string{
		"query_id":  "AAHdF6IQAAAAAN0XohDhrOrc",
		"user":      `{"id":987654321,"first_name":"Ann","username":"ann_t","language_code":"en"}`,
		"auth_date": "1749600000",
	}
}

func TestVerifyLogin_KnownVector(t *testing.T) {
	tg := newTestTelegram(t, Config{}, knownVectorAuthTime.Add(5*time.Minute))
	id, err := tg.VerifyLogin(context.Background(), knownVectorInitData)
	if err != nil {
		t.Fatalf("已知向量验签应通过，得到错误: %v", err)
	}
	if id.Platform != PlatformName {
		t.Errorf("Platform = %q, 期望 %q", id.Platform, PlatformName)
	}
	if id.OpenID != "123456789" {
		t.Errorf("OpenID = %q, 期望 123456789", id.OpenID)
	}
	if id.UnionID != "" || id.SessionKey != "" {
		t.Errorf("UnionID/SessionKey 应为空, 得到 %q/%q", id.UnionID, id.SessionKey)
	}
	wantRaw := map[string]string{
		"username":           "timh",
		"first_name":         "Tim",
		"last_name":          "H",
		"language_code":      "zh-hans",
		"is_premium":         "true",
		"allows_write_to_pm": "true",
		"query_id":           "AAHdF6IQAAAAAN0XohDhrOrc",
		"start_param":        "ref_abc",
		"auth_date":          "1749600000",
	}
	for k, want := range wantRaw {
		if got := id.Raw[k]; got != want {
			t.Errorf("Raw[%q] = %q, 期望 %q", k, got, want)
		}
	}
}

func TestVerifyLogin_TableDriven(t *testing.T) {
	base := defaultFields()

	tests := []struct {
		name string
		// initData 构造器（返回送入 VerifyLogin 的 credential）
		build func(t *testing.T) string
		// now 固定时钟（零值用 knownVectorAuthTime+5min）
		now time.Time
		// wantErrSub 期望错误信息包含的片段；空串表示期望成功
		wantErrSub string
		// check 成功时的额外断言
		check func(t *testing.T, openID string)
	}{
		{
			name: "成功_合法initData",
			build: func(t *testing.T) string {
				return buildInitData(t, testBotToken, base)
			},
			check: func(t *testing.T, openID string) {
				if openID != "987654321" {
					t.Errorf("OpenID = %q, 期望 987654321", openID)
				}
			},
		},
		{
			name: "失败_credential为空",
			build: func(t *testing.T) string {
				return ""
			},
			wantErrSub: "为空",
		},
		{
			name: "失败_user字段被篡改",
			build: func(t *testing.T) string {
				good := buildInitData(t, testBotToken, base)
				// 篡改 user 内的 id（保持 hash 不变）
				return strings.Replace(good, "987654321", "111111111", 1)
			},
			wantErrSub: "验签失败",
		},
		{
			name: "失败_hash被篡改",
			build: func(t *testing.T) string {
				good := buildInitData(t, testBotToken, base)
				v, _ := url.ParseQuery(good)
				v.Set("hash", strings.Repeat("0", 64))
				return v.Encode()
			},
			wantErrSub: "验签失败",
		},
		{
			name: "失败_hash非hex",
			build: func(t *testing.T) string {
				good := buildInitData(t, testBotToken, base)
				v, _ := url.ParseQuery(good)
				v.Set("hash", "not-hex!!")
				return v.Encode()
			},
			wantErrSub: "验签失败",
		},
		{
			name: "失败_缺少hash字段",
			build: func(t *testing.T) string {
				v := url.Values{}
				for k, val := range base {
					v.Set(k, val)
				}
				return v.Encode()
			},
			wantErrSub: "缺少 hash",
		},
		{
			name: "失败_BotToken不匹配",
			build: func(t *testing.T) string {
				return buildInitData(t, "8000000002:AnotherBotTokenXYZ", base)
			},
			wantErrSub: "验签失败",
		},
		{
			name: "失败_auth_date过期",
			build: func(t *testing.T) string {
				return buildInitData(t, testBotToken, base)
			},
			now:        knownVectorAuthTime.Add(2 * time.Hour), // 超默认 1h 窗口
			wantErrSub: "已过期",
		},
		{
			name: "失败_缺少auth_date",
			build: func(t *testing.T) string {
				f := map[string]string{"query_id": base["query_id"], "user": base["user"]}
				return buildInitData(t, testBotToken, f)
			},
			wantErrSub: "缺少 auth_date",
		},
		{
			name: "失败_auth_date非数字",
			build: func(t *testing.T) string {
				f := map[string]string{"user": base["user"], "auth_date": "yesterday"}
				return buildInitData(t, testBotToken, f)
			},
			wantErrSub: "auth_date 非法",
		},
		{
			name: "失败_缺少user字段",
			build: func(t *testing.T) string {
				f := map[string]string{"query_id": base["query_id"], "auth_date": base["auth_date"]}
				return buildInitData(t, testBotToken, f)
			},
			wantErrSub: "缺少 user",
		},
		{
			name: "失败_userJSON非法",
			build: func(t *testing.T) string {
				f := map[string]string{"user": "{not-json", "auth_date": base["auth_date"]}
				return buildInitData(t, testBotToken, f)
			},
			wantErrSub: "JSON 解析失败",
		},
		{
			name: "失败_user缺id",
			build: func(t *testing.T) string {
				f := map[string]string{"user": `{"first_name":"NoID"}`, "auth_date": base["auth_date"]}
				return buildInitData(t, testBotToken, f)
			},
			wantErrSub: "user.id 缺失",
		},
		{
			name: "失败_重复字段",
			build: func(t *testing.T) string {
				good := buildInitData(t, testBotToken, base)
				return good + "&auth_date=1749600001"
			},
			wantErrSub: "字段重复",
		},
		{
			name: "失败_非法query string",
			build: func(t *testing.T) string {
				return "a=%zz;%%"
			},
			wantErrSub: "query string",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock := tc.now
			if clock.IsZero() {
				clock = knownVectorAuthTime.Add(5 * time.Minute)
			}
			tg := newTestTelegram(t, Config{}, clock)
			id, err := tg.VerifyLogin(context.Background(), tc.build(t))
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("期望成功, 得到错误: %v", err)
				}
				if tc.check != nil {
					tc.check(t, id.OpenID)
				}
				return
			}
			if err == nil {
				t.Fatalf("期望错误（包含 %q）, 得到成功: %+v", tc.wantErrSub, id)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("错误信息 %q 不含 %q", err.Error(), tc.wantErrSub)
			}
			// 错误必须是平台统一错误类型
			if _, ok := errs.AsPlatformError(err); !ok {
				t.Errorf("错误未包装为 *errs.Error: %v", err)
			}
		})
	}
}

// TestVerifyLogin_AuthMaxAgeConfigurable 验证自定义新鲜度窗口生效。
func TestVerifyLogin_AuthMaxAgeConfigurable(t *testing.T) {
	base := defaultFields()
	initData := buildInitData(t, testBotToken, base)

	// 窗口 10 分钟，偏差 5 分钟 → 通过
	tg := newTestTelegram(t, Config{AuthMaxAge: 10 * time.Minute}, knownVectorAuthTime.Add(5*time.Minute))
	if _, err := tg.VerifyLogin(context.Background(), initData); err != nil {
		t.Fatalf("窗口内应通过: %v", err)
	}
	// 窗口 10 分钟，偏差 11 分钟 → 拒绝
	tg2 := newTestTelegram(t, Config{AuthMaxAge: 10 * time.Minute}, knownVectorAuthTime.Add(11*time.Minute))
	if _, err := tg2.VerifyLogin(context.Background(), initData); err == nil {
		t.Fatal("超窗口应拒绝")
	}
}
