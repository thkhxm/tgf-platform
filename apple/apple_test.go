//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description apple：构造器校验单测
//2026/6/11
//***************************************************

package apple

import (
	"strings"
	"testing"
)

func TestNew_Validation(t *testing.T) {
	key := genECKey(t)
	validP8 := p8PEM(t, key)

	tests := []struct {
		name    string
		cfg     Config
		wantErr string // 空串 = 期望成功
	}{
		{
			name:    "全空凭据报错",
			cfg:     Config{},
			wantErr: "至少配置一组凭据",
		},
		{
			name: "仅登录凭据成功",
			cfg:  Config{ClientID: "com.test.app"},
		},
		{
			name: "支付四件套全配成功",
			cfg: Config{
				IssuerID: "issuer-1", KeyID: "KEY123", PrivateKeyP8: validP8, BundleID: "com.test.app",
			},
		},
		{
			name:    "支付凭据半配报错",
			cfg:     Config{IssuerID: "issuer-1", KeyID: "KEY123"},
			wantErr: "支付凭据不完整",
		},
		{
			name: "p8 私钥非法报错",
			cfg: Config{
				IssuerID: "issuer-1", KeyID: "KEY123", PrivateKeyP8: "不是 PEM", BundleID: "com.test.app",
			},
			wantErr: "PrivateKeyP8 解析失败",
		},
		{
			name: "登录与支付同时配置成功",
			cfg: Config{
				ClientID: "com.test.app",
				IssuerID: "issuer-1", KeyID: "KEY123", PrivateKeyP8: validP8, BundleID: "com.test.app",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("期望成功，实际错误: %v", err)
				}
				if a.Name() != PlatformName {
					t.Fatalf("Name() = %q，期望 %q", a.Name(), PlatformName)
				}
				return
			}
			if err == nil {
				t.Fatalf("期望错误（含 %q），实际成功", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误信息 %q 不含期望片段 %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestNew_BuiltinAppleRootCA(t *testing.T) {
	// 内置 Apple Root CA - G3（真实 DER）必须能解析成信任池。
	pool, err := appleRootPool()
	if err != nil {
		t.Fatalf("内置 Apple Root CA - G3 构造失败: %v", err)
	}
	if pool == nil {
		t.Fatal("信任池为 nil")
	}
}

func TestMustNew_PanicOnBadConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("期望 MustNew 对非法配置 panic")
		}
	}()
	MustNew(Config{})
}

func TestMinorUnits(t *testing.T) {
	// 官方示例核对（https://developer.apple.com/documentation/appstoreserverapi/price ，
	// 2026-06-11 拉取）：$1.99→1990、JPY 300→300000、KRW 3300→3300000。
	tests := []struct {
		price    int64
		currency string
		want     int64
	}{
		{1990, "USD", 199},     // 2 位小数：199 cents
		{300000, "JPY", 300},   // 0 位小数：300 yen
		{3300000, "KRW", 3300}, // 0 位小数：3300 won
		{1000, "KWD", 1000},    // 3 位小数：1.000 KWD = 1000 fils
		{1990, "CNY", 199},     // 默认 2 位：1.99 元 = 199 分
		{1990, "XYZ", 199},     // 未知货币按默认 2 位
		{0, "USD", 0},          // 零价
		{12340, "CLF", 123400}, // 4 位小数
	}
	for _, tc := range tests {
		if got := minorUnits(tc.price, tc.currency); got != tc.want {
			t.Errorf("minorUnits(%d, %s) = %d，期望 %d", tc.price, tc.currency, got, tc.want)
		}
	}
}
