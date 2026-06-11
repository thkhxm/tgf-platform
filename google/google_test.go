//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description google：New 构造器 fail-fast 校验单测
//2026/6/11
//***************************************************

package google

import "testing"

func TestNewValidation(t *testing.T) {
	priv := testRSAKey(t)
	validPEM := pemOfKey(t, priv)

	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "失败_三个能力全未配置",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name: "成功_仅登录",
			cfg:  Config{ClientIDs: []string{"cid"}},
		},
		{
			name: "成功_仅webhook",
			cfg: Config{
				PubSubAudience:            "https://example.com/rtdn",
				PubSubServiceAccountEmail: "push@proj.iam.gserviceaccount.com",
			},
		},
		{
			name: "成功_仅支付",
			cfg: Config{
				PackageName:                 "com.example.app",
				ServiceAccountEmail:         "sa@proj.iam.gserviceaccount.com",
				ServiceAccountPrivateKeyPEM: validPEM,
			},
		},
		{
			name: "失败_支付缺PackageName",
			cfg: Config{
				ServiceAccountEmail:         "sa@proj.iam.gserviceaccount.com",
				ServiceAccountPrivateKeyPEM: validPEM,
			},
			wantErr: true,
		},
		{
			name: "失败_支付缺私钥",
			cfg: Config{
				PackageName:         "com.example.app",
				ServiceAccountEmail: "sa@proj.iam.gserviceaccount.com",
			},
			wantErr: true,
		},
		{
			name: "失败_支付私钥PEM非法",
			cfg: Config{
				PackageName:                 "com.example.app",
				ServiceAccountEmail:         "sa@proj.iam.gserviceaccount.com",
				ServiceAccountPrivateKeyPEM: "not a pem",
			},
			wantErr: true,
		},
		{
			name: "失败_webhook缺audience",
			cfg: Config{
				PubSubServiceAccountEmail: "push@proj.iam.gserviceaccount.com",
			},
			wantErr: true,
		},
		{
			name: "失败_webhook缺服务账号邮箱",
			cfg: Config{
				PubSubAudience: "https://example.com/rtdn",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := New(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("New 应失败，实际成功")
				}
				return
			}
			if err != nil {
				t.Fatalf("New 应成功，实际失败: %v", err)
			}
			if g.Name() != PlatformName {
				t.Errorf("Name() = %q, 期望 %q", g.Name(), PlatformName)
			}
		})
	}
}

func TestMustNewPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustNew 对非法配置应 panic")
		}
	}()
	MustNew(Config{})
}
