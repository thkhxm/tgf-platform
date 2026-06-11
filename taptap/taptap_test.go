//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description taptap：构造器单测——配置校验 / 默认值 / host:port 解析
//2026/6/11
//***************************************************

package taptap

import (
	"strings"
	"testing"
)

// TestNew_Validation 配置校验：必填项缺失 / BaseURL 非法形态一律 fail-fast。
func TestNew_Validation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"缺 ClientID", Config{}, "ClientID 不能为空"},
		{"BaseURL 带路径", Config{ClientID: "c", BaseURL: "https://open.tapapis.cn/api"}, "scheme://host[:port]"},
		{"BaseURL 带查询", Config{ClientID: "c", BaseURL: "https://open.tapapis.cn?a=1"}, "scheme://host[:port]"},
		{"BaseURL scheme 非法", Config{ClientID: "c", BaseURL: "ftp://open.tapapis.cn"}, "scheme"},
		{"BaseURL 缺 host", Config{ClientID: "c", BaseURL: "https://"}, "缺少 host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil {
				t.Fatal("期望错误, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("错误信息应含 %q: %v", tc.wantErr, err)
			}
		})
	}
}

// TestNew_Defaults 默认值：BaseURL 默认国内域名，host/port 解析正确。
func TestNew_Defaults(t *testing.T) {
	tt, err := New(Config{ClientID: "c"})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if tt.cfg.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %s, want %s", tt.cfg.BaseURL, DefaultBaseURL)
	}
	if tt.host != "open.tapapis.cn" || tt.port != "443" {
		t.Errorf("host:port = %s:%s, want open.tapapis.cn:443", tt.host, tt.port)
	}
	if tt.Name() != PlatformName {
		t.Errorf("Name = %s, want %s", tt.Name(), PlatformName)
	}
}

// TestNew_HostPortParsing host/port 解析：显式端口 / http 默认 80 / 末尾斜杠容忍 /
// 海外域名。
func TestNew_HostPortParsing(t *testing.T) {
	cases := []struct {
		baseURL  string
		wantHost string
		wantPort string
	}{
		{"http://127.0.0.1:54321", "127.0.0.1", "54321"},
		{"http://example.com", "example.com", "80"},
		{"https://open.tapapis.cn/", "open.tapapis.cn", "443"},
		{DefaultBaseURLOverseas, "open.tapapis.com", "443"},
	}
	for _, tc := range cases {
		t.Run(tc.baseURL, func(t *testing.T) {
			tt, err := New(Config{ClientID: "c", BaseURL: tc.baseURL})
			if err != nil {
				t.Fatalf("New 失败: %v", err)
			}
			if tt.host != tc.wantHost || tt.port != tc.wantPort {
				t.Errorf("host:port = %s:%s, want %s:%s", tt.host, tt.port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

// TestMustNew 非法配置 panic，合法配置正常返回。
func TestMustNew(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("非法配置应 panic")
		}
	}()
	if got := MustNew(Config{ClientID: "c"}); got == nil {
		t.Error("合法配置应返回实例")
	}
	MustNew(Config{}) // 触发 panic
}
