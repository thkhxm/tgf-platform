//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description taptap：MAC Token 签算单测——待签名串格式 / HMAC-SHA1 标准向量 / nonce / Authorization 头
//2026/6/11
//***************************************************

package taptap

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestBuildSigningString 待签名串必须与官方格式逐字符一致：
// {timestamp}\n{nonce}\n{method}\n{uri}\n{host}\n{port}\n\n
// （ts / nonce 取官方 curl 示例中的值 1618221750 / adssd）。
func TestBuildSigningString(t *testing.T) {
	got := buildSigningString("1618221750", "adssd", "GET",
		"/account/profile/v1?client_id=abc", "open.tapapis.cn", "443")
	want := "1618221750\nadssd\nGET\n/account/profile/v1?client_id=abc\nopen.tapapis.cn\n443\n\n"
	if got != want {
		t.Fatalf("待签名串不符:\ngot  %q\nwant %q", got, want)
	}
	// 末尾必须是两个 \n（官方格式 ...{port}\n\n）——漏掉一个就是永远对不上的签名。
	if !strings.HasSuffix(got, "\n\n") {
		t.Fatalf("待签名串末尾必须是两个换行: %q", got)
	}
}

// TestMACSign_RFC2202Vector 用 RFC 2202 的 HMAC-SHA1 标准测试向量（case 2）
// 校验签算原语：key="Jefe"，data="what do ya want for nothing?"，
// 期望摘要 effcdf6ae5eb2fa2d27416d5f184df9c259a7c79。
func TestMACSign_RFC2202Vector(t *testing.T) {
	got := macSign("what do ya want for nothing?", "Jefe")
	raw, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("macSign 输出不是合法 base64: %v", err)
	}
	if hex.EncodeToString(raw) != "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" {
		t.Fatalf("HMAC-SHA1 摘要不符: %s", hex.EncodeToString(raw))
	}
}

// TestBuildAuthorization Authorization 头格式必须与官方逐字符一致：
// MAC id="{kid}",ts="{timestamp}",nonce="{nonce}",mac="{mac}"
func TestBuildAuthorization(t *testing.T) {
	got := buildAuthorization("kid-1", "1618221750", "adssd", "XWTPmq6A6LzgK8BbNDwj+kE4gzs=")
	want := `MAC id="kid-1",ts="1618221750",nonce="adssd",mac="XWTPmq6A6LzgK8BbNDwj+kE4gzs="`
	if got != want {
		t.Fatalf("Authorization 头不符:\ngot  %s\nwant %s", got, want)
	}
}

// TestRandomNonce 长度 / 字符集 / 两次调用不重复。
func TestRandomNonce(t *testing.T) {
	a, err := randomNonce(defaultNonceLength)
	if err != nil {
		t.Fatalf("randomNonce 失败: %v", err)
	}
	if len(a) != defaultNonceLength {
		t.Fatalf("nonce 长度 = %d, want %d", len(a), defaultNonceLength)
	}
	for _, c := range a {
		if !strings.ContainsRune(nonceChars, c) {
			t.Fatalf("nonce 含非法字符 %q: %s", c, a)
		}
	}
	b, err := randomNonce(defaultNonceLength)
	if err != nil {
		t.Fatalf("randomNonce 失败: %v", err)
	}
	if a == b {
		t.Fatalf("两次 nonce 相同（随机源异常）: %s", a)
	}
}
