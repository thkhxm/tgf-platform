//***************************************************
//@Link  https://github.com/thkhxm/tgf-platform
//author tim.huang<thkhxm@gmail.com>
//@Description taptap：VerifyLogin 单测——httptest mock 平台应答（服务端按官方算法重算 MAC 验签）
//2026/6/11
//***************************************************

package taptap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thkhxm/tgf-platform/core/errs"
)

// 测试用凭据。
const (
	testClientID = "test-client-id"
	testKid      = "1/test-kid-value"
	testMacKey   = "test-mac-key-secret"
)

// testCredential 合法的 credential（客户端 Access Token JSON）。
const testCredential = `{"kid":"` + testKid + `","mac_key":"` + testMacKey + `","token_type":"mac","mac_algorithm":"hmac-sha-1","scopes":["basic_info"]}`

// newTestTapTap 构造指向 httptest server 的实例。
func newTestTapTap(t *testing.T, baseURL string, useProfile bool) *TapTap {
	t.Helper()
	tt, err := New(Config{ClientID: testClientID, BaseURL: baseURL, UseProfileAPI: useProfile})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	return tt
}

// parseMACHeader 解析 `MAC id="..",ts="..",nonce="..",mac=".."` 形式的
// Authorization 头，返回字段 map；格式非法时 ok=false。
func parseMACHeader(headerVal string) (map[string]string, bool) {
	rest, found := strings.CutPrefix(headerVal, "MAC ")
	if !found {
		return nil, false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
			return nil, false
		}
		fields[k] = v[1 : len(v)-1]
	}
	if fields["id"] == "" || fields["ts"] == "" || fields["nonce"] == "" || fields["mac"] == "" {
		return nil, false
	}
	return fields, true
}

// verifyMACRequest 在 mock 服务端按官方算法重算 MAC 并核对请求
// （待签名串从真实请求属性重建：method / RequestURI / Host 拆分出的 host+port——
// 与客户端实现相互独立，证明签算与实际请求逐字符一致）。
// 返回空串表示验签通过，否则返回失败原因。
func verifyMACRequest(r *http.Request, macKey string) string {
	fields, ok := parseMACHeader(r.Header.Get("Authorization"))
	if !ok {
		return "Authorization 头格式非法: " + r.Header.Get("Authorization")
	}
	if fields["id"] != testKid {
		return "MAC id 不符: " + fields["id"]
	}
	ts, err := strconv.ParseInt(fields["ts"], 10, 64)
	if err != nil {
		return "ts 非十进制秒: " + fields["ts"]
	}
	if d := time.Now().Unix() - ts; d < -60 || d > 60 {
		return "ts 偏差超过 60s: " + fields["ts"]
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		return "拆分 Host 失败: " + r.Host
	}
	signing := fields["ts"] + "\n" + fields["nonce"] + "\n" + r.Method + "\n" +
		r.URL.RequestURI() + "\n" + host + "\n" + port + "\n\n"
	if macSign(signing, macKey) != fields["mac"] {
		return "MAC 签名比对失败"
	}
	return ""
}

// TestVerifyLogin_Success_FlatBasicInfo 成功：默认走 basic-info 接口，
// 平铺应答形态（官方字段表），服务端验 MAC 通过。
func TestVerifyLogin_Success_FlatBasicInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != basicInfoPath {
			t.Errorf("path = %s, want %s", r.URL.Path, basicInfoPath)
		}
		if got := r.URL.Query().Get("client_id"); got != testClientID {
			t.Errorf("client_id = %s, want %s", got, testClientID)
		}
		if reason := verifyMACRequest(r, testMacKey); reason != "" {
			t.Errorf("MAC 验签失败: %s", reason)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"openid":"open-1","unionid":"union-1"}`))
	}))
	defer srv.Close()

	identity, err := newTestTapTap(t, srv.URL, false).VerifyLogin(context.Background(), testCredential)
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}
	if identity.Platform != PlatformName {
		t.Errorf("Platform = %s, want %s", identity.Platform, PlatformName)
	}
	if identity.OpenID != "open-1" || identity.UnionID != "union-1" {
		t.Errorf("身份映射不符: %+v", identity)
	}
	if identity.SessionKey != "" {
		t.Errorf("SessionKey 应恒为空, got %s", identity.SessionKey)
	}
}

// TestVerifyLogin_Success_WrappedProfile 成功：UseProfileAPI 走 profile 接口，
// data 包封应答形态（TDS 时代线上行为），name/avatar 透传进 Raw。
func TestVerifyLogin_Success_WrappedProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != profilePath {
			t.Errorf("path = %s, want %s", r.URL.Path, profilePath)
		}
		if reason := verifyMACRequest(r, testMacKey); reason != "" {
			t.Errorf("MAC 验签失败: %s", reason)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"name":"玩家甲","avatar":"https://img.example/a.png","openid":"open-2","unionid":"union-2"},"now":1718000000,"success":true}`))
	}))
	defer srv.Close()

	identity, err := newTestTapTap(t, srv.URL, true).VerifyLogin(context.Background(), testCredential)
	if err != nil {
		t.Fatalf("VerifyLogin 失败: %v", err)
	}
	if identity.OpenID != "open-2" || identity.UnionID != "union-2" {
		t.Errorf("身份映射不符: %+v", identity)
	}
	if identity.Raw["name"] != "玩家甲" || identity.Raw["avatar"] != "https://img.example/a.png" {
		t.Errorf("Raw 透传不符: %v", identity.Raw)
	}
}

// TestVerifyLogin_PlatformErrors 平台业务错误码映射与可重试分类
// （错误码表见 login.go retryableAPICode 注释，2026-06-11 拉取）。
func TestVerifyLogin_PlatformErrors(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		body          string
		wantCode      string
		wantRetryable bool
	}{
		{"invalid_request 平铺", http.StatusBadRequest,
			`{"code":100,"error":"invalid_request","error_description":"缺少参数"}`,
			"invalid_request", false},
		{"invalid_time 平铺", http.StatusBadRequest,
			`{"code":100,"error":"invalid_time","error_description":"ts 时间不合法"}`,
			"invalid_time", false},
		{"invalid_client 平铺", http.StatusBadRequest,
			`{"code":100,"error":"invalid_client","error_description":"client_id 无效"}`,
			"invalid_client", false},
		{"access_denied 包封", http.StatusUnauthorized,
			`{"data":{"code":100,"error":"access_denied","error_description":"token 已失效"},"now":1,"success":false}`,
			"access_denied", false},
		{"forbidden 平铺", http.StatusForbidden,
			`{"code":100,"error":"forbidden","error_description":"无权限"}`,
			"forbidden", false},
		{"not_found 平铺", http.StatusNotFound,
			`{"code":100,"error":"not_found","error_description":"资源未发现"}`,
			"not_found", false},
		// server_error 是官方唯一明示可重试的码（建议最多 3 次）。
		{"server_error 包封", http.StatusInternalServerError,
			`{"data":{"code":100,"error":"server_error","error_description":"服务器异常"},"now":1,"success":false}`,
			"server_error", true},
		// HTTP 200 也要按应答体里的业务错误码判定（不能只看 HTTP 状态码）。
		{"insufficient_scope http200", http.StatusOK,
			`{"code":100,"error":"insufficient_scope","error_description":"授权范围不匹配"}`,
			"insufficient_scope", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := newTestTapTap(t, srv.URL, false).VerifyLogin(context.Background(), testCredential)
			if err == nil {
				t.Fatal("期望错误, got nil")
			}
			pe, ok := errs.AsPlatformError(err)
			if !ok {
				t.Fatalf("期望 *errs.Error, got %T: %v", err, err)
			}
			if pe.Code != tc.wantCode {
				t.Errorf("Code = %s, want %s", pe.Code, tc.wantCode)
			}
			if pe.HTTPStatus != tc.status {
				t.Errorf("HTTPStatus = %d, want %d", pe.HTTPStatus, tc.status)
			}
			if errs.IsRetryable(err) != tc.wantRetryable {
				t.Errorf("IsRetryable = %v, want %v", errs.IsRetryable(err), tc.wantRetryable)
			}
		})
	}
}

// TestVerifyLogin_SignatureTampered 验签篡改：客户端用错误的 mac_key 签算
// （等价于凭据被篡改/伪造），服务端按正确密钥重算比对失败 → 拒绝。
func TestVerifyLogin_SignatureTampered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if reason := verifyMACRequest(r, testMacKey); reason != "" {
			// 平台对鉴权失败返回 access_denied（错误码表，2026-06-11 拉取）。
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":100,"error":"access_denied","error_description":"签名校验失败"}`))
			return
		}
		_, _ = w.Write([]byte(`{"openid":"open-1","unionid":"union-1"}`))
	}))
	defer srv.Close()

	tampered := `{"kid":"` + testKid + `","mac_key":"wrong-mac-key"}`
	_, err := newTestTapTap(t, srv.URL, false).VerifyLogin(context.Background(), tampered)
	if err == nil {
		t.Fatal("篡改凭据应失败, got nil")
	}
	if errs.CodeOf(err) != "access_denied" {
		t.Errorf("Code = %s, want access_denied（错误: %v）", errs.CodeOf(err), err)
	}
	if errs.IsRetryable(err) {
		t.Error("access_denied 不应标记可重试")
	}
}

// TestVerifyLogin_ProtocolAnomalies 协议异常应答：缺 openid / success=false 无码 /
// 非 JSON 应答。
func TestVerifyLogin_ProtocolAnomalies(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		body          string
		wantRetryable bool
	}{
		{"200 缺 openid（平铺）", http.StatusOK, `{}`, false},
		{"200 缺 openid（包封）", http.StatusOK, `{"data":{"unionid":"u"},"success":true}`, false},
		{"success=false 无错误码", http.StatusOK, `{"data":{},"now":1,"success":false}`, false},
		{"500 HTML 错误页", http.StatusInternalServerError, `<html>boom</html>`, true},
		{"503 非 JSON", http.StatusServiceUnavailable, `upstream unavailable`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := newTestTapTap(t, srv.URL, false).VerifyLogin(context.Background(), testCredential)
			if err == nil {
				t.Fatal("期望错误, got nil")
			}
			if errs.IsRetryable(err) != tc.wantRetryable {
				t.Errorf("IsRetryable = %v, want %v（错误: %v）", errs.IsRetryable(err), tc.wantRetryable, err)
			}
		})
	}
}

// TestVerifyLogin_TransportError 传输层失败（服务已关闭）→ 可重试错误。
func TestVerifyLogin_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // 立即关闭，制造连接拒绝

	_, err := newTestTapTap(t, srv.URL, false).VerifyLogin(context.Background(), testCredential)
	if err == nil {
		t.Fatal("期望传输层错误, got nil")
	}
	if !errs.IsRetryable(err) {
		t.Errorf("传输层错误应可重试: %v", err)
	}
}

// TestVerifyLogin_BadCredential 非法 credential：一律本地拒绝，不发起任何 HTTP 调用。
func TestVerifyLogin_BadCredential(t *testing.T) {
	cases := []struct {
		name       string
		credential string
		wantMsg    string
	}{
		{"空串", "", "为空"},
		{"非法 JSON", "not-json", "不是合法的 Access Token JSON"},
		{"缺 kid", `{"mac_key":"k"}`, "缺少 kid"},
		{"缺 mac_key", `{"kid":"id"}`, "缺少 mac_key"},
		{"token_type 不支持", `{"kid":"id","mac_key":"k","token_type":"bearer"}`, "不支持的 token_type"},
		{"mac_algorithm 不支持", `{"kid":"id","mac_key":"k","mac_algorithm":"hmac-sha-256"}`, "不支持的 mac_algorithm"},
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	tt := newTestTapTap(t, srv.URL, false)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tt.VerifyLogin(context.Background(), tc.credential)
			if err == nil {
				t.Fatal("期望错误, got nil")
			}
			var pe *errs.Error
			if !errors.As(err, &pe) || pe.Op != opCredential {
				t.Fatalf("期望 op=%s 的平台错误, got %v", opCredential, err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("错误信息应含 %q: %v", tc.wantMsg, err)
			}
			if errs.IsRetryable(err) {
				t.Errorf("credential 错误不应可重试: %v", err)
			}
		})
	}
	if calls != 0 {
		t.Errorf("非法 credential 不应发起 HTTP 调用, 实际调用 %d 次", calls)
	}
}

// TestVerifyLogin_TokenTypeCaseInsensitive token_type / mac_algorithm 大小写不敏感
// （SDK 不同语言序列化可能大小写不同，语义一致即放行）。
func TestVerifyLogin_TokenTypeCaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"openid":"open-1","unionid":"union-1"}`))
	}))
	defer srv.Close()

	cred := `{"kid":"` + testKid + `","mac_key":"` + testMacKey + `","token_type":"MAC","mac_algorithm":"HMAC-SHA-1"}`
	if _, err := newTestTapTap(t, srv.URL, false).VerifyLogin(context.Background(), cred); err != nil {
		t.Fatalf("大小写变体应放行: %v", err)
	}
}

// TestVerifyLogin_ContextCancelled ctx 取消时立即失败。
func TestVerifyLogin_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"openid":"o"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newTestTapTap(t, srv.URL, false).VerifyLogin(ctx, testCredential); err == nil {
		t.Fatal("ctx 已取消应失败, got nil")
	}
}
