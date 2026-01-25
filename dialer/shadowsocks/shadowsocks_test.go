package shadowsocks

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var initOnce sync.Once

const (
	ssLegacyLinkExample = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@example.com:8388/#Example_Legacy_SIP002"
	ss2022LinkExample  = "ss://MjAyMi1ibGFrZTMtY2hhY2hhMjAtcG9seTEzMDU6QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQT0=@example.com:8388/#Example_SS2022"
)

func initDirect() {
	initOnce.Do(func() {
		direct.InitDirectDialers("")
	})
}

// TestParseSSURL 测试 ss:// 链接解析
func TestParseSSURL(t *testing.T) {
	tests := []struct {
		name       string
		link       string
		wantCipher string
		wantServer string
		wantPort   int
		wantName   string
		wantErr    bool
	}{
		{
			name:       "标准 SIP002 格式",
			link:       ssLegacyLinkExample,
			wantCipher: "chacha20-ietf-poly1305",
			wantServer: "example.com",
			wantPort:   8388,
			wantName:   "Example_Legacy_SIP002",
			wantErr:    false,
		},
		{
			name:       "简单格式",
			link:       "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#TestNode",
			wantCipher: "aes-256-gcm",
			wantServer: "example.com",
			wantPort:   8388,
			wantName:   "TestNode",
			wantErr:    false,
		},
		{
			name:    "无效链接",
			link:    "ss://invalid",
			wantErr: true,
		},
		{
			name:       "SS2022 ChaCha20 格式",
			link:       ss2022LinkExample,
			wantCipher: "2022-blake3-chacha20-poly1305",
			wantServer: "example.com",
			wantPort:   8388,
			wantName:   "Example_SS2022",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss, err := ParseSSURL(tt.link)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCipher, ss.Cipher)
			assert.Equal(t, tt.wantServer, ss.Server)
			assert.Equal(t, tt.wantPort, ss.Port)
			assert.Equal(t, tt.wantName, ss.Name)
			t.Logf("解析结果: Cipher=%s, Server=%s:%d, Password=%s, Name=%s",
				ss.Cipher, ss.Server, ss.Port, ss.Password, ss.Name)
		})
	}
}

// TestNewDialerFromLink 测试从链接创建 Dialer
func TestNewDialerFromLink(t *testing.T) {
	initDirect()
	link := ssLegacyLinkExample

	d, prop, err := NewShadowsocksFromLink(nil, direct.SymmetricDirect, link)
	require.NoError(t, err, "创建 Dialer 失败")

	t.Logf("Dialer 创建成功:")
	t.Logf("  Name: %s", prop.Name)
	t.Logf("  Protocol: %s", prop.Protocol)
	t.Logf("  Address: %s", prop.Address)
	t.Logf("  Link: %s", prop.Link)

	assert.NotNil(t, d)
	assert.Equal(t, "Example_Legacy_SIP002", prop.Name)
	assert.Equal(t, "shadowsocks", prop.Protocol)
}

// TestSSConnection 测试实际连接（需要代理服务器在线）
// 运行: go test -v -run TestSSConnection ./dialer/shadowsocks/
func TestSSConnection(t *testing.T) {
	initDirect()
	if testing.Short() {
		t.Skip("跳过连接测试（使用 -short 标志）")
	}

	links := getTestLinks()
	if allPlaceholderLinks(links) {
		t.Skip("未设置 SS_TEST_LINKS，跳过真实连接测试")
	}

	// 创建 HTTP 客户端（每个节点设置自己的 Transport）
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 测试连接
	testURLs := []string{
		"https://www.google.com",
		"https://api.ipify.org?format=json",
	}

	for _, link := range links {
		d, prop, err := NewShadowsocksFromLink(nil, direct.SymmetricDirect, link)
		require.NoError(t, err, "创建 Dialer 失败")
		t.Logf("使用节点: %s (%s)", prop.Name, prop.Address)

		// 绑定当前节点的 dialer
		client.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				t.Logf("正在连接: %s %s", network, addr)
				conn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{Conn: conn}, nil
			},
		}

		for _, url := range testURLs {
			t.Run(prop.Name+" "+url, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				require.NoError(t, err)

				resp, err := client.Do(req)
				if err != nil {
					t.Logf("连接失败: %v", err)
					t.FailNow()
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				t.Logf("状态码: %d", resp.StatusCode)
				t.Logf("响应: %s", truncate(body, 200))

				assert.Equal(t, http.StatusOK, resp.StatusCode)
			})
		}
	}
}

// TestSSConnectionTCP 测试 TCP 原始连接
func TestSSConnectionTCP(t *testing.T) {
	initDirect()
	if testing.Short() {
		t.Skip("跳过连接测试")
	}

	links := getTestLinks()
	if allPlaceholderLinks(links) {
		t.Skip("未设置 SS_TEST_LINKS，跳过真实连接测试")
	}

	for _, link := range links {
		d, prop, err := NewShadowsocksFromLink(nil, direct.SymmetricDirect, link)
		require.NoError(t, err)

		t.Run(prop.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// 连接到一个简单的 TCP 服务
			conn, err := d.DialContext(ctx, "tcp", "httpbin.org:80")
			if err != nil {
				t.Fatalf("TCP 连接失败: %v", err)
			}
			defer conn.Close()

			// 发送简单的 HTTP 请求
			_, err = conn.Write([]byte("GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"))
			require.NoError(t, err)

			// 读取响应
			buf := new(bytes.Buffer)
			_, err = io.Copy(buf, conn)
			require.NoError(t, err)

			t.Logf("TCP 响应:\n%s", truncate(buf.Bytes(), 500))
			assert.Contains(t, buf.String(), "HTTP/1.1")
		})
	}
}

// TestDialerExport 测试链接导出
func TestDialerExport(t *testing.T) {
	link := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@example.com:8388/#TestExport"

	ss, err := ParseSSURL(link)
	require.NoError(t, err)

	exported := ss.ExportToURL()
	t.Logf("原链接: %s", link)
	t.Logf("导出链接: %s", exported)

	// 验证导出的链接可以被重新解析
	ss2, err := ParseSSURL(exported)
	require.NoError(t, err)
	assert.Equal(t, ss.Cipher, ss2.Cipher)
	assert.Equal(t, ss.Password, ss2.Password)
	assert.Equal(t, ss.Server, ss2.Server)
	assert.Equal(t, ss.Port, ss2.Port)
}

// TestWithCustomDialer 使用 dialer.NewNetproxyDialerFromLink 的完整测试
func TestWithCustomDialer(t *testing.T) {
	initDirect()
	link := ssLegacyLinkExample

	// 使用主入口函数
	d, prop, err := dialer.NewNetproxyDialerFromLink(direct.SymmetricDirect, nil, link)
	require.NoError(t, err)

	t.Logf("通过 NewNetproxyDialerFromLink 创建:")
	t.Logf("  Name: %s", prop.Name)
	t.Logf("  Protocol: %s", prop.Protocol)
	t.Logf("  Address: %s", prop.Address)

	assert.NotNil(t, d)
}

func truncate(b []byte, maxLen int) string {
	if len(b) > maxLen {
		return string(b[:maxLen]) + "..."
	}
	return string(b)
}

func getTestLinks() []string {
	if v := strings.TrimSpace(os.Getenv("SS_TEST_LINKS")); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{ssLegacyLinkExample, ss2022LinkExample}
}

func allPlaceholderLinks(links []string) bool {
	for _, link := range links {
		if !strings.Contains(link, "example.com") {
			return false
		}
	}
	return true
}
