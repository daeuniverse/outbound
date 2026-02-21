package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type nopDialer struct{}

func (nopDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return nil, nil
}

func pskBase64(length int, v byte) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = v
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestNewDialer_UnsupportedCipher(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305",
		Password:     pskBase64(32, 0x11),
		ProxyAddress: "127.0.0.1:443",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported shadowsocks 2022 cipher") {
		t.Fatalf("expected unsupported cipher error, got: %v", err)
	}
}

func TestNewDialer_TooManyPSKs(t *testing.T) {
	keys := make([]string, maxPSKListLength+1)
	for i := range keys {
		keys[i] = pskBase64(16, byte(i+1))
	}
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-aes-128-gcm",
		Password:     strings.Join(keys, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err == nil || !strings.Contains(err.Error(), "too many PSKs") {
		t.Fatalf("expected too many PSKs error, got: %v", err)
	}
}

func TestNewDialer_ValidMultiPSK(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-aes-256-gcm",
		Password:     strings.Join([]string{pskBase64(32, 0x21), pskBase64(32, 0x22)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
