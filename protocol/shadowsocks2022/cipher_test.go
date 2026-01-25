package shadowsocks2022

import (
	"encoding/base64"
	"testing"
)

func TestDeriveSessionKey(t *testing.T) {
	// Test key derivation produces consistent output
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 32)
	}

	key1 := DeriveSessionKey(psk, salt, 32)
	key2 := DeriveSessionKey(psk, salt, 32)

	if len(key1) != 32 {
		t.Errorf("expected key length 32, got %d", len(key1))
	}

	for i := range key1 {
		if key1[i] != key2[i] {
			t.Errorf("key derivation not deterministic at position %d", i)
		}
	}

	// Different salt should produce different key
	salt[0] = 0xFF
	key3 := DeriveSessionKey(psk, salt, 32)
	same := true
	for i := range key1 {
		if key1[i] != key3[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different salt should produce different key")
	}
}

func TestDeriveIdentitySubkey(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	key := DeriveIdentitySubkey(psk, 32)
	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}
}

func TestParsePSK(t *testing.T) {
	// Create a valid 32-byte PSK
	pskBytes := make([]byte, 32)
	for i := range pskBytes {
		pskBytes[i] = byte(i)
	}
	pskBase64 := base64.StdEncoding.EncodeToString(pskBytes)

	// Test single PSK
	password := pskBase64
	psk, err := ParsePSK(password, 32)
	if err != nil {
		t.Fatalf("ParsePSK failed: %v", err)
	}
	if len(psk) != 32 {
		t.Errorf("expected PSK length 32, got %d", len(psk))
	}

	// Test method:psk format
	password = "2022-blake3-aes-256-gcm:" + pskBase64
	psk, err = ParsePSK(password, 32)
	if err != nil {
		t.Fatalf("ParsePSK with method failed: %v", err)
	}
	if len(psk) != 32 {
		t.Errorf("expected PSK length 32, got %d", len(psk))
	}

	// Test wrong length
	shortPSK := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	_, err = ParsePSK(shortPSK, 32)
	if err == nil {
		t.Error("expected error for wrong PSK length")
	}
}

func TestParseMultiUserPSK(t *testing.T) {
	// Create valid 32-byte PSKs
	iPSKBytes := make([]byte, 32)
	uPSKBytes := make([]byte, 32)
	for i := range iPSKBytes {
		iPSKBytes[i] = byte(i)
		uPSKBytes[i] = byte(i + 32)
	}
	iPSKBase64 := base64.StdEncoding.EncodeToString(iPSKBytes)
	uPSKBase64 := base64.StdEncoding.EncodeToString(uPSKBytes)

	// Test multi-user format: method:ipsk:upsk
	password := "2022-blake3-aes-256-gcm:" + iPSKBase64 + ":" + uPSKBase64
	iPSK, uPSK, err := ParseMultiUserPSK(password, 32)
	if err != nil {
		t.Fatalf("ParseMultiUserPSK failed: %v", err)
	}
	if len(iPSK) != 32 {
		t.Errorf("expected iPSK length 32, got %d", len(iPSK))
	}
	if len(uPSK) != 32 {
		t.Errorf("expected uPSK length 32, got %d", len(uPSK))
	}

	// Test single-user format (should return nil, nil, nil)
	password = "2022-blake3-aes-256-gcm:" + iPSKBase64
	iPSK, uPSK, err = ParseMultiUserPSK(password, 32)
	if err != nil {
		t.Fatalf("ParseMultiUserPSK for single-user failed: %v", err)
	}
	if iPSK != nil || uPSK != nil {
		t.Error("expected nil for single-user mode")
	}
}

func TestGetCipherConfig(t *testing.T) {
	tests := []struct {
		method  string
		keyLen  int
		wantErr bool
	}{
		{"2022-blake3-aes-128-gcm", 16, false},
		{"2022-blake3-aes-256-gcm", 32, false},
		{"2022-blake3-chacha20-poly1305", 32, false},
		{"unknown-cipher", 0, true},
	}

	for _, tt := range tests {
		config, err := GetCipherConfig(tt.method)
		if tt.wantErr {
			if err == nil {
				t.Errorf("GetCipherConfig(%s) expected error", tt.method)
			}
			continue
		}
		if err != nil {
			t.Errorf("GetCipherConfig(%s) unexpected error: %v", tt.method, err)
			continue
		}
		if config.KeyLen != tt.keyLen {
			t.Errorf("GetCipherConfig(%s) keyLen = %d, want %d", tt.method, config.KeyLen, tt.keyLen)
		}
	}
}

func TestCipherConfigUDPMode(t *testing.T) {
	tests := []struct {
		method       string
		expectedMode UDPCipherMode
		udpNonceLen  int
	}{
		{"2022-blake3-aes-128-gcm", UDPModeAES, 12},
		{"2022-blake3-aes-256-gcm", UDPModeAES, 12},
		{"2022-blake3-chacha20-poly1305", UDPModeChaCha, 24},
	}

	for _, tt := range tests {
		config, err := GetCipherConfig(tt.method)
		if err != nil {
			t.Fatalf("GetCipherConfig(%s) failed: %v", tt.method, err)
		}

		if config.UDPMode != tt.expectedMode {
			t.Errorf("GetCipherConfig(%s) UDPMode = %d, want %d", tt.method, config.UDPMode, tt.expectedMode)
		}

		if config.UDPNonceLen != tt.udpNonceLen {
			t.Errorf("GetCipherConfig(%s) UDPNonceLen = %d, want %d", tt.method, config.UDPNonceLen, tt.udpNonceLen)
		}

		// Verify NewUDPCipher works
		key := make([]byte, config.KeyLen)
		cipher, err := config.NewUDPCipher(key)
		if err != nil {
			t.Errorf("GetCipherConfig(%s) NewUDPCipher failed: %v", tt.method, err)
			continue
		}

		// Verify nonce size matches expected
		if cipher.NonceSize() != tt.udpNonceLen {
			t.Errorf("GetCipherConfig(%s) cipher.NonceSize() = %d, want %d", tt.method, cipher.NonceSize(), tt.udpNonceLen)
		}
	}
}
