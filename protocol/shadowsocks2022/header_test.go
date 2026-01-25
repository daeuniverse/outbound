package shadowsocks2022

import (
	"testing"
	"time"
)

func TestEncodeDecodeFixedHeader(t *testing.T) {
	timestamp := uint64(time.Now().Unix())
	varHeaderLen := uint16(100)

	encoded := EncodeFixedHeader(HeaderTypeClientRequest, timestamp, varHeaderLen)
	if len(encoded) != FixedHeaderLen {
		t.Errorf("expected fixed header length %d, got %d", FixedHeaderLen, len(encoded))
	}

	decoded, err := DecodeFixedHeader(encoded)
	if err != nil {
		t.Fatalf("DecodeFixedHeader failed: %v", err)
	}

	if decoded.Type != HeaderTypeClientRequest {
		t.Errorf("Type mismatch: got %d, want %d", decoded.Type, HeaderTypeClientRequest)
	}
	if decoded.Timestamp != timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", decoded.Timestamp, timestamp)
	}
	if decoded.VarHeaderLen != varHeaderLen {
		t.Errorf("VarHeaderLen mismatch: got %d, want %d", decoded.VarHeaderLen, varHeaderLen)
	}
}

func TestValidateTimestamp(t *testing.T) {
	// Valid timestamp (now)
	now := uint64(time.Now().Unix())
	if err := ValidateTimestamp(now); err != nil {
		t.Errorf("ValidateTimestamp(now) failed: %v", err)
	}

	// Valid timestamp (within window)
	withinWindow := uint64(time.Now().Unix()) + 15
	if err := ValidateTimestamp(withinWindow); err != nil {
		t.Errorf("ValidateTimestamp(+15s) failed: %v", err)
	}

	// Invalid timestamp (too old)
	tooOld := uint64(time.Now().Unix()) - 60
	if err := ValidateTimestamp(tooOld); err == nil {
		t.Error("ValidateTimestamp(-60s) should fail")
	}

	// Invalid timestamp (too new)
	tooNew := uint64(time.Now().Unix()) + 60
	if err := ValidateTimestamp(tooNew); err == nil {
		t.Error("ValidateTimestamp(+60s) should fail")
	}
}

func TestEncodeDecodeAddress(t *testing.T) {
	tests := []struct {
		hostname string
		port     uint16
	}{
		{"127.0.0.1", 8080},
		{"192.168.1.1", 443},
		{"::1", 8080},
		{"2001:db8::1", 443},
		{"example.com", 80},
		{"www.example.org", 443},
	}

	for _, tt := range tests {
		encoded, err := EncodeAddress(tt.hostname, tt.port)
		if err != nil {
			t.Errorf("EncodeAddress(%s, %d) failed: %v", tt.hostname, tt.port, err)
			continue
		}

		hostname, port, _, err := DecodeAddress(encoded)
		if err != nil {
			t.Errorf("DecodeAddress for %s:%d failed: %v", tt.hostname, tt.port, err)
			continue
		}

		if hostname != tt.hostname {
			t.Errorf("hostname mismatch: got %s, want %s", hostname, tt.hostname)
		}
		if port != tt.port {
			t.Errorf("port mismatch: got %d, want %d", port, tt.port)
		}
	}
}

func TestAddressLength(t *testing.T) {
	tests := []struct {
		hostname    string
		expectedLen int
	}{
		{"127.0.0.1", 1 + 4 + 2},        // IPv4
		{"::1", 1 + 16 + 2},             // IPv6
		{"example.com", 1 + 1 + 11 + 2}, // Domain
	}

	for _, tt := range tests {
		got := AddressLength(tt.hostname)
		if got != tt.expectedLen {
			t.Errorf("AddressLength(%s) = %d, want %d", tt.hostname, got, tt.expectedLen)
		}
	}
}
