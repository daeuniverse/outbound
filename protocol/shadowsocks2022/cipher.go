package shadowsocks2022

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

const (
	// KeyLen for different ciphers
	KeyLen128 = 16
	KeyLen256 = 32

	// BLAKE3 context strings
	SessionSubkeyContext  = "shadowsocks 2022 session subkey"
	IdentitySubkeyContext = "shadowsocks 2022 identity subkey"

	// Salt length (same as key length for SS2022)
	SaltLen128 = 16
	SaltLen256 = 32

	// AEAD tag length
	TagLen = 16

	// Nonce length for TCP (standard AEAD)
	NonceLen = 12

	// Nonce length for UDP XChaCha20-Poly1305
	XChaCha20NonceLen = 24
)

// UDPCipherMode indicates which UDP encryption mode to use
type UDPCipherMode int

const (
	// UDPModeAES uses 16B separate header + AES-ECB + AES-GCM AEAD
	UDPModeAES UDPCipherMode = iota
	// UDPModeChaCha uses 24B nonce prefix + XChaCha20-Poly1305 AEAD
	UDPModeChaCha
)

// CipherConfig holds the configuration for a SS2022 cipher
type CipherConfig struct {
	KeyLen       int
	SaltLen      int
	NonceLen     int // For TCP
	TagLen       int
	UDPMode      UDPCipherMode
	UDPNonceLen  int // For UDP (12 for AES, 24 for XChaCha20)
	NewCipher    func(key []byte) (cipher.AEAD, error)       // For TCP
	NewUDPCipher func(key []byte) (cipher.AEAD, error)       // For UDP (may differ for ChaCha20)
}

// Cipher configs for SS2022
var CipherConfigs = map[string]*CipherConfig{
	"2022-blake3-aes-128-gcm": {
		KeyLen:       KeyLen128,
		SaltLen:      SaltLen128,
		NonceLen:     NonceLen,
		TagLen:       TagLen,
		UDPMode:      UDPModeAES,
		UDPNonceLen:  NonceLen,
		NewCipher:    newAESGCM,
		NewUDPCipher: newAESGCM,
	},
	"2022-blake3-aes-256-gcm": {
		KeyLen:       KeyLen256,
		SaltLen:      SaltLen256,
		NonceLen:     NonceLen,
		TagLen:       TagLen,
		UDPMode:      UDPModeAES,
		UDPNonceLen:  NonceLen,
		NewCipher:    newAESGCM,
		NewUDPCipher: newAESGCM,
	},
	"2022-blake3-chacha20-poly1305": {
		KeyLen:       KeyLen256,
		SaltLen:      SaltLen256,
		NonceLen:     NonceLen,
		TagLen:       TagLen,
		UDPMode:      UDPModeChaCha,
		UDPNonceLen:  XChaCha20NonceLen,
		NewCipher:    chacha20poly1305.New,
		NewUDPCipher: chacha20poly1305.NewX, // XChaCha20-Poly1305 for UDP
	},
}

// newAESGCM creates a new AES-GCM cipher
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// DeriveSessionKey derives a session subkey using BLAKE3
func DeriveSessionKey(psk, salt []byte, keyLen int) []byte {
	keyMaterial := make([]byte, len(psk)+len(salt))
	copy(keyMaterial, psk)
	copy(keyMaterial[len(psk):], salt)

	subkey := make([]byte, keyLen)
	blake3.DeriveKey(subkey, SessionSubkeyContext, keyMaterial)
	return subkey
}

// DeriveIdentitySubkey derives an identity subkey for EIH using BLAKE3
func DeriveIdentitySubkey(psk []byte, keyLen int) []byte {
	subkey := make([]byte, keyLen)
	blake3.DeriveKey(subkey, IdentitySubkeyContext, psk)
	return subkey
}

// ParsePSK parses a base64-encoded PSK and validates its length
func ParsePSK(password string, expectedLen int) ([]byte, error) {
	// Handle the format "method:psk" or "method:ipsk:upsk"
	parts := strings.SplitN(password, ":", 3)
	var pskStr string
	switch len(parts) {
	case 1:
		pskStr = parts[0]
	case 2:
		// method:psk
		pskStr = parts[1]
	case 3:
		// method:ipsk:upsk - return uPSK
		pskStr = parts[2]
	default:
		return nil, fmt.Errorf("invalid password format")
	}

	psk, err := base64.StdEncoding.DecodeString(pskStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PSK: %w", err)
	}

	if len(psk) != expectedLen {
		return nil, fmt.Errorf("PSK length mismatch: expected %d, got %d", expectedLen, len(psk))
	}

	return psk, nil
}

// ParseMultiUserPSK parses multi-user PSK format (ipsk:upsk)
func ParseMultiUserPSK(password string, expectedLen int) (iPSK, uPSK []byte, err error) {
	parts := strings.SplitN(password, ":", 3)
	if len(parts) < 3 {
		// Single user mode
		return nil, nil, nil
	}

	// parts[0] is method, parts[1] is iPSK, parts[2] is uPSK
	iPSK, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode iPSK: %w", err)
	}
	if len(iPSK) != expectedLen {
		return nil, nil, fmt.Errorf("iPSK length mismatch: expected %d, got %d", expectedLen, len(iPSK))
	}

	uPSK, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode uPSK: %w", err)
	}
	if len(uPSK) != expectedLen {
		return nil, nil, fmt.Errorf("uPSK length mismatch: expected %d, got %d", expectedLen, len(uPSK))
	}

	return iPSK, uPSK, nil
}

// GetCipherConfig returns the cipher config for the given method
func GetCipherConfig(method string) (*CipherConfig, error) {
	config, ok := CipherConfigs[method]
	if !ok {
		return nil, fmt.Errorf("unsupported cipher method: %s", method)
	}
	return config, nil
}
