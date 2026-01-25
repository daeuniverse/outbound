package shadowsocks2022

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"

	"lukechampine.com/blake3"
)

const (
	// IdentityHeaderLen is the length of the encrypted identity header
	IdentityHeaderLen = 16
)

// PSKHash returns the BLAKE3 hash of a PSK truncated to 16 bytes
func PSKHash(psk []byte) [IdentityHeaderLen]byte {
	hash := blake3.Sum512(psk)
	var result [IdentityHeaderLen]byte
	copy(result[:], hash[:IdentityHeaderLen])
	return result
}

// DeriveIdentitySubkeyWithSalt derives an identity subkey for TCP EIH using BLAKE3
// Context: "shadowsocks 2022 identity subkey"
// Key material: iPSK || salt
func DeriveIdentitySubkeyWithSalt(iPSK, salt []byte, keyLen int) []byte {
	keyMaterial := make([]byte, len(iPSK)+len(salt))
	copy(keyMaterial, iPSK)
	copy(keyMaterial[len(iPSK):], salt)

	subkey := make([]byte, keyLen)
	blake3.DeriveKey(subkey, IdentitySubkeyContext, keyMaterial)
	return subkey
}

// IdentityHeader handles EIH (Encrypted Identity Header) for multi-user mode
type IdentityHeader struct {
	iPSK   []byte // identity PSK (server's main key)
	uPSK   []byte // user PSK
	keyLen int
}

// NewIdentityHeader creates a new IdentityHeader for multi-user mode
func NewIdentityHeader(iPSK, uPSK []byte, keyLen int) *IdentityHeader {
	return &IdentityHeader{
		iPSK:   iPSK,
		uPSK:   uPSK,
		keyLen: keyLen,
	}
}

// IsMultiUser returns true if this is multi-user mode
func (h *IdentityHeader) IsMultiUser() bool {
	return h != nil && h.iPSK != nil && h.uPSK != nil
}

// GenerateUDPIdentityHeader generates the identity header for UDP
// For UDP, the identity header is: AES-ECB-Encrypt(iPSK, XOR(uPSKHash, separateHeader))
// Note: Uses iPSK for encryption, not uPSK
func GenerateUDPIdentityHeader(iPSK []byte, uPSKHash [IdentityHeaderLen]byte, separateHeader []byte) ([]byte, error) {
	if len(separateHeader) < IdentityHeaderLen {
		return nil, fmt.Errorf("separate header too short")
	}

	// XOR uPSK hash with separate header
	xored := make([]byte, IdentityHeaderLen)
	subtle.XORBytes(xored, uPSKHash[:], separateHeader[:IdentityHeaderLen])

	// Encrypt with AES-ECB using iPSK
	// Use appropriate key length based on iPSK length
	block, err := CreateECBEncryptorWithKeyLen(iPSK, len(iPSK))
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	identityHeader := make([]byte, IdentityHeaderLen)
	block.Encrypt(identityHeader, xored)

	return identityHeader, nil
}

// VerifyUDPIdentityHeader verifies and decrypts a UDP identity header
// Returns the index of the matching user PSK, or -1 if not found
func VerifyUDPIdentityHeader(iPSK, separateHeader, encryptedHeader []byte, userPSKHashes [][IdentityHeaderLen]byte) (int, error) {
	if len(encryptedHeader) != IdentityHeaderLen {
		return -1, fmt.Errorf("invalid identity header length: %d", len(encryptedHeader))
	}

	// Decrypt with AES-ECB using iPSK
	block, err := CreateECBEncryptorWithKeyLen(iPSK, len(iPSK))
	if err != nil {
		return -1, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	decrypted := make([]byte, IdentityHeaderLen)
	block.Decrypt(decrypted, encryptedHeader)

	// XOR with separate header to get original uPSK hash
	subtle.XORBytes(decrypted, decrypted, separateHeader[:IdentityHeaderLen])

	// Compare with each user's PSK hash
	for i, hash := range userPSKHashes {
		if compareConstantTime(decrypted, hash[:]) {
			return i, nil
		}
	}

	return -1, fmt.Errorf("no matching user PSK found")
}

// compareConstantTime compares two byte slices in constant time
func compareConstantTime(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// compareBytes compares two byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GetEffectivePSK returns the PSK to use for encryption
// For multi-user mode, returns uPSK; for single-user mode, returns the only PSK
func (h *IdentityHeader) GetEffectivePSK() []byte {
	if h.IsMultiUser() {
		return h.uPSK
	}
	return h.uPSK // In single-user mode, uPSK holds the only PSK
}

// CreateECBDecryptor creates an AES-ECB decryptor with 16-byte key (AES-128)
func CreateECBDecryptor(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key[:16])
}

// CreateECBEncryptor creates an AES-ECB encryptor with 16-byte key (AES-128)
func CreateECBEncryptor(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key[:16])
}

// CreateECBEncryptorWithKeyLen creates an AES-ECB encryptor with appropriate key length
// For AES-128 (keyLen=16): uses first 16 bytes
// For AES-256 (keyLen=32): uses first 32 bytes (AES-256)
func CreateECBEncryptorWithKeyLen(key []byte, keyLen int) (cipher.Block, error) {
	switch keyLen {
	case 16:
		return aes.NewCipher(key[:16])
	case 32:
		return aes.NewCipher(key[:32])
	default:
		return nil, fmt.Errorf("unsupported key length: %d", keyLen)
	}
}

// CreateECBDecryptorWithKeyLen creates an AES-ECB decryptor with appropriate key length
func CreateECBDecryptorWithKeyLen(key []byte, keyLen int) (cipher.Block, error) {
	switch keyLen {
	case 16:
		return aes.NewCipher(key[:16])
	case 32:
		return aes.NewCipher(key[:32])
	default:
		return nil, fmt.Errorf("unsupported key length: %d", keyLen)
	}
}
