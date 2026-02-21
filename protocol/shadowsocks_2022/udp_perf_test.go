package shadowsocks_2022

import (
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
)

// BenchmarkCipherCreationNoCache benchmarks cipher creation without cache
func BenchmarkCipherCreationNoCache(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)
	
	// Fill with test data
	for i := range psk {
		psk[i] = byte(i)
	}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate current implementation: create cipher every time
		ciph, err := CreateCipher(psk, sessionID, conf)
		if err != nil {
			b.Fatal(err)
		}
		_ = ciph
	}
}

// BenchmarkCipherCreationWithCache benchmarks cipher creation with cache
func BenchmarkCipherCreationWithCache(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)
	
	for i := range psk {
		psk[i] = byte(i)
	}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Optimized: use cached cipher
		ciph, err := GetCachedCipher(psk, sessionID, conf, true)
		if err != nil {
			b.Fatal(err)
		}
		_ = ciph
	}
}

// BenchmarkEncryptNoCache benchmarks encryption without cipher cache
func BenchmarkEncryptNoCache(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)
	plaintext := make([]byte, 1400) // Typical MTU
	nonce := make([]byte, 12)
	
	for i := range psk {
		psk[i] = byte(i)
	}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create cipher every time (current implementation)
		ciph, err := CreateCipher(psk, sessionID, conf)
		if err != nil {
			b.Fatal(err)
		}
		
		// Encrypt
		ciphertext := make([]byte, len(plaintext)+16)
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// BenchmarkEncryptWithCache benchmarks encryption with cipher cache
func BenchmarkEncryptWithCache(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)
	plaintext := make([]byte, 1400)
	nonce := make([]byte, 12)
	
	for i := range psk {
		psk[i] = byte(i)
	}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	
	// Pre-warm cache
	_, _ = GetCachedCipher(psk, sessionID, conf, true)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Get cached cipher
		ciph, err := GetCachedCipher(psk, sessionID, conf, true)
		if err != nil {
			b.Fatal(err)
		}
		
		// Encrypt
		ciphertext := make([]byte, len(plaintext)+16)
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// BenchmarkDecryptNoCache benchmarks decryption without cipher cache
func BenchmarkDecryptNoCache(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)
	plaintext := make([]byte, 1400)
	nonce := make([]byte, 12)
	
	for i := range psk {
		psk[i] = byte(i)
	}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	
	// Create cipher once to encrypt test data
	ciph, _ := CreateCipher(psk, sessionID, conf)
	ciphertext := make([]byte, len(plaintext)+16)
	ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create cipher every time (current implementation)
		ciph, err := CreateCipher(psk, sessionID, conf)
		if err != nil {
			b.Fatal(err)
		}
		
		// Decrypt
		plaintextOut := make([]byte, len(plaintext))
		_, err = ciph.Open(plaintextOut[:0], nonce, ciphertext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptWithCache benchmarks decryption with cipher cache
func BenchmarkDecryptWithCache(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)
	plaintext := make([]byte, 1400)
	nonce := make([]byte, 12)
	
	for i := range psk {
		psk[i] = byte(i)
	}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	
	// Create cipher once to encrypt test data
	ciph, _ := CreateCipher(psk, sessionID, conf)
	ciphertext := make([]byte, len(plaintext)+16)
	ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	
	// Pre-warm cache
	GetCachedCipher(psk, sessionID, conf, false)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Get cached cipher
		ciph, err := GetCachedCipher(psk, sessionID, conf, false)
		if err != nil {
			b.Fatal(err)
		}
		
		// Decrypt
		plaintextOut := make([]byte, len(plaintext))
		_, err = ciph.Open(plaintextOut[:0], nonce, ciphertext, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMultipleSessionsNoCache simulates multiple UDP sessions without cache
func BenchmarkMultipleSessionsNoCache(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	
	// Simulate 10 different sessions
	sessions := make([][]byte, 10)
	for i := range sessions {
		sessions[i] = make([]byte, 8)
		for j := range sessions[i] {
			sessions[i][j] = byte(i*10 + j)
		}
	}
	
	plaintext := make([]byte, 1400)
	nonce := make([]byte, 12)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Rotate through sessions
		sessionID := sessions[i%len(sessions)]
		
		// Create cipher every time
		ciph, err := CreateCipher(psk, sessionID, conf)
		if err != nil {
			b.Fatal(err)
		}
		
		ciphertext := make([]byte, len(plaintext)+16)
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// BenchmarkMultipleSessionsWithCache simulates multiple UDP sessions with cache
func BenchmarkMultipleSessionsWithCache(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	
	sessions := make([][]byte, 10)
	for i := range sessions {
		sessions[i] = make([]byte, 8)
		for j := range sessions[i] {
			sessions[i][j] = byte(i*10 + j)
		}
	}
	
	plaintext := make([]byte, 1400)
	nonce := make([]byte, 12)
	
	// Pre-warm cache for all sessions
	for _, sessionID := range sessions {
		GetCachedCipher(psk, sessionID, conf, true)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionID := sessions[i%len(sessions)]
		
		// Get cached cipher
		ciph, err := GetCachedCipher(psk, sessionID, conf, true)
		if err != nil {
			b.Fatal(err)
		}
		
		ciphertext := make([]byte, len(plaintext)+16)
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// TestCacheEffectiveness tests that cache actually works
func TestCacheEffectiveness(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)
	
	// First call should create cipher
	ciph1, err := GetCachedCipher(psk, sessionID, conf, true)
	if err != nil {
		t.Fatal(err)
	}
	
	// Second call should return same cipher from cache
	ciph2, err := GetCachedCipher(psk, sessionID, conf, true)
	if err != nil {
		t.Fatal(err)
	}
	
	// Verify it's the same cipher instance
	if ciph1 != ciph2 {
		t.Error("Cache should return same cipher instance")
	}
	
	// Test encrypt vs decrypt caches are separate
	ciph3, err := GetCachedCipher(psk, sessionID, conf, false)
	if err != nil {
		t.Fatal(err)
	}
	
	// Encrypt and decrypt ciphers can be different instances
	// (they're functionally equivalent but cached separately)
	_ = ciph3
}

// TestMultipleSalts tests cache with different session IDs
func TestMultipleSalts(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	
	sessionID1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	sessionID2 := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	
	ciph1, err := GetCachedCipher(psk, sessionID1, conf, true)
	if err != nil {
		t.Fatal(err)
	}
	
	ciph2, err := GetCachedCipher(psk, sessionID2, conf, true)
	if err != nil {
		t.Fatal(err)
	}
	
	// Different session IDs should create different ciphers
	if ciph1 == ciph2 {
		t.Error("Different session IDs should create different cipher instances")
	}
	
	// Same session ID should return same cipher
	ciph1Again, err := GetCachedCipher(psk, sessionID1, conf, true)
	if err != nil {
		t.Fatal(err)
	}
	
	if ciph1 != ciph1Again {
		t.Error("Same session ID should return same cipher from cache")
	}
}
