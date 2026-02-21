package shadowsocks

import (
	"fmt"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
)

// BenchmarkUDPClassicVsOptimized compares classic vs optimized UDP encryption/decryption
func BenchmarkUDPClassicVsOptimized(b *testing.B) {
	// Setup
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	key := &Key{
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
		MasterKey:  masterKey,
	}

	data := make([]byte, 1400) // typical MTU size
	for i := range data {
		data[i] = byte(i % 256)
	}

	salt := make([]byte, key.CipherConf.SaltLen)
	for i := range salt {
		salt[i] = byte(i)
	}

	b.Run("ClassicEncrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encrypted, err := EncryptUDPFromPool(key, data, salt, ShadowsocksReusedInfo)
			if err != nil {
				b.Fatal(err)
			}
			pool.Put(encrypted)
		}
	})

	b.Run("OptimizedEncrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encrypted, err := EncryptUDPFromPoolOptimized(key, data, salt, ShadowsocksReusedInfo)
			if err != nil {
				b.Fatal(err)
			}
			pool.Put(encrypted)
		}
	})

	// Pre-encrypt for decryption benchmarks
	encryptedClassic, _ := EncryptUDPFromPool(key, data, salt, ShadowsocksReusedInfo)
	defer pool.Put(encryptedClassic)

	b.Run("ClassicDecrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decrypted := pool.Get(len(encryptedClassic))
			n, err := DecryptUDP(decrypted[:0], key, encryptedClassic, ShadowsocksReusedInfo)
			if err != nil {
				b.Fatal(err)
			}
			pool.Put(decrypted)
			_ = n
		}
	})

	b.Run("OptimizedDecrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decrypted, err := DecryptUDPFromPoolOptimized(key, encryptedClassic, ShadowsocksReusedInfo)
			if err != nil {
				b.Fatal(err)
			}
			pool.Put(decrypted)
		}
	})
}

// BenchmarkUDPWithDifferentSizes benchmarks encryption with various packet sizes
func BenchmarkUDPWithDifferentSizes(b *testing.B) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	key := &Key{
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
		MasterKey:  masterKey,
	}

	salt := make([]byte, key.CipherConf.SaltLen)
	for i := range salt {
		salt[i] = byte(i)
	}

	sizes := []int{64, 512, 1400, 4096, 8192}

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		b.Run(fmt.Sprintf("Classic_%dB", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encrypted, err := EncryptUDPFromPool(key, data, salt, ShadowsocksReusedInfo)
				if err != nil {
					b.Fatal(err)
				}
				pool.Put(encrypted)
			}
		})

		b.Run(fmt.Sprintf("Optimized_%dB", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encrypted, err := EncryptUDPFromPoolOptimized(key, data, salt, ShadowsocksReusedInfo)
				if err != nil {
					b.Fatal(err)
				}
				pool.Put(encrypted)
			}
		})
	}
}

// BenchmarkUDPMultipleSalts benchmarks performance with multiple different salts
// This simulates real-world scenario where each packet has a different salt
func BenchmarkUDPMultipleSalts(b *testing.B) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	key := &Key{
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
		MasterKey:  masterKey,
	}

	data := make([]byte, 1400)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Generate multiple salts
	numSalts := 100
	salts := make([][]byte, numSalts)
	for i := range salts {
		salts[i] = make([]byte, key.CipherConf.SaltLen)
		for j := range salts[i] {
			salts[i][j] = byte((i*256 + j) % 256)
		}
	}

	b.Run("ClassicMultipleSalts", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			salt := salts[i%numSalts]
			encrypted, err := EncryptUDPFromPool(key, data, salt, ShadowsocksReusedInfo)
			if err != nil {
				b.Fatal(err)
			}
			pool.Put(encrypted)
		}
	})

	b.Run("OptimizedMultipleSalts", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			salt := salts[i%numSalts]
			encrypted, err := EncryptUDPFromPoolOptimized(key, data, salt, ShadowsocksReusedInfo)
			if err != nil {
				b.Fatal(err)
			}
			pool.Put(encrypted)
		}
	})
}
