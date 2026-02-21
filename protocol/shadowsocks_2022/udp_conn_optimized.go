package shadowsocks_2022

import (
	"crypto/cipher"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
)

// Optimized: UDP cipher cache for session reuse
// This optimization caches ciphers to avoid repeated key derivation (BLAKE3)
// and cipher creation overhead.

// cipherCacheEntry represents a cached cipher with timestamp for cleanup
type cipherCacheEntry struct {
	cipher    cipher.AEAD
	timestamp time.Time
}

var (
	// Global cipher caches for encrypt and decrypt operations
	udpEncryptCache sync.Map // cacheKey(string) -> *cipherCacheEntry
	udpDecryptCache sync.Map // cacheKey(string) -> *cipherCacheEntry
	
	// Cache cleanup configuration
	udpCacheCleanupInterval = 5 * time.Minute
	udpCacheMaxAge          = 10 * time.Minute
)

func init() {
	// Start background cleanup goroutine
	go udpCacheCleanup()
}

// udpCacheCleanup periodically removes expired cache entries
func udpCacheCleanup() {
	ticker := time.NewTicker(udpCacheCleanupInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		now := time.Now()
		
		// Clean encrypt cache
		udpEncryptCache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(*cipherCacheEntry); ok {
				if now.Sub(entry.timestamp) > udpCacheMaxAge {
					udpEncryptCache.Delete(key)
				}
			}
			return true
		})
		
		// Clean decrypt cache
		udpDecryptCache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(*cipherCacheEntry); ok {
				if now.Sub(entry.timestamp) > udpCacheMaxAge {
					udpDecryptCache.Delete(key)
				}
			}
			return true
		})
	}
}

// generateCacheKey generates a cache key from sessionID and psk
// For SS2022, we use sessionID (8 bytes) + first 8 bytes of psk
func generateCacheKey(sessionID []byte, psk []byte) string {
	// Simple concatenation for cache key
	keyLen := len(sessionID) + 8
	if len(psk) < 8 {
		keyLen = len(sessionID) + len(psk)
	}
	
	key := make([]byte, keyLen)
	copy(key, sessionID)
	if len(psk) >= 8 {
		copy(key[len(sessionID):], psk[:8])
	} else {
		copy(key[len(sessionID):], psk)
	}
	return string(key)
}

// GetCachedCipher gets or creates a cipher from cache
// This is the optimized version that reuses ciphers for the same session
func GetCachedCipher(psk []byte, sessionID []byte, cipherConf *ciphers.CipherConf2022, isEncrypt bool) (cipher.AEAD, error) {
	cacheKey := generateCacheKey(sessionID, psk)
	
	// Select appropriate cache
	cache := &udpDecryptCache
	if isEncrypt {
		cache = &udpEncryptCache
	}
	
	// Try to get cipher from cache
	if cached, ok := cache.Load(cacheKey); ok {
		if entry, ok := cached.(*cipherCacheEntry); ok {
			// Update timestamp for LRU-like behavior
			entry.timestamp = time.Now()
			return entry.cipher, nil
		}
	}
	
	// Cache miss: create new cipher
	ciph, err := CreateCipher(psk, sessionID, cipherConf)
	if err != nil {
		return nil, err
	}
	
	// Store in cache
	cache.Store(cacheKey, &cipherCacheEntry{
		cipher:    ciph,
		timestamp: time.Now(),
	})
	
	return ciph, nil
}
