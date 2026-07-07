package mkcp

import (
	"bytes"
	"testing"
)

func TestSimpleAuthenticatorSealOpen(t *testing.T) {
	auth := NewSimpleAuthenticator()

	plainText := []byte("hello, world!")
	sealed := auth.Seal(nil, nil, plainText, nil)

	opened, err := auth.Open(nil, nil, sealed, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(opened, plainText) {
		t.Errorf("data mismatch: expected %v, got %v", plainText, opened)
	}
}

func TestSimpleAuthenticatorOverhead(t *testing.T) {
	auth := NewSimpleAuthenticator()

	if auth.NonceSize() != 0 {
		t.Errorf("expected NonceSize 0, got %d", auth.NonceSize())
	}

	if auth.Overhead() != 6 {
		t.Errorf("expected Overhead 6, got %d", auth.Overhead())
	}
}

func TestAESGCMBasedOnSeed(t *testing.T) {
	aead := NewAEADAESGCMBasedOnSeed("test-seed")

	if aead.NonceSize() != 12 {
		t.Errorf("expected NonceSize 12, got %d", aead.NonceSize())
	}

	// Test seal and open
	plainText := []byte("secret message")
	nonce := make([]byte, aead.NonceSize())

	sealed := aead.Seal(nil, nonce, plainText, nil)

	opened, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(opened, plainText) {
		t.Errorf("data mismatch: expected %v, got %v", plainText, opened)
	}
}

func TestXorFunctions(t *testing.T) {
	// Test that xorfwd and xorbkd are inverse operations
	original := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	data := make([]byte, len(original))
	copy(data, original)

	xorfwd(data)
	xorbkd(data)

	if !bytes.Equal(data, original) {
		t.Errorf("xor operations are not inverse: expected %v, got %v", original, data)
	}
}
