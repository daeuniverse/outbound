package client

import (
	"errors"
	"math/rand"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestSalamanderObfuscatorRoundTrip(t *testing.T) {
	obfs, err := newSalamanderObfuscator([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	obfs.randSrc = rand.New(rand.NewSource(1))

	payload := []byte("hello hysteria2 salamander")
	encoded := make([]byte, len(payload)+salamanderSaltLen)
	if n := obfs.Obfuscate(payload, encoded); n != len(encoded) {
		t.Fatalf("Obfuscate() = %d, want %d", n, len(encoded))
	}
	if string(encoded[salamanderSaltLen:]) == string(payload) {
		t.Fatal("payload was not obfuscated")
	}

	decoded := make([]byte, len(payload))
	if n := obfs.Deobfuscate(encoded, decoded); n != len(payload) {
		t.Fatalf("Deobfuscate() = %d, want %d", n, len(payload))
	}
	if string(decoded) != string(payload) {
		t.Fatalf("round trip = %q, want %q", decoded, payload)
	}
}

func TestSalamanderObfuscatorRejectsShortPSK(t *testing.T) {
	if _, err := newSalamanderObfuscator([]byte("abc")); !errors.Is(err, errSalamanderPSKTooShort) {
		t.Fatalf("newSalamanderObfuscator() error = %v, want %v", err, errSalamanderPSKTooShort)
	}
}

func TestObfsPacketConnRejectsOversizedPacket(t *testing.T) {
	obfs, err := newSalamanderObfuscator([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	conn := newObfsPacketConn(&stubPacketConn{}, obfs)

	if _, err := conn.WriteTo(make([]byte, udpBufferSize), &net.UDPAddr{}); err == nil {
		t.Fatal("WriteTo() error = nil, want oversized packet error")
	}
}

func TestGenericObfsPacketConnDoesNotExposeUDPBufferOptions(t *testing.T) {
	obfs, err := newSalamanderObfuscator([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	conn := newObfsPacketConn(&stubPacketConn{}, obfs)

	if _, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		t.Fatal("generic obfs packet conn unexpectedly exposes SetReadBuffer")
	}
	if _, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		t.Fatal("generic obfs packet conn unexpectedly exposes SetWriteBuffer")
	}
	if _, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		t.Fatal("generic obfs packet conn unexpectedly exposes SyscallConn")
	}
}

type stubPacketConn struct{}

func (c *stubPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}

func (c *stubPacketConn) Close() error {
	return nil
}

func (c *stubPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *stubPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *stubPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *stubPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
