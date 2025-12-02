package client

import (
	"crypto/rand"
	"crypto/subtle"
	"net"
	"time"

	"golang.org/x/crypto/blake2b"
)

type SalamanderPacketConn struct {
	Connection net.PacketConn
	Key        []byte
}

func NewSalamanderPacketConn(conn net.PacketConn, key []byte) SalamanderPacketConn {
	return SalamanderPacketConn{
		Connection: conn,
		Key:        key,
	}
}

func (s SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet := make([]byte, len(p)+8)

	n, addr, err = s.Connection.ReadFrom(packet)

	if err != nil {
		return
	}

	if n <= 8 {
		return 0, addr, nil
	}

	s.Process(p, packet[8:n], packet[:8])

	n -= 8

	return
}

func (s SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	packet := make([]byte, len(p)+8)

	rand.Read(packet[:8])

	s.Process(packet[8:], p, packet[:8])

	n, err = s.Connection.WriteTo(packet, addr)

	if err == nil {
		n -= 8
	}

	return
}

func (s SalamanderPacketConn) Process(dst, src, salt []byte) {
	hash := blake2b.Sum256(append(s.Key, salt...))

	for i := 0; i < len(src); i += 32 {
		subtle.XORBytes(dst[i:], src[i:], hash[:])
	}
}

func (s SalamanderPacketConn) Close() error {
	return s.Connection.Close()
}

func (s SalamanderPacketConn) LocalAddr() net.Addr {
	return s.Connection.LocalAddr()
}

func (s SalamanderPacketConn) SetDeadline(t time.Time) error {
	return s.Connection.SetDeadline(t)
}

func (s SalamanderPacketConn) SetReadDeadline(t time.Time) error {
	return s.Connection.SetReadDeadline(t)
}

func (s SalamanderPacketConn) SetWriteDeadline(t time.Time) error {
	return s.Connection.SetWriteDeadline(t)
}
