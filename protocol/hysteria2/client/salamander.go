package client

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/blake2b"
)

const (
	salamanderPSKMinLen = 4
	salamanderSaltLen   = 8
	salamanderKeyLen    = blake2b.Size256
	udpBufferSize       = 2048
)

var errSalamanderPSKTooShort = fmt.Errorf("PSK must be at least %d bytes", salamanderPSKMinLen)

type packetObfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

type salamanderObfuscator struct {
	psk     []byte
	randSrc *rand.Rand

	mu       sync.Mutex
	keyInput []byte
}

func newSalamanderObfuscator(psk []byte) (*salamanderObfuscator, error) {
	if len(psk) < salamanderPSKMinLen {
		return nil, errSalamanderPSKTooShort
	}
	pskCopy := append([]byte(nil), psk...)
	keyInput := make([]byte, len(pskCopy)+salamanderSaltLen)
	copy(keyInput, pskCopy)
	return &salamanderObfuscator{
		psk:      pskCopy,
		randSrc:  rand.New(rand.NewSource(time.Now().UnixNano())),
		keyInput: keyInput,
	}, nil
}

func (o *salamanderObfuscator) Obfuscate(in, out []byte) int {
	outLen := len(in) + salamanderSaltLen
	if len(out) < outLen {
		return 0
	}
	o.mu.Lock()
	_, _ = o.randSrc.Read(out[:salamanderSaltLen])
	key := o.keyLocked(out[:salamanderSaltLen])
	o.mu.Unlock()
	for i, b := range in {
		out[i+salamanderSaltLen] = b ^ key[i%salamanderKeyLen]
	}
	return outLen
}

func (o *salamanderObfuscator) Deobfuscate(in, out []byte) int {
	outLen := len(in) - salamanderSaltLen
	if outLen <= 0 || len(out) < outLen {
		return 0
	}
	o.mu.Lock()
	key := o.keyLocked(in[:salamanderSaltLen])
	o.mu.Unlock()
	for i, b := range in[salamanderSaltLen:] {
		out[i] = b ^ key[i%salamanderKeyLen]
	}
	return outLen
}

func (o *salamanderObfuscator) keyLocked(salt []byte) [salamanderKeyLen]byte {
	copy(o.keyInput[len(o.psk):], salt[:salamanderSaltLen])
	return blake2b.Sum256(o.keyInput)
}

type obfsPacketConn struct {
	conn net.PacketConn
	obfs packetObfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

type obfsPacketConnUDP struct {
	*obfsPacketConn
	udpConn *net.UDPConn
}

func newObfsPacketConn(conn net.PacketConn, obfs packetObfuscator) net.PacketConn {
	obfsConn := &obfsPacketConn{
		conn:     conn,
		obfs:     obfs,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
	if udpConn, ok := conn.(*net.UDPConn); ok {
		return &obfsPacketConnUDP{
			obfsPacketConn: obfsConn,
			udpConn:        udpConn,
		}
	}
	return obfsConn
}

func newSalamanderPacketConn(conn net.PacketConn, key []byte) (net.PacketConn, error) {
	obfs, err := newSalamanderObfuscator(key)
	if err != nil {
		return nil, err
	}
	return newObfsPacketConn(conn, obfs), nil
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		c.readMutex.Lock()
		n, addr, err = c.conn.ReadFrom(c.readBuf)
		if n <= 0 {
			c.readMutex.Unlock()
			return n, addr, err
		}
		n = c.obfs.Deobfuscate(c.readBuf[:n], p)
		c.readMutex.Unlock()
		if n > 0 || err != nil {
			return n, addr, err
		}
	}
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()
	nn := c.obfs.Obfuscate(p, c.writeBuf)
	if nn == 0 {
		c.writeMutex.Unlock()
		return 0, fmt.Errorf("obfuscated packet is too large: %d bytes", len(p))
	}
	_, err = c.conn.WriteTo(c.writeBuf[:nn], addr)
	c.writeMutex.Unlock()
	if err == nil {
		n = len(p)
	}
	return n, err
}

func (c *obfsPacketConn) Close() error {
	return c.conn.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *obfsPacketConnUDP) SetReadBuffer(bytes int) error {
	return c.udpConn.SetReadBuffer(bytes)
}

func (c *obfsPacketConnUDP) SetWriteBuffer(bytes int) error {
	return c.udpConn.SetWriteBuffer(bytes)
}

func (c *obfsPacketConnUDP) SyscallConn() (syscall.RawConn, error) {
	return c.udpConn.SyscallConn()
}
