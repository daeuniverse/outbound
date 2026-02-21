package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	poolBytes "github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
	"lukechampine.com/blake3"
)

type UdpConn struct {
	net.Conn

	sessionID [8]byte
	packetID  atomic.Uint64

	cipherConf         *ciphers.CipherConf2022
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block

	pskList [][]byte
	uPSK    []byte
	bloom   *disk_bloom.FilterGroup

	// Use sync.Map for better read performance in hot path
	replayWindow sync.Map // map[[8]byte]*udpSessionReplayState
}

const (
	udpPacketReplayWindowSize = 1024
	maxTrackedUdpSessions     = 128
)

type udpSessionReplayState struct {
	filter   *ciphers.SlidingWindowFilter
	lastSeen atomic.Int64 // Unix nano timestamp
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf2022, blockCipherEncrypt cipher.Block, blockCipherDecrypt cipher.Block, pskList [][]byte, uPSK []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := UdpConn{
		Conn:               conn,
		cipherConf:         conf,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
		pskList:            pskList,
		uPSK:               uPSK,
		bloom:              bloom,
	}
	fastrand.Read(u.sessionID[:])
	return &u, nil
}

func (c *UdpConn) nextPacketID() uint64 {
	return c.packetID.Add(1)
}

func (c *UdpConn) checkAndUpdateReplay(sessionID [8]byte, packetID uint64, now time.Time) bool {
	nowNano := now.UnixNano()
	expireNano := ciphers.SaltStorageDuration.Nanoseconds()

	// Fast path: try to get existing state
	if v, ok := c.replayWindow.Load(sessionID); ok {
		state := v.(*udpSessionReplayState)
		lastSeen := state.lastSeen.Load()
		if nowNano-lastSeen > expireNano {
			// Session expired, try to delete and create new
			c.replayWindow.CompareAndDelete(sessionID, v)
		} else {
			state.lastSeen.Store(nowNano)
			return state.filter.CheckAndUpdate(packetID)
		}
	}

	// Periodic cleanup of expired sessions
	c.cleanupExpiredSessions(nowNano, expireNano)

	// Try to create new state
	newState := &udpSessionReplayState{
		filter: ciphers.NewSlidingWindowFilter(udpPacketReplayWindowSize),
	}
	newState.lastSeen.Store(nowNano)

	// Use LoadOrStore for atomic create-or-get
	actual, loaded := c.replayWindow.LoadOrStore(sessionID, newState)
	state := actual.(*udpSessionReplayState)

	if loaded {
		// Another goroutine created it first
		state.lastSeen.Store(nowNano)
	} else {
		// Check if we need to evict oldest session (only for creator)
		c.evictOldestIfNeeded()
	}

	return state.filter.CheckAndUpdate(packetID)
}

// cleanupExpiredSessions removes expired sessions periodically
func (c *UdpConn) cleanupExpiredSessions(nowNano, expireNano int64) {
	c.replayWindow.Range(func(key, value interface{}) bool {
		state := value.(*udpSessionReplayState)
		if nowNano-state.lastSeen.Load() > expireNano {
			c.replayWindow.Delete(key)
		}
		return true
	})
}

// evictOldestIfNeeded evicts the oldest session if we exceed max sessions
func (c *UdpConn) evictOldestIfNeeded() {
	var count int
	var oldestKey [8]byte
	var oldestNano int64 = ^int64(0) // max int64

	c.replayWindow.Range(func(key, value interface{}) bool {
		count++
		state := value.(*udpSessionReplayState)
		seen := state.lastSeen.Load()
		if seen < oldestNano {
			oldestKey = key.([8]byte)
			oldestNano = seen
		}
		return true
	})

	if count > maxTrackedUdpSessions {
		c.replayWindow.Delete(oldestKey)
	}
}

func (c *UdpConn) writeIdentityHeader(buf *poolBytes.Buffer, separateHeader []byte) error {
	for i := 0; i < len(c.pskList)-1; i++ {
		identityHeader := pool.Get(aes.BlockSize)
		defer pool.Put(identityHeader)

		hash := blake3.Sum512(c.pskList[i+1])
		subtle.XORBytes(identityHeader, hash[:aes.BlockSize], separateHeader)
		b, err := c.cipherConf.NewBlockCipher(c.pskList[i])
		if err != nil {
			return err
		}
		b.Encrypt(identityHeader, identityHeader)
		buf.Write(identityHeader)
	}
	return nil
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	separateHeader := pool.GetBuffer()
	defer pool.PutBuffer(separateHeader)

	packetID := c.nextPacketID()

	separateHeader.Write(c.sessionID[:])
	binary.Write(separateHeader, binary.BigEndian, packetID)

	separateHeaderEncrypted := pool.Get(16)
	defer pool.Put(separateHeaderEncrypted)
	c.blockCipherEncrypt.Encrypt(separateHeaderEncrypted, separateHeader.Bytes())

	buf.Write(separateHeaderEncrypted)

	err := c.writeIdentityHeader(buf, separateHeader.Bytes())
	if err != nil {
		return 0, oops.Wrapf(err, "fail to write identity header")
	}

	message, err := EncodeMessage(HeaderTypeClientStream, uint64(time.Now().Unix()), addr, b)
	defer pool.PutBuffer(message)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to encode message")
	}

	// Encrypt and send
	// Optimized: Use cached cipher for session reuse
	cipher, err := GetCachedCipher(c.uPSK, separateHeader.Bytes()[:8], c.cipherConf, true)
	if err != nil {
		return 0, err
	}
	buf.Write(cipher.Seal(nil, separateHeader.Bytes()[4:16], message.Bytes(), nil))

	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

func EncodeMessage(typ uint8, timestamp uint64, address string, b []byte) (*poolBytes.Buffer, error) {
	message := pool.GetBuffer()
	// Header
	message.WriteByte(typ)
	binary.Write(message, binary.BigEndian, timestamp)
	// No padding
	binary.Write(message, binary.BigEndian, uint16(0))
	// Socks Address
	addrInfo, err := socks5.AddressFromString(address)
	if err != nil {
		return nil, err
	}
	if err := socks5.WriteAddrInfo(addrInfo, message); err != nil {
		return nil, err
	}
	// Payload
	message.Write(b)

	return message, nil
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(len(b) + 16 + c.cipherConf.TagLen)
	defer pool.Put(buf)
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < 16 {
		return 0, netip.AddrPort{}, fmt.Errorf("short length to decrypt")
	}

	c.blockCipherDecrypt.Decrypt(buf[:16], buf[:16])
	var sessionID [8]byte
	copy(sessionID[:], buf[:8])
	packetID := binary.BigEndian.Uint64(buf[8:16])
	now := time.Now()
	if !c.checkAndUpdateReplay(sessionID, packetID, now) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	payload := buf[16:n]
	// Optimized: Use cached cipher for session reuse
	ciph, err := GetCachedCipher(c.uPSK, buf[:8], c.cipherConf, false)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload, err = ciph.Open(payload[:0], buf[4:16], payload, nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Use bytes.Reader to simplify parsing
	reader := bytes.NewReader(payload)

	// Read header type
	var typ uint8
	if err := binary.Read(reader, binary.BigEndian, &typ); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read header type: %w", err)
	}

	// Read timestamp
	var timestampRaw uint64
	if err := binary.Read(reader, binary.BigEndian, &timestampRaw); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	timestamp := time.Unix(int64(timestampRaw), 0)

	// Skip client session ID (8 bytes)
	if _, err := reader.Seek(8, io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip session ID: %w", err)
	}

	// Read padding length
	var paddingLength uint16
	if err := binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read padding length: %w", err)
	}

	// Skip padding
	if _, err := reader.Seek(int64(paddingLength), io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip padding: %w", err)
	}

	if typ != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, fmt.Errorf("received unexpected header type: %d", typ)
	}

	if err := validateTimestamp(timestamp, now); err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Parse address from decrypted data
	netAddr, err := socks5.ReadAddr(reader)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Convert net.Addr to netip.AddrPort
	if udpAddr, ok := netAddr.(*net.UDPAddr); ok {
		ipAddr, _ := netip.AddrFromSlice(udpAddr.IP)
		addr = netip.AddrPortFrom(ipAddr, uint16(udpAddr.Port))
	}

	// Copy remaining data to output buffer
	n, err = reader.Read(b)
	return
}
