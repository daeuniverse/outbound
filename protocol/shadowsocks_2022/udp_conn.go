package shadowsocks_2022

import (
	"bytes"
	"crypto/cipher"
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
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
)

// UdpConn represents a Shadowsocks 2022 UDP connection.
// Design follows sing-box: cipher is created once at session initialization.
type UdpConn struct {
	*SS2022Core

	net.Conn

	sessionID [8]byte
	packetID  atomic.Uint64

	// cipher is derived from the local session ID and reused for outbound
	// packets. Inbound packets must decrypt against the remote session ID
	// carried in each packet, so they use decryptCiphers instead.
	cipher     cipher.AEAD
	cipherOnce sync.Once
	cipherErr  error

	// decryptCiphers caches inbound AEAD instances by remote session ID.
	// Keeping this per-UdpConn avoids the old process-wide cache while
	// preserving the protocol requirement that receive-side decryption uses
	// the sender's session ID, not the local one.
	decryptCiphers sync.Map // map[[8]byte]cipher.AEAD

	bloom *disk_bloom.FilterGroup

	replayWindow sync.Map
	replayCount  atomic.Int64

	cleanupCounter atomic.Int64
}

const (
	udpPacketReplayWindowSize = 1024
	maxTrackedUdpSessions     = 128
)

type udpSessionReplayState struct {
	filter   *ciphers.SlidingWindowFilter
	lastSeen atomic.Int64
}

// NewUdpConn creates a new UDP connection bound to a shared SS2022 profile.
func NewUdpConn(conn net.Conn, core *SS2022Core, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := &UdpConn{
		SS2022Core: core,
		Conn:       conn,
		bloom:      bloom,
	}

	// Generate session ID
	fastrand.Read(u.sessionID[:])
	return u, nil
}

func (c *UdpConn) ensureCipher() error {
	c.cipherOnce.Do(func() {
		c.cipher, c.cipherErr = CreateCipher(c.UPSK(), c.sessionID[:], c.CipherConf())
		if c.cipherErr != nil {
			c.cipherErr = fmt.Errorf("failed to create session cipher: %w", c.cipherErr)
		}
	})
	return c.cipherErr
}

func (c *UdpConn) decryptCipherFor(sessionID [8]byte) (cipher.AEAD, error) {
	if cached, ok := c.decryptCiphers.Load(sessionID); ok {
		return cached.(cipher.AEAD), nil
	}

	sessionCipher, err := CreateCipher(c.UPSK(), sessionID[:], c.CipherConf())
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypt cipher for remote session: %w", err)
	}
	actual, _ := c.decryptCiphers.LoadOrStore(sessionID, sessionCipher)
	return actual.(cipher.AEAD), nil
}

func (c *UdpConn) nextPacketID() uint64 {
	return c.packetID.Add(1)
}

func (c *UdpConn) checkAndUpdateReplay(sessionID [8]byte, packetID uint64, now time.Time) bool {
	nowNano := now.UnixNano()
	expireNano := ciphers.SaltStorageDuration.Nanoseconds()

	if v, ok := c.replayWindow.Load(sessionID); ok {
		state := v.(*udpSessionReplayState)
		lastSeen := state.lastSeen.Load()
		if nowNano-lastSeen > expireNano {
			if c.replayWindow.CompareAndDelete(sessionID, v) {
				c.replayCount.Add(-1)
			}
		} else {
			state.lastSeen.Store(nowNano)
			return state.filter.CheckAndUpdate(packetID)
		}
	}

	if c.cleanupCounter.Add(1)%cleanupInterval == 0 {
		go c.cleanupExpiredSessions(nowNano, expireNano)
	}

	newState := &udpSessionReplayState{
		filter: ciphers.NewSlidingWindowFilter(udpPacketReplayWindowSize),
	}
	newState.lastSeen.Store(nowNano)

	actual, loaded := c.replayWindow.LoadOrStore(sessionID, newState)
	state := actual.(*udpSessionReplayState)

	if loaded {
		state.lastSeen.Store(nowNano)
	} else {
		c.replayCount.Add(1)
		c.evictOldestIfNeeded()
	}

	return state.filter.CheckAndUpdate(packetID)
}

const cleanupInterval = 1000

func (c *UdpConn) cleanupExpiredSessions(nowNano, expireNano int64) {
	c.replayWindow.Range(func(key, value interface{}) bool {
		state := value.(*udpSessionReplayState)
		if nowNano-state.lastSeen.Load() > expireNano {
			if c.replayWindow.CompareAndDelete(key, value) {
				c.replayCount.Add(-1)
			}
		}
		return true
	})
}

func (c *UdpConn) evictOldestIfNeeded() {
	for c.replayCount.Load() > maxTrackedUdpSessions {
		var (
			found      bool
			oldestKey  [8]byte
			oldestVal  any
			oldestNano int64 = ^int64(0)
		)

		c.replayWindow.Range(func(key, value interface{}) bool {
			state := value.(*udpSessionReplayState)
			seen := state.lastSeen.Load()
			if !found || seen < oldestNano {
				found = true
				oldestKey = key.([8]byte)
				oldestVal = value
				oldestNano = seen
			}
			return true
		})

		if !found {
			c.replayCount.Store(0)
			return
		}
		if c.replayWindow.CompareAndDelete(oldestKey, oldestVal) {
			c.replayCount.Add(-1)
			continue
		}
		// Retry if the oldest entry changed concurrently.
	}
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	if err := c.ensureCipher(); err != nil {
		return 0, err
	}

	packetID := c.nextPacketID()
	var separateHeader [16]byte
	copy(separateHeader[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)

	var separateHeaderEncrypted [16]byte
	c.BlockCipherEncrypt().Encrypt(separateHeaderEncrypted[:], separateHeader[:])

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to parse target address")
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to calculate address length")
	}
	messageLen := 1 + 8 + 2 + addrLen + len(b)
	totalPacketLen := len(separateHeaderEncrypted) + c.IdentityHeaderLen() + messageLen + c.CipherConf().TagLen
	packet := pool.Get(totalPacketLen)
	defer pool.Put(packet)
	offset := 0
	copy(packet[offset:], separateHeaderEncrypted[:])
	offset += len(separateHeaderEncrypted)

	identityHeaderLen, err := c.WriteIdentityHeader(packet[offset:], separateHeader[:])
	if err != nil {
		return 0, oops.Wrapf(err, "fail to write identity header")
	}
	offset += identityHeaderLen

	messageOffset := offset
	message := packet[messageOffset : messageOffset+messageLen]
	message[0] = HeaderTypeClientStream
	binary.BigEndian.PutUint64(message[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(message[9:11], 0)
	addrWritten, err := writeAddrInfoTo(message[11:], addrInfo)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to encode request address")
	}
	copy(message[11+addrWritten:], b)

	// Use session-level cipher (no cache lookup needed)
	packet = c.cipher.Seal(packet[:messageOffset], separateHeader[4:16], message, nil)

	_, err = c.Conn.Write(packet)
	return len(b), err
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(len(b) + 16 + c.CipherConf().TagLen)
	defer pool.Put(buf)
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < 16 {
		return 0, netip.AddrPort{}, fmt.Errorf("short length to decrypt")
	}

	c.BlockCipherDecrypt().Decrypt(buf[:16], buf[:16])
	var sessionID [8]byte
	copy(sessionID[:], buf[:8])
	packetID := binary.BigEndian.Uint64(buf[8:16])
	now := time.Now()
	if !c.checkAndUpdateReplay(sessionID, packetID, now) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	payload := buf[16:n]
	sessionCipher, err := c.decryptCipherFor(sessionID)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload, err = sessionCipher.Open(payload[:0], buf[4:16], payload, nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	reader := bytes.NewReader(payload)

	var typ uint8
	if err := binary.Read(reader, binary.BigEndian, &typ); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read header type: %w", err)
	}

	var timestampRaw uint64
	if err := binary.Read(reader, binary.BigEndian, &timestampRaw); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	timestamp := time.Unix(int64(timestampRaw), 0)

	if _, err := reader.Seek(8, io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip session ID: %w", err)
	}

	var paddingLength uint16
	if err := binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read padding length: %w", err)
	}

	if _, err := reader.Seek(int64(paddingLength), io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip padding: %w", err)
	}

	if typ != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, fmt.Errorf("received unexpected header type: %d", typ)
	}

	if err := validateTimestamp(timestamp, now); err != nil {
		return 0, netip.AddrPort{}, err
	}

	netAddr, err := socks5.ReadAddr(reader)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if udpAddr, ok := netAddr.(*net.UDPAddr); ok {
		ipAddr, _ := netip.AddrFromSlice(udpAddr.IP)
		addr = netip.AddrPortFrom(ipAddr, uint16(udpAddr.Port))
	}

	n, err = reader.Read(b)
	return
}
