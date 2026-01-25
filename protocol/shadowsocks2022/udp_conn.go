package shadowsocks2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

const (
	// UDP separate header for AES mode: Session ID(8B) + Packet ID(8B)
	UDPSeparateHeaderLen = 16

	// UDP client message header: Type(1) + Timestamp(8) + PaddingLen(2)
	UDPClientMessageHeaderFixedLen = 1 + 8 + 2

	// UDP server message header: Type(1) + Timestamp(8) + ClientSessionID(8) + PaddingLen(2)
	UDPServerMessageHeaderFixedLen = 1 + 8 + 8 + 2

	// Max UDP payload size
	MaxUDPPayloadSize = 65535

	// UDP session ID length for ChaCha20 mode (part of 24B nonce)
	UDPChaChaSessionIDLen = 8
)

// UDPConn represents a SS2022 UDP connection
type UDPConn struct {
	netproxy.PacketConn

	proxyAddress string
	metadata     protocol.Metadata
	config       *CipherConfig
	psk          []byte
	iPSK         []byte

	// Session state (common for both modes)
	clientSessionID uint64
	packetID        atomic.Uint64 // Starts from 1 (first Add returns 1)

	// ============= AES Mode Fields =============
	// AEAD cipher for this session (derived from session ID)
	sessionCipher cipher.AEAD

	// Block cipher for separate header encryption (AES mode only)
	// For single-user: uses psk (uPSK)
	// For multi-user client->server: uses iPSK
	// For multi-user server->client: uses uPSK
	clientHeaderBlockCipher cipher.Block // For encrypting client packets
	serverHeaderBlockCipher cipher.Block // For decrypting server packets (uses uPSK)

	// PSK hash for identity header
	uPSKHash [IdentityHeaderLen]byte

	// Server session tracking for replay protection (AES mode)
	serverSessionMu            sync.Mutex
	currentServerSessionID     uint64
	currentServerSessionCipher cipher.AEAD
	currentServerFilter        *SlidingWindowFilter
	oldServerSessionID         uint64
	oldServerSessionCipher     cipher.AEAD
	oldServerFilter            *SlidingWindowFilter
	oldServerLastSeen          time.Time

	// ============= ChaCha20 Mode Fields =============
	// For ChaCha20 mode: cipher is derived from PSK directly (no session key derivation)
	chachaCipher cipher.AEAD
	// ChaCha20 mode uses per-packet random nonce, no separate header
	// Server session tracking for ChaCha20 (simpler - just packet ID filter)
	chachaServerFilter *SlidingWindowFilter

	tgtAddr string
}

// NewUDPConn creates a new SS2022 UDP connection
func NewUDPConn(conn netproxy.PacketConn, proxyAddress string, metadata protocol.Metadata, psk, iPSK []byte, config *CipherConfig) (*UDPConn, error) {
	// Generate random client session ID
	var sessionIDBuf [8]byte
	if _, err := rand.Read(sessionIDBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	clientSessionID := binary.BigEndian.Uint64(sessionIDBuf[:])

	c := &UDPConn{
		PacketConn:      conn,
		proxyAddress:    proxyAddress,
		metadata:        metadata,
		config:          config,
		psk:             psk,
		iPSK:            iPSK,
		clientSessionID: clientSessionID,
		tgtAddr:         net.JoinHostPort(metadata.Hostname, strconv.Itoa(int(metadata.Port))),
	}

	var err error

	if config.UDPMode == UDPModeChaCha {
		// ChaCha20 mode: use XChaCha20-Poly1305 with 24B random nonce
		// Use PSK directly (no session key derivation), consistent with Rust/Sing.
		c.chachaCipher, err = config.NewUDPCipher(psk)
		if err != nil {
			return nil, fmt.Errorf("failed to create XChaCha20 cipher: %w", err)
		}
		c.chachaServerFilter = NewSlidingWindowFilter(DefaultWindowSize)
	} else {
		// AES mode: use 16B separate header + AES-ECB + AES-GCM
		// Derive session key using session ID as salt
		sessionKey := DeriveSessionKey(psk, sessionIDBuf[:], config.KeyLen)

		// Create session AEAD cipher
		c.sessionCipher, err = config.NewUDPCipher(sessionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create session cipher: %w", err)
		}

		// Create header block ciphers
		// For client->server separate header:
		//   - Single-user: use psk (uPSK)
		//   - Multi-user: use iPSK
		var clientHeaderBlockCipher cipher.Block
		if iPSK != nil {
			// Multi-user mode: use iPSK for client->server
			clientHeaderBlockCipher, err = CreateECBEncryptorWithKeyLen(iPSK, config.KeyLen)
		} else {
			// Single-user mode: use psk
			clientHeaderBlockCipher, err = CreateECBEncryptorWithKeyLen(psk, config.KeyLen)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create client header cipher: %w", err)
		}
		c.clientHeaderBlockCipher = clientHeaderBlockCipher

		// For server->client separate header: always use psk (uPSK)
		serverHeaderBlockCipher, err := CreateECBEncryptorWithKeyLen(psk, config.KeyLen)
		if err != nil {
			return nil, fmt.Errorf("failed to create server header cipher: %w", err)
		}
		c.serverHeaderBlockCipher = serverHeaderBlockCipher

		// Pre-compute uPSK hash for identity headers
		c.uPSKHash = PSKHash(psk)
	}

	return c, nil
}

// Close closes the connection
func (c *UDPConn) Close() error {
	return c.PacketConn.Close()
}

// Read reads data from the connection
func (c *UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

// Write writes data to the connection
func (c *UDPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.tgtAddr)
}

// WriteTo writes data to the specified address
func (c *UDPConn) WriteTo(b []byte, addr string) (int, error) {
	if c.config.UDPMode == UDPModeChaCha {
		return c.writeToChaCha(b, addr)
	}
	return c.writeToAES(b, addr)
}

// writeToChaCha writes data using ChaCha20 mode (24B random nonce + XChaCha20-Poly1305)
// ChaCha20 message body contains SessionID and PacketID (unlike AES mode where they're in separate header)
func (c *UDPConn) writeToChaCha(b []byte, addr string) (int, error) {
	// Parse target address
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}

	// Get current packet ID (starts from 1)
	packetID := c.packetID.Add(1)

	// Build address
	addrBytes, err := EncodeAddress(mdata.Hostname, mdata.Port)
	if err != nil {
		return 0, fmt.Errorf("failed to encode address: %w", err)
	}
	defer pool.Put(addrBytes)

	// No padding for simplicity
	paddingLen := 0

	// ChaCha20 message body format (different from AES!):
	// SessionID(8) + PacketID(8) + Type(1) + Timestamp(8) + PaddingLen(2) + Padding + Address + Payload
	messageLen := 8 + 8 + UDPClientMessageHeaderFixedLen + paddingLen + len(addrBytes) + len(b)
	message := pool.Get(messageLen)
	defer pool.Put(message)

	offset := 0
	// SessionID and PacketID are inside encrypted body for ChaCha20
	binary.BigEndian.PutUint64(message[offset:], c.clientSessionID)
	offset += 8
	binary.BigEndian.PutUint64(message[offset:], packetID)
	offset += 8
	message[offset] = HeaderTypeClientRequest
	offset++
	binary.BigEndian.PutUint64(message[offset:], uint64(time.Now().Unix()))
	offset += 8
	binary.BigEndian.PutUint16(message[offset:], uint16(paddingLen))
	offset += 2
	offset += paddingLen // Skip padding
	copy(message[offset:], addrBytes)
	offset += len(addrBytes)
	copy(message[offset:], b)

	// ChaCha20 mode packet format:
	// Nonce(24B, pure random) + EncryptedMessage + Tag(16B)
	totalLen := XChaCha20NonceLen + messageLen + c.config.TagLen
	packet := pool.Get(totalLen)
	defer pool.Put(packet)

	// Generate pure random 24B nonce (no embedded session/packet ID)
	nonce := packet[:XChaCha20NonceLen]
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// AEAD seal the message
	c.chachaCipher.Seal(packet[XChaCha20NonceLen:XChaCha20NonceLen], nonce, message, nil)

	return c.PacketConn.WriteTo(packet[:totalLen], c.proxyAddress)
}

// writeToAES writes data using AES mode (16B separate header + AES-ECB + AES-GCM)
func (c *UDPConn) writeToAES(b []byte, addr string) (int, error) {
	// Parse target address
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}

	// Get current packet ID (starts from 1)
	packetID := c.packetID.Add(1)

	// Build address
	addrBytes, err := EncodeAddress(mdata.Hostname, mdata.Port)
	if err != nil {
		return 0, fmt.Errorf("failed to encode address: %w", err)
	}
	defer pool.Put(addrBytes)

	// No padding for simplicity
	paddingLen := 0

	// Build message: Type(1) + Timestamp(8) + PaddingLen(2) + Padding + Address + Payload
	messageLen := UDPClientMessageHeaderFixedLen + paddingLen + len(addrBytes) + len(b)
	message := pool.Get(messageLen)
	defer pool.Put(message)

	offset := 0
	message[offset] = HeaderTypeClientRequest
	offset++
	binary.BigEndian.PutUint64(message[offset:], uint64(time.Now().Unix()))
	offset += 8
	binary.BigEndian.PutUint16(message[offset:], uint16(paddingLen))
	offset += 2
	offset += paddingLen // Skip padding
	copy(message[offset:], addrBytes)
	offset += len(addrBytes)
	copy(message[offset:], b)

	// Calculate identity headers length
	identityHeadersLen := 0
	if c.iPSK != nil {
		identityHeadersLen = IdentityHeaderLen
	}

	// Total packet: SeparateHeader(16) + IdentityHeaders(optional) + EncryptedMessage + Tag
	totalLen := UDPSeparateHeaderLen + identityHeadersLen + messageLen + c.config.TagLen
	packet := pool.Get(totalLen)
	defer pool.Put(packet)

	// Build separate header: SessionID(8) + PacketID(8)
	separateHeader := packet[:UDPSeparateHeaderLen]
	binary.BigEndian.PutUint64(separateHeader[:8], c.clientSessionID)
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)

	// Nonce is bytes [4:16] of the separate header (before encryption)
	nonce := make([]byte, c.config.NonceLen)
	copy(nonce, separateHeader[4:16])

	writeOffset := UDPSeparateHeaderLen

	// Generate identity headers if multi-user mode
	if c.iPSK != nil {
		identityHeader, err := GenerateUDPIdentityHeader(c.iPSK, c.uPSKHash, separateHeader)
		if err != nil {
			return 0, fmt.Errorf("failed to generate identity header: %w", err)
		}
		copy(packet[writeOffset:], identityHeader)
		writeOffset += IdentityHeaderLen
	}

	// AEAD seal the message
	c.sessionCipher.Seal(packet[writeOffset:writeOffset], nonce, message, nil)
	writeOffset += messageLen + c.config.TagLen

	// Encrypt separate header with AES-ECB (using clientHeaderBlockCipher)
	c.clientHeaderBlockCipher.Encrypt(packet[:UDPSeparateHeaderLen], separateHeader)

	return c.PacketConn.WriteTo(packet[:writeOffset], c.proxyAddress)
}

// ReadFrom reads data from the connection
func (c *UDPConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	if c.config.UDPMode == UDPModeChaCha {
		return c.readFromChaCha(b)
	}
	return c.readFromAES(b)
}

// readFromChaCha reads data using ChaCha20 mode (24B random nonce + XChaCha20-Poly1305)
// ChaCha20 message body contains SessionID and PacketID (unlike AES mode where they're in separate header)
func (c *UDPConn) readFromChaCha(b []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(MaxUDPPayloadSize)
	defer pool.Put(buf)

	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Minimum packet size: 24B nonce + tag
	minSize := XChaCha20NonceLen + c.config.TagLen
	if n < minSize {
		return 0, netip.AddrPort{}, fmt.Errorf("packet too short: %d < %d", n, minSize)
	}

	packet := buf[:n]

	// Extract 24B nonce (pure random, no embedded session/packet ID)
	nonce := packet[:XChaCha20NonceLen]
	ciphertext := packet[XChaCha20NonceLen:]

	// Decrypt message using the same cipher (server uses same session key)
	plaintext, err := c.chachaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to decrypt: %w", err)
	}

	// ChaCha20 server message body format:
	// SessionID(8) + PacketID(8) + Type(1) + Timestamp(8) + ClientSessionID(8) + PaddingLen(2) + Padding + Address + Payload
	minBodyLen := 8 + 8 + UDPServerMessageHeaderFixedLen
	if len(plaintext) < minBodyLen {
		return 0, netip.AddrPort{}, fmt.Errorf("plaintext too short for server header")
	}

	offset := 0

	// Server session ID (from encrypted body)
	serverSessionID := binary.BigEndian.Uint64(plaintext[offset:])
	offset += 8
	_ = serverSessionID // Server session ID is for session tracking if needed

	// Packet ID (from encrypted body) - used for replay protection
	serverPacketID := binary.BigEndian.Uint64(plaintext[offset:])
	offset += 8

	// Check replay using packet ID extracted from body
	if !c.chachaServerFilter.Check(serverPacketID) {
		return 0, netip.AddrPort{}, fmt.Errorf("replay detected: packet %d", serverPacketID)
	}

	// Type
	if plaintext[offset] != HeaderTypeServerResponse {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid header type: expected %d, got %d", HeaderTypeServerResponse, plaintext[offset])
	}
	offset++

	// Timestamp
	timestamp := binary.BigEndian.Uint64(plaintext[offset:])
	offset += 8
	if err := ValidateTimestamp(timestamp); err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Client session ID
	responseClientSessionID := binary.BigEndian.Uint64(plaintext[offset:])
	offset += 8
	if responseClientSessionID != c.clientSessionID {
		return 0, netip.AddrPort{}, fmt.Errorf("client session ID mismatch: expected %d, got %d", c.clientSessionID, responseClientSessionID)
	}

	// Padding length
	paddingLen := int(binary.BigEndian.Uint16(plaintext[offset:]))
	offset += 2
	offset += paddingLen // Skip padding

	// Address (for server response, this is the source address)
	_, _, addrLen, err := DecodeAddress(plaintext[offset:])
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to decode address: %w", err)
	}
	offset += addrLen

	// Copy payload
	payload := plaintext[offset:]
	n = copy(b, payload)

	return n, addr, nil
}

// readFromAES reads data using AES mode (16B separate header + AES-ECB + AES-GCM)
func (c *UDPConn) readFromAES(b []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(MaxUDPPayloadSize)
	defer pool.Put(buf)

	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Minimum packet size: separate header + tag
	minSize := UDPSeparateHeaderLen + c.config.TagLen
	if n < minSize {
		return 0, netip.AddrPort{}, fmt.Errorf("packet too short: %d < %d", n, minSize)
	}

	packet := buf[:n]

	// Decrypt separate header with AES-ECB (using serverHeaderBlockCipher = uPSK)
	separateHeader := make([]byte, UDPSeparateHeaderLen)
	c.serverHeaderBlockCipher.Decrypt(separateHeader, packet[:UDPSeparateHeaderLen])

	// Extract session ID and packet ID
	serverSessionID := binary.BigEndian.Uint64(separateHeader[:8])
	serverPacketID := binary.BigEndian.Uint64(separateHeader[8:])

	// Nonce is bytes [4:16] of the decrypted separate header
	nonce := make([]byte, c.config.NonceLen)
	copy(nonce, separateHeader[4:16])

	ciphertext := packet[UDPSeparateHeaderLen:]

	// Determine which server session cipher to use
	c.serverSessionMu.Lock()
	var serverCipher cipher.AEAD
	var filter *SlidingWindowFilter
	var isNewSession bool

	switch {
	case serverSessionID == c.currentServerSessionID && c.currentServerSessionCipher != nil:
		serverCipher = c.currentServerSessionCipher
		filter = c.currentServerFilter
	case serverSessionID == c.oldServerSessionID && c.oldServerSessionCipher != nil:
		serverCipher = c.oldServerSessionCipher
		filter = c.oldServerFilter
		c.oldServerLastSeen = time.Now()
	case time.Since(c.oldServerLastSeen) < time.Minute && c.currentServerSessionID != 0:
		c.serverSessionMu.Unlock()
		return 0, netip.AddrPort{}, fmt.Errorf("server session changed too frequently")
	default:
		// New server session - derive key
		sessionKey := DeriveSessionKey(c.psk, separateHeader[:8], c.config.KeyLen)
		serverCipher, err = c.config.NewUDPCipher(sessionKey)
		if err != nil {
			c.serverSessionMu.Unlock()
			return 0, netip.AddrPort{}, fmt.Errorf("failed to create server cipher: %w", err)
		}
		isNewSession = true
	}
	c.serverSessionMu.Unlock()

	// Check replay
	if filter != nil && !filter.Check(serverPacketID) {
		return 0, netip.AddrPort{}, fmt.Errorf("replay detected: session %d packet %d", serverSessionID, serverPacketID)
	}

	// Decrypt message
	plaintext, err := serverCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Parse server message header: Type(1) + Timestamp(8) + ClientSessionID(8) + PaddingLen(2) + Padding + Address + Payload
	if len(plaintext) < UDPServerMessageHeaderFixedLen {
		return 0, netip.AddrPort{}, fmt.Errorf("plaintext too short for server header")
	}

	offset := 0

	// Type
	if plaintext[offset] != HeaderTypeServerResponse {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid header type: expected %d, got %d", HeaderTypeServerResponse, plaintext[offset])
	}
	offset++

	// Timestamp
	timestamp := binary.BigEndian.Uint64(plaintext[offset:])
	offset += 8
	if err := ValidateTimestamp(timestamp); err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Client session ID
	responseClientSessionID := binary.BigEndian.Uint64(plaintext[offset:])
	offset += 8
	if responseClientSessionID != c.clientSessionID {
		return 0, netip.AddrPort{}, fmt.Errorf("client session ID mismatch: expected %d, got %d", c.clientSessionID, responseClientSessionID)
	}

	// Padding length
	paddingLen := int(binary.BigEndian.Uint16(plaintext[offset:]))
	offset += 2
	offset += paddingLen // Skip padding

	// Address (for server response, this is the source address)
	_, _, addrLen, err := DecodeAddress(plaintext[offset:])
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to decode address: %w", err)
	}
	offset += addrLen

	// Update server session tracking
	c.serverSessionMu.Lock()
	if isNewSession {
		if c.currentServerSessionID != 0 {
			c.oldServerSessionID = c.currentServerSessionID
			c.oldServerSessionCipher = c.currentServerSessionCipher
			c.oldServerFilter = c.currentServerFilter
			c.oldServerLastSeen = time.Now()
		}
		c.currentServerSessionID = serverSessionID
		c.currentServerSessionCipher = serverCipher
		c.currentServerFilter = NewSlidingWindowFilter(DefaultWindowSize)
	}
	if c.currentServerSessionID == serverSessionID {
		c.currentServerFilter.Check(serverPacketID) // Add to filter
	} else if c.oldServerSessionID == serverSessionID {
		c.oldServerFilter.Check(serverPacketID)
	}
	c.serverSessionMu.Unlock()

	// Copy payload
	payload := plaintext[offset:]
	n = copy(b, payload)

	return n, addr, nil
}
