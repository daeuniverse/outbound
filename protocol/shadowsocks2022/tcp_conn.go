package shadowsocks2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

const (
	// TCPChunkMaxLen is the maximum length of a TCP chunk payload
	TCPChunkMaxLen = 0xFFFF // 65535 bytes

	// MaxInitialPayloadLen is the maximum length of initial payload in variable header
	// to avoid u16 overflow: varHeaderLen = addrLen + 2 + paddingLen + initialPayloadLen
	// We reserve some space for address and padding length field
	MaxInitialPayloadLen = 0xFFFF - 256 - 2
)

// TCPConn represents a SS2022 TCP connection
type TCPConn struct {
	netproxy.Conn
	metadata    protocol.Metadata
	config      *CipherConfig
	psk         []byte // effective PSK for encryption
	iPSK        []byte // identity PSK (nil for single-user mode)
	requestSalt []byte // stored for response validation

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    sync.Once
	onceWrite   sync.Once
	nonceRead   []byte
	nonceWrite  []byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	leftToRead  []byte
	indexToRead int

	// Track if first write has been done (to avoid sending initial data twice)
	firstWriteDone bool
}

// NewTCPConn creates a new SS2022 TCP connection
func NewTCPConn(conn netproxy.Conn, metadata protocol.Metadata, psk, iPSK []byte, config *CipherConfig) (*TCPConn, error) {
	c := &TCPConn{
		Conn:       conn,
		metadata:   metadata,
		config:     config,
		psk:        psk,
		iPSK:       iPSK,
		nonceRead:  make([]byte, config.NonceLen),
		nonceWrite: make([]byte, config.NonceLen),
	}

	return c, nil
}

// Close closes the connection
func (c *TCPConn) Close() error {
	return c.Conn.Close()
}

// Write writes data to the connection
func (c *TCPConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// First write: send header with initial payload
	if !c.firstWriteDone {
		c.firstWriteDone = true

		// Limit initial payload to avoid u16 overflow
		initialPayloadLen := common.Min(len(b), MaxInitialPayloadLen)
		if err := c.initWrite(b[:initialPayloadLen]); err != nil {
			return 0, err
		}
		n = initialPayloadLen
		b = b[initialPayloadLen:]

		// If there's remaining data, send as chunks
		if len(b) == 0 {
			return n, nil
		}
	}

	if c.cipherWrite == nil {
		return 0, fmt.Errorf("cipher not initialized")
	}

	// Write remaining data in chunks
	for len(b) > 0 {
		chunkLen := common.Min(TCPChunkMaxLen, len(b))
		chunk := b[:chunkLen]
		b = b[chunkLen:]

		// Encrypt and write chunk
		if err := c.writeChunk(chunk); err != nil {
			return n, err
		}
		n += chunkLen
	}

	return n, nil
}

// initWrite initializes the write side with request header
func (c *TCPConn) initWrite(initialData []byte) error {
	// Generate random salt
	salt := pool.Get(c.config.SaltLen)
	defer pool.Put(salt)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Store salt for response validation
	c.requestSalt = make([]byte, c.config.SaltLen)
	copy(c.requestSalt, salt)

	// Derive session key
	sessionKey := DeriveSessionKey(c.psk, salt, c.config.KeyLen)
	defer func() {
		for i := range sessionKey {
			sessionKey[i] = 0
		}
	}()

	// Create cipher
	var err error
	c.cipherWrite, err = c.config.NewCipher(sessionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Build address
	addrBytes, err := EncodeAddress(c.metadata.Hostname, c.metadata.Port)
	if err != nil {
		return fmt.Errorf("failed to encode address: %w", err)
	}
	defer pool.Put(addrBytes)

	// Calculate padding (0 for simplicity, can add random padding later)
	paddingLen := 0

	// Variable header format: Address + PaddingLen(2B) + Padding + InitialPayload
	varHeaderLen := len(addrBytes) + 2 + paddingLen + len(initialData)

	// Safety check for u16 overflow
	if varHeaderLen > 0xFFFF {
		return fmt.Errorf("variable header too long: %d > 65535", varHeaderLen)
	}

	varHeader := pool.Get(varHeaderLen)
	defer pool.Put(varHeader)

	offset := 0
	copy(varHeader[offset:], addrBytes)
	offset += len(addrBytes)
	binary.BigEndian.PutUint16(varHeader[offset:], uint16(paddingLen))
	offset += 2
	offset += paddingLen // Skip padding (zeros)
	copy(varHeader[offset:], initialData)

	// Build fixed header: Type(1) + Timestamp(8) + VarHeaderLen(2) = 11 bytes
	timestamp := uint64(time.Now().Unix())
	fixedHeader := EncodeFixedHeader(HeaderTypeClientRequest, timestamp, uint16(varHeaderLen))

	// Calculate identity headers length
	identityHeadersLen := 0
	if c.iPSK != nil {
		identityHeadersLen = IdentityHeaderLen
	}

	// Total: Salt + IdentityHeaders(optional) + EncryptedFixedHeader + EncryptedVarHeader
	totalLen := c.config.SaltLen + identityHeadersLen +
		(FixedHeaderLen + c.config.TagLen) +
		(varHeaderLen + c.config.TagLen)

	buf := pool.Get(totalLen)
	defer pool.Put(buf)

	writeOffset := 0

	// Copy salt
	copy(buf[writeOffset:], salt)
	writeOffset += c.config.SaltLen

	// Generate and copy identity header if multi-user mode
	if c.iPSK != nil {
		identityHeader, err := generateTCPIdentityHeader(c.iPSK, c.psk, salt, c.config.KeyLen)
		if err != nil {
			return fmt.Errorf("failed to generate identity header: %w", err)
		}
		copy(buf[writeOffset:], identityHeader)
		writeOffset += IdentityHeaderLen
	}

	// Encrypt fixed header
	c.cipherWrite.Seal(buf[writeOffset:writeOffset], c.nonceWrite, fixedHeader, nil)
	writeOffset += FixedHeaderLen + c.config.TagLen
	common.BytesIncLittleEndian(c.nonceWrite)

	// Encrypt variable header
	c.cipherWrite.Seal(buf[writeOffset:writeOffset], c.nonceWrite, varHeader, nil)
	writeOffset += varHeaderLen + c.config.TagLen
	common.BytesIncLittleEndian(c.nonceWrite)

	// Write to connection
	_, err = c.Conn.Write(buf[:writeOffset])
	return err
}

// generateTCPIdentityHeader generates the identity header for TCP
// Format: AES-ECB-Encrypt(identitySubkey, BLAKE3(uPSK)[:16])
func generateTCPIdentityHeader(iPSK, uPSK, salt []byte, keyLen int) ([]byte, error) {
	// Derive identity subkey: BLAKE3-DeriveKey("shadowsocks 2022 identity subkey", iPSK || salt)
	identitySubkey := DeriveIdentitySubkeyWithSalt(iPSK, salt, keyLen)

	// Hash user PSK: BLAKE3(uPSK)[:16]
	userPSKHash := PSKHash(uPSK)

	// Encrypt with AES-ECB (use appropriate key length)
	block, err := CreateECBEncryptorWithKeyLen(identitySubkey, keyLen)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	identityHeader := make([]byte, IdentityHeaderLen)
	block.Encrypt(identityHeader, userPSKHash[:])

	return identityHeader, nil
}

// writeChunk writes an encrypted chunk
func (c *TCPConn) writeChunk(data []byte) error {
	// Chunk format: EncryptedLength(2+Tag) + EncryptedPayload(len+Tag)
	chunkLen := 2 + c.config.TagLen + len(data) + c.config.TagLen
	buf := pool.Get(chunkLen)
	defer pool.Put(buf)

	// Encrypt length
	lenBuf := []byte{byte(len(data) >> 8), byte(len(data))}
	c.cipherWrite.Seal(buf[:0], c.nonceWrite, lenBuf, nil)
	common.BytesIncLittleEndian(c.nonceWrite)

	// Encrypt payload
	c.cipherWrite.Seal(buf[2+c.config.TagLen:2+c.config.TagLen], c.nonceWrite, data, nil)
	common.BytesIncLittleEndian(c.nonceWrite)

	_, err := c.Conn.Write(buf)
	return err
}

// Read reads data from the connection
func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	var initErr error
	c.onceRead.Do(func() {
		initErr = c.initRead()
	})
	if initErr != nil {
		return 0, initErr
	}

	// Return buffered data first
	if c.indexToRead < len(c.leftToRead) {
		n = copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead >= len(c.leftToRead) {
			pool.Put(c.leftToRead)
			c.leftToRead = nil
			c.indexToRead = 0
		}
		return n, nil
	}

	// Read new chunk
	chunk, err := c.readChunk()
	if err != nil {
		return 0, err
	}

	n = copy(b, chunk)
	if n < len(chunk) {
		c.leftToRead = chunk
		c.indexToRead = n
	} else {
		pool.Put(chunk)
	}

	return n, nil
}

// initRead initializes the read side by processing response header
func (c *TCPConn) initRead() error {
	// Read response salt
	salt := pool.Get(c.config.SaltLen)
	defer pool.Put(salt)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return fmt.Errorf("failed to read response salt: %w", err)
	}

	// Derive session key from response salt
	sessionKey := DeriveSessionKey(c.psk, salt, c.config.KeyLen)
	defer func() {
		for i := range sessionKey {
			sessionKey[i] = 0
		}
	}()

	// Create cipher
	var err error
	c.cipherRead, err = c.config.NewCipher(sessionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Response header length: Type(1) + Timestamp(8) + RequestSalt(SaltLen) + Length(2)
	responseHeaderLen := 1 + 8 + c.config.SaltLen + 2

	// Read and decrypt response header
	encResponseHeader := pool.Get(responseHeaderLen + c.config.TagLen)
	defer pool.Put(encResponseHeader)
	if _, err := io.ReadFull(c.Conn, encResponseHeader); err != nil {
		return fmt.Errorf("failed to read response header: %w", err)
	}

	responseHeader := pool.Get(responseHeaderLen)
	defer pool.Put(responseHeader)
	if _, err := c.cipherRead.Open(responseHeader[:0], c.nonceRead, encResponseHeader, nil); err != nil {
		return fmt.Errorf("failed to decrypt response header: %w", err)
	}
	common.BytesIncLittleEndian(c.nonceRead)

	// Parse response header
	// Type
	if responseHeader[0] != HeaderTypeServerResponse {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidHeaderType, HeaderTypeServerResponse, responseHeader[0])
	}

	// Timestamp
	timestamp := binary.BigEndian.Uint64(responseHeader[1:9])
	if err := ValidateTimestamp(timestamp); err != nil {
		return err
	}

	// Request salt validation
	responseSalt := responseHeader[9 : 9+c.config.SaltLen]
	if !compareBytes(responseSalt, c.requestSalt) {
		return ErrInvalidSalt
	}

	// Length of first payload chunk
	firstPayloadLen := binary.BigEndian.Uint16(responseHeader[9+c.config.SaltLen:])
	if firstPayloadLen == 0 {
		return fmt.Errorf("zero payload length in response header")
	}

	// Read and decrypt first payload chunk
	encFirstPayload := pool.Get(int(firstPayloadLen) + c.config.TagLen)
	defer pool.Put(encFirstPayload)
	if _, err := io.ReadFull(c.Conn, encFirstPayload); err != nil {
		return fmt.Errorf("failed to read first payload: %w", err)
	}

	firstPayload := pool.Get(int(firstPayloadLen))
	if _, err := c.cipherRead.Open(firstPayload[:0], c.nonceRead, encFirstPayload, nil); err != nil {
		pool.Put(firstPayload)
		return fmt.Errorf("failed to decrypt first payload: %w", err)
	}
	common.BytesIncLittleEndian(c.nonceRead)

	// Store first payload for later reading
	if firstPayloadLen > 0 {
		c.leftToRead = firstPayload
		c.indexToRead = 0
	} else {
		pool.Put(firstPayload)
	}

	return nil
}

// readChunk reads and decrypts a single chunk
func (c *TCPConn) readChunk() ([]byte, error) {
	// Read encrypted length
	encLen := pool.Get(2 + c.config.TagLen)
	defer pool.Put(encLen)
	if _, err := io.ReadFull(c.Conn, encLen); err != nil {
		return nil, err
	}

	// Decrypt length
	lenBuf := pool.Get(2)
	defer pool.Put(lenBuf)
	if _, err := c.cipherRead.Open(lenBuf[:0], c.nonceRead, encLen, nil); err != nil {
		return nil, fmt.Errorf("failed to decrypt length: %w", err)
	}
	common.BytesIncLittleEndian(c.nonceRead)

	payloadLen := binary.BigEndian.Uint16(lenBuf)
	if payloadLen == 0 {
		return nil, fmt.Errorf("zero length chunk")
	}

	// Read encrypted payload
	encPayload := pool.Get(int(payloadLen) + c.config.TagLen)
	defer pool.Put(encPayload)
	if _, err := io.ReadFull(c.Conn, encPayload); err != nil {
		return nil, err
	}

	// Decrypt payload (returned buffer must be freed by caller)
	payload := pool.Get(int(payloadLen))
	if _, err := c.cipherRead.Open(payload[:0], c.nonceRead, encPayload, nil); err != nil {
		pool.Put(payload)
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}
	common.BytesIncLittleEndian(c.nonceRead)

	return payload, nil
}
