package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/pool"
	poolBytes "github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
	"lukechampine.com/blake3"
)

const (
	TCPChunkMaxLen = (1 << 16) - 1

	HeaderTypeClientStream = 0
	HeaderTypeServerStream = 1
	MinPaddingLength       = 0
	MaxPaddingLength       = 900
)

// TCPConn represents a Shadowsocks TCP connection
type TCPConn struct {
	net.Conn
	addr       *socks5.AddressInfo
	cipherConf *ciphers.CipherConf2022
	pskList    [][]byte
	uPSK       []byte
	sg         shadowsocks.SaltGenerator

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	nonceRead   []byte
	nonceWrite  []byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	bufReader io.Reader

	bloom *disk_bloom.FilterGroup
}

type Key struct {
	CipherConf *ciphers.CipherConf
	MasterKey  []byte
}

func NewTCPConn(conn net.Conn, conf *ciphers.CipherConf2022, pskList [][]byte, uPSK []byte, sg shadowsocks.SaltGenerator, addr *socks5.AddressInfo, bloom *disk_bloom.FilterGroup) net.Conn {
	tcpConn := &TCPConn{
		Conn:       conn,
		addr:       addr,
		cipherConf: conf,
		pskList:    pskList,
		uPSK:       uPSK,
		sg:         sg,
		nonceRead:  make([]byte, conf.NonceLen),
		nonceWrite: make([]byte, conf.NonceLen),
		bloom:      bloom,
	}
	return tcpConn
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.bufReader != nil {
		n, err = c.bufReader.Read(b)
		if err != nil {
			c.bufReader = nil
			if err != io.EOF {
				return 0, err
			}
		}
		return n, nil
	}

	var payloadLength uint16

	if !c.onceRead {
		var salt = pool.Get(c.cipherConf.SaltLen)
		defer pool.Put(salt)

		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return 0, err
		}
		c.cipherRead, err = CreateCipher(c.uPSK, salt, c.cipherConf)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}

		header := pool.Get(11 + c.cipherConf.SaltLen + c.cipherConf.TagLen)
		defer pool.Put(header)
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			return 0, err
		}
		header, err := c.cipherRead.Open(header[:0], c.nonceRead, header, nil)
		if err != nil {
			return 0, protocol.ErrFailAuth
		}
		common.BytesIncLittleEndian(c.nonceRead)
		offset := 0
		typ := uint8(header[offset])
		offset += 1
		timestamp := time.Unix(int64(binary.BigEndian.Uint64(header[offset:offset+8])), 0)
		offset += 8

		if typ != HeaderTypeServerStream {
			return 0, fmt.Errorf("received unexpected header type: %d", typ)
		}

		if err := validateTimestamp(timestamp, time.Now()); err != nil {
			return 0, err
		}

		// Best-effort replay protection fallback for environments that provide bloom.
		if c.bloom != nil {
			if c.bloom.ExistOrAdd(salt) {
				return 0, protocol.ErrReplayAttack
			}
		}

		// Skip request salt
		offset += c.cipherConf.SaltLen

		payloadLength = binary.BigEndian.Uint16(header[offset : offset+2])

		c.onceRead = true
	} else {
		payloadLengthBuf := pool.Get(2 + c.cipherConf.TagLen)
		defer pool.Put(payloadLengthBuf)
		if _, err := io.ReadFull(c.Conn, payloadLengthBuf); err != nil {
			return 0, err
		}
		payloadLengthBuf, err := c.cipherRead.Open(payloadLengthBuf[:0], c.nonceRead, payloadLengthBuf, nil)
		if err != nil {
			return 0, protocol.ErrFailAuth
		}
		common.BytesIncLittleEndian(c.nonceRead)

		payloadLength = binary.BigEndian.Uint16(payloadLengthBuf)
	}

	if c.cipherRead == nil {
		return 0, oops.Wrapf(err, "cipher is not initialized")
	}

	payload := pool.Get(int(payloadLength) + c.cipherConf.TagLen)
	if _, err = io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}
	payload, err = c.cipherRead.Open(payload[:0], c.nonceRead, payload, nil)
	if err != nil {
		return 0, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)

	n = copy(b, payload)
	if len(payload) > n {
		c.bufReader = bytes.NewReader(payload[n:])
	}
	return n, nil
}

func EncodeRequestHeader(typ uint8, timestamp uint64, addressInfo *socks5.AddressInfo, b *[]byte) (*poolBytes.Buffer, *poolBytes.Buffer, error) {
	fixedHeader := poolBytes.NewBuffer(nil)
	varHeader := poolBytes.NewBuffer(nil)

	// Variable-length header: address (variable) + paddingLength (2) + padding (variable, 0) + payload (variable)
	if err := socks5.WriteAddrInfo(addressInfo, varHeader); err != nil {
		return nil, nil, err
	}
	// No padding
	binary.Write(varHeader, binary.BigEndian, uint16(0))
	initialPayloadMaxLength := TCPChunkMaxLen - varHeader.Len()
	var n int
	if len(*b) > initialPayloadMaxLength {
		varHeader.Write((*b)[:initialPayloadMaxLength])
		n = initialPayloadMaxLength
	} else {
		varHeader.Write(*b)
		n = len(*b)
	}
	*b = (*b)[n:]

	// Fixed-length header: type (1) + timestamp (8) + length (2) = 11 bytes
	fixedHeader.WriteByte(typ)
	binary.Write(fixedHeader, binary.BigEndian, timestamp)
	binary.Write(fixedHeader, binary.BigEndian, uint16(varHeader.Len()))

	return fixedHeader, varHeader, nil
}

func (c *TCPConn) writeIdentityHeader(buf *poolBytes.Buffer, salt []byte) error {
	identityHeader := pool.Get(aes.BlockSize)
	defer pool.Put(identityHeader)
	for i := 0; i < len(c.pskList)-1; i++ {
		identity_subkey := GenerateSubKey(c.pskList[i], salt, Shadowsocks2022IdentityHeaderInfo)
		plaintext := blake3.Sum512(c.pskList[i+1])
		b, err := c.cipherConf.NewBlockCipher(identity_subkey)
		if err != nil {
			return err
		}
		b.Encrypt(identityHeader, plaintext[:aes.BlockSize])
		buf.Write(identityHeader)
	}
	return nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	n = len(b)
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	if !c.onceWrite {
		// Generate salt
		salt := c.sg.Get()
		defer pool.Put(salt)
		buf.Write(salt)

		err := c.writeIdentityHeader(buf, salt)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to write identity header")
		}

		// Setup encryption
		c.cipherWrite, err = CreateCipher(c.uPSK, salt, c.cipherConf)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}

		// Add Request headers
		fixedHeader, varHeader, err := EncodeRequestHeader(HeaderTypeClientStream, uint64(time.Now().Unix()), c.addr, &b)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to encode request header")
		}
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, fixedHeader.Bytes(), nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, varHeader.Bytes(), nil))
		common.BytesIncLittleEndian(c.nonceWrite)

		c.onceWrite = true
	}
	if c.cipherWrite == nil {
		return 0, fmt.Errorf("cipher is not initialized")
	}
	c.seal(buf, b)
	_, err = c.Conn.Write(buf.Bytes())
	return n, err
}

func (c *TCPConn) seal(buf *poolBytes.Buffer, payload []byte) {
	chunkLengthBuf := pool.Get(2)
	defer pool.Put(chunkLengthBuf)
	for i := 0; i < len(payload); i += TCPChunkMaxLen {
		// write chunk
		var chunkLength = common.Min(TCPChunkMaxLen, len(payload)-i)
		binary.BigEndian.PutUint16(chunkLengthBuf, uint16(chunkLength))
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, chunkLengthBuf, nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, payload[i:i+chunkLength], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
	}
}
