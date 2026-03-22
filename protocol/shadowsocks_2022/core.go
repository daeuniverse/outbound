package shadowsocks_2022

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/daeuniverse/outbound/ciphers"
	"lukechampine.com/blake3"
)

// SS2022Core contains shared logic for Shadowsocks 2022 protocol.
// Both TCPConn and UdpConn embed this struct to avoid code duplication.
type SS2022Core struct {
	cipherConf *ciphers.CipherConf2022
	pskList    [][]byte
	uPSK       []byte

	// Shared block ciphers derived from the configured PSKs.
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block

	// Pre-computed identity header hash components for multi-PSK scenario
	pskHash [][]byte

	// Pre-created block ciphers for identity header encryption
	identityBlockCiphers []cipher.Block

	// Flag indicating if multi-PSK is enabled
	hasMultiPSK bool
}

// NewSS2022Core creates a new SS2022Core with pre-computed identity components.
func NewSS2022Core(conf *ciphers.CipherConf2022, pskList [][]byte, uPSK []byte) (*SS2022Core, error) {
	if len(pskList) == 0 {
		return nil, fmt.Errorf("empty PSK list")
	}

	blockCipherEncrypt, err := conf.NewBlockCipher(pskList[0])
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypt block cipher: %w", err)
	}
	blockCipherDecrypt, err := conf.NewBlockCipher(uPSK)
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypt block cipher: %w", err)
	}

	core := &SS2022Core{
		cipherConf:         conf,
		pskList:            pskList,
		uPSK:               uPSK,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
		hasMultiPSK:        len(pskList) > 1,
	}

	// Pre-compute identity header components for multi-PSK scenario (like sing-box)
	if core.hasMultiPSK {
		core.pskHash = make([][]byte, len(pskList))
		core.identityBlockCiphers = make([]cipher.Block, len(pskList)-1)

		for i, psk := range pskList {
			// Pre-compute BLAKE3 hash of each PSK (same as sing-box)
			hash := blake3.Sum512(psk)
			core.pskHash[i] = make([]byte, aes.BlockSize)
			copy(core.pskHash[i], hash[:aes.BlockSize])

			// Pre-create block cipher for identity header encryption
			if i < len(pskList)-1 {
				blockCipher, err := conf.NewBlockCipher(pskList[i])
				if err != nil {
					return nil, fmt.Errorf("failed to create identity block cipher: %w", err)
				}
				core.identityBlockCiphers[i] = blockCipher
			}
		}
	}

	return core, nil
}

// WriteIdentityHeader writes the identity header to dst for multi-PSK scenario.
// Returns the number of bytes written.
// For single PSK, this is a no-op and returns 0.
func (c *SS2022Core) WriteIdentityHeader(dst []byte, separateHeader []byte) (int, error) {
	if !c.hasMultiPSK {
		return 0, nil
	}

	headerLen := (len(c.pskList) - 1) * aes.BlockSize
	if len(dst) < headerLen {
		return 0, io.ErrShortBuffer
	}

	offset := 0
	for i := 0; i < len(c.pskList)-1; i++ {
		header := dst[offset : offset+aes.BlockSize]
		// XOR pskHash with separateHeader, then encrypt (same as sing-box)
		subtle.XORBytes(header, c.pskHash[i+1], separateHeader)
		c.identityBlockCiphers[i].Encrypt(header, header)
		offset += aes.BlockSize
	}

	return headerLen, nil
}

// IdentityHeaderLen returns the length of identity header for this connection.
func (c *SS2022Core) IdentityHeaderLen() int {
	if !c.hasMultiPSK {
		return 0
	}
	return (len(c.pskList) - 1) * aes.BlockSize
}

// HasMultiPSK returns true if multiple PSKs are configured.
func (c *SS2022Core) HasMultiPSK() bool {
	return c.hasMultiPSK
}

// CipherConf returns the cipher configuration.
func (c *SS2022Core) CipherConf() *ciphers.CipherConf2022 {
	return c.cipherConf
}

// UPSK returns the user PSK.
func (c *SS2022Core) UPSK() []byte {
	return c.uPSK
}

// BlockCipherEncrypt returns the shared block cipher used for encrypting the
// separate header on outbound packets.
func (c *SS2022Core) BlockCipherEncrypt() cipher.Block {
	return c.blockCipherEncrypt
}

// BlockCipherDecrypt returns the shared block cipher used for decrypting the
// separate header on inbound packets.
func (c *SS2022Core) BlockCipherDecrypt() cipher.Block {
	return c.blockCipherDecrypt
}

// PSKList returns the list of PSKs.
func (c *SS2022Core) PSKList() [][]byte {
	return c.pskList
}

// PSKHash returns pre-computed PSK hash at index i.
func (c *SS2022Core) PSKHash(i int) []byte {
	if i < 0 || i >= len(c.pskHash) {
		return nil
	}
	return c.pskHash[i]
}

// IdentityBlockCipher returns pre-created identity block cipher at index i.
func (c *SS2022Core) IdentityBlockCipher(i int) cipher.Block {
	if i < 0 || i >= len(c.identityBlockCiphers) {
		return nil
	}
	return c.identityBlockCiphers[i]
}
