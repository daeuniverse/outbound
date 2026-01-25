package shadowsocks2022

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

const (
	// Header types
	HeaderTypeClientRequest  = 0
	HeaderTypeServerResponse = 1

	// Fixed header size: Type(1) + Timestamp(8) + Length(2) = 11 bytes
	FixedHeaderLen = 11

	// Address types (SOCKS5 format)
	AddrTypeIPv4   = 1
	AddrTypeDomain = 3
	AddrTypeIPv6   = 4

	// Time validation window (±30 seconds)
	TimestampValidWindow = 30 * time.Second

	// Max padding length
	MaxPaddingLen = 900

	// Min padding length
	MinPaddingLen = 0
)

var (
	ErrInvalidTimestamp   = errors.New("timestamp validation failed")
	ErrInvalidHeaderType  = errors.New("invalid header type")
	ErrInvalidAddressType = errors.New("invalid address type")
	ErrInvalidSalt        = errors.New("response salt mismatch")
)

// FixedHeader represents the fixed-length header in SS2022
type FixedHeader struct {
	Type         byte   // 0 for request, 1 for response
	Timestamp    uint64 // Unix timestamp
	VarHeaderLen uint16 // Length of variable header
}

// EncodeFixedHeader encodes a fixed header
func EncodeFixedHeader(headerType byte, timestamp uint64, varHeaderLen uint16) []byte {
	buf := make([]byte, FixedHeaderLen)
	buf[0] = headerType
	binary.BigEndian.PutUint64(buf[1:9], timestamp)
	binary.BigEndian.PutUint16(buf[9:11], varHeaderLen)
	return buf
}

// DecodeFixedHeader decodes a fixed header
func DecodeFixedHeader(data []byte) (*FixedHeader, error) {
	if len(data) < FixedHeaderLen {
		return nil, fmt.Errorf("fixed header too short: %d < %d", len(data), FixedHeaderLen)
	}

	return &FixedHeader{
		Type:         data[0],
		Timestamp:    binary.BigEndian.Uint64(data[1:9]),
		VarHeaderLen: binary.BigEndian.Uint16(data[9:11]),
	}, nil
}

// ValidateTimestamp validates if the timestamp is within acceptable range
func ValidateTimestamp(timestamp uint64) error {
	now := uint64(time.Now().Unix())
	diff := int64(timestamp) - int64(now)
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(TimestampValidWindow.Seconds()) {
		return fmt.Errorf("%w: diff=%ds", ErrInvalidTimestamp, diff)
	}
	return nil
}

// EncodeAddress encodes an address in SOCKS5 format
func EncodeAddress(hostname string, port uint16) ([]byte, error) {
	ip := net.ParseIP(hostname)
	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			// IPv4
			buf := pool.Get(1 + 4 + 2)
			buf[0] = AddrTypeIPv4
			copy(buf[1:5], ipv4)
			binary.BigEndian.PutUint16(buf[5:7], port)
			return buf, nil
		}
		// IPv6
		buf := pool.Get(1 + 16 + 2)
		buf[0] = AddrTypeIPv6
		copy(buf[1:17], ip.To16())
		binary.BigEndian.PutUint16(buf[17:19], port)
		return buf, nil
	}

	// Domain
	domainLen := len(hostname)
	if domainLen > 255 {
		return nil, fmt.Errorf("domain name too long: %d", domainLen)
	}
	buf := pool.Get(1 + 1 + domainLen + 2)
	buf[0] = AddrTypeDomain
	buf[1] = byte(domainLen)
	copy(buf[2:2+domainLen], hostname)
	binary.BigEndian.PutUint16(buf[2+domainLen:], port)
	return buf, nil
}

// DecodeAddress decodes a SOCKS5 format address
func DecodeAddress(data []byte) (hostname string, port uint16, addrLen int, err error) {
	if len(data) < 1 {
		return "", 0, 0, fmt.Errorf("address data too short")
	}

	addrType := data[0]
	switch addrType {
	case AddrTypeIPv4:
		if len(data) < 1+4+2 {
			return "", 0, 0, fmt.Errorf("IPv4 address too short")
		}
		hostname = net.IP(data[1:5]).String()
		port = binary.BigEndian.Uint16(data[5:7])
		addrLen = 7
	case AddrTypeIPv6:
		if len(data) < 1+16+2 {
			return "", 0, 0, fmt.Errorf("IPv6 address too short")
		}
		hostname = net.IP(data[1:17]).String()
		port = binary.BigEndian.Uint16(data[17:19])
		addrLen = 19
	case AddrTypeDomain:
		if len(data) < 2 {
			return "", 0, 0, fmt.Errorf("domain address too short")
		}
		domainLen := int(data[1])
		if len(data) < 1+1+domainLen+2 {
			return "", 0, 0, fmt.Errorf("domain address too short for domain length %d", domainLen)
		}
		hostname = string(data[2 : 2+domainLen])
		port = binary.BigEndian.Uint16(data[2+domainLen : 2+domainLen+2])
		addrLen = 1 + 1 + domainLen + 2
	default:
		return "", 0, 0, fmt.Errorf("%w: %d", ErrInvalidAddressType, addrType)
	}

	return hostname, port, addrLen, nil
}

// AddressLength returns the length of an encoded address
func AddressLength(hostname string) int {
	ip := net.ParseIP(hostname)
	if ip != nil {
		if ip.To4() != nil {
			return 1 + 4 + 2
		}
		return 1 + 16 + 2
	}
	return 1 + 1 + len(hostname) + 2
}

// MetadataTypeFromAddrType converts SS2022 address type to protocol.MetadataType
func MetadataTypeFromAddrType(addrType byte) protocol.MetadataType {
	switch addrType {
	case AddrTypeIPv4:
		return protocol.MetadataTypeIPv4
	case AddrTypeDomain:
		return protocol.MetadataTypeDomain
	case AddrTypeIPv6:
		return protocol.MetadataTypeIPv6
	default:
		return protocol.MetadataTypeInvalid
	}
}

// AddrTypeFromMetadataType converts protocol.MetadataType to SS2022 address type
func AddrTypeFromMetadataType(t protocol.MetadataType) byte {
	switch t {
	case protocol.MetadataTypeIPv4:
		return AddrTypeIPv4
	case protocol.MetadataTypeDomain:
		return AddrTypeDomain
	case protocol.MetadataTypeIPv6:
		return AddrTypeIPv6
	default:
		return 0
	}
}
