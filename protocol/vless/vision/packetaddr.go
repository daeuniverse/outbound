package vision

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	ErrInvalidPacketAddr = errors.New("invalid packet addr")
	ErrInvalidAddrType   = errors.New("invalid addr type")
	ErrInvalidIP         = errors.New("invalid IP")
)

func IPAddrToPacketAddrLength(addr netip.AddrPort) int {
	nip, ok := netip.AddrFromSlice(addr.Addr().AsSlice())
	if !ok {
		return 0
	}

	if nip.Is4() {
		return 1 + 4 + 2
	} else {
		return 1 + 16 + 2
	}
}

func PutPacketAddr(src []byte, addr netip.AddrPort) error {
	nip, ok := netip.AddrFromSlice(addr.Addr().AsSlice())
	if !ok {
		return ErrInvalidIP
	}

	if nip.Is4() {
		binary.BigEndian.PutUint16(src[0:2], addr.Port())
		src[2] = 1
		copy(src[3:7], nip.AsSlice())
	} else {
		binary.BigEndian.PutUint16(src[0:2], addr.Port())
		src[2] = 3
		copy(src[3:19], nip.AsSlice())
	}

	return nil
}

func ReadPacketAddr(p []byte) (addr netip.AddrPort, err error) {
	if len(p) < 3 {
		return netip.AddrPort{}, ErrInvalidPacketAddr
	}
	port := binary.BigEndian.Uint16(p[0:2])
	ipType := p[2]
	ip := p[3:]
	switch ipType {
	case 1:
		if len(ip) < 4 {
			return netip.AddrPort{}, ErrInvalidPacketAddr
		}
		ip = ip[:4]
	case 3:
		if len(ip) < 16 {
			return netip.AddrPort{}, ErrInvalidPacketAddr
		}
		ip = ip[:16]
	default:
		return netip.AddrPort{}, ErrInvalidAddrType
	}
	ipAddr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, ErrInvalidIP
	}
	return netip.AddrPortFrom(ipAddr, port), nil
}
