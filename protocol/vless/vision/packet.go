package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

var _ netproxy.PacketConn = (*PacketConn)(nil)

type PacketConn struct {
	*Conn
	network string
	addr    string
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	if c.network == "tcp" {
		return c.Conn.Read(b)
	}
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) Write(b []byte) (n int, err error) {
	if c.network == "tcp" {
		return c.Conn.Write(b)
	}
	return c.WriteTo(b, c.addr)
}

// +-------------------+-------------------+
// | Frame Length (2B) | Frame Header (4B) |
// +-------------------+-------------------+
// |Net Type (1B) | PORT (2B)  | IP Type (1B) | IP Address |
// +-------------------+-------------------+
// |   Length Data     |     Payload      |
// +-------------------+-------------------+
func (c *PacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	data := make([]byte, 1024)
	n, err = c.Conn.Read(data)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	data = data[:n]
	var frameLength uint16
	var frameHeaderBytes [4]byte
	buf := bytes.NewBuffer(data)
	frameLength = binary.BigEndian.Uint16(buf.Next(2))
	frameHeaderBytes = [4]byte(buf.Next(4))
	switch frameHeaderBytes[2] {
	case 0x01:
		// New
		return 0, netip.AddrPort{}, fmt.Errorf("unexpected frame new")
	case 0x02:
		// Keep
		if frameLength != 4 {
			addrData := make([]byte, frameLength-4)
			_, err = buf.Read(addrData)
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
			addr, err = ReadPacketAddr(addrData)
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
		}
	case 0x03:
		// End
		return 0, netip.AddrPort{}, io.EOF
	case 0x04:
		// KeepAlive
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported frame header: %x", frameHeaderBytes[2])
	}
	if frameHeaderBytes[3]&1 != 1 {
		return c.ReadFrom(p)
	} else {
		length := binary.BigEndian.Uint16(buf.Next(2))
		payload := make([]byte, length)
		n, err = buf.Read(payload)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		copy(p, payload)
		return n, addr, nil
	}
}

// +------------------------+------------------------+
// |  Metadata Length (2B)  |    Session ID (2B)    |
// +------------------------+------------------------+
// |    Type (1B)          |    Options (1B)        |
// |    (New=1/Keep=2)     |                        |
// +------------------------+------------------------+
// |  Protocol Type (1B)    |                       |
// +------------------------+                       |
// |     Target Address     |       Port            |
// |     (Variable)         |                       |
// +------------------------+------------------------+
// |     Global ID (8B)     |                       |
// |     (Optional)         |                       |
// +------------------------+------------------------+
// |   Data Length (2B)     |      Payload          |
// +------------------------+------------------------+
func (pc *PacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	dataLen := len(p)
	prefix, err := pc.prefixPacket(addr)
	if err != nil {
		return 0, err
	}
	defer prefix.Put()
	_, err = iout.MultiWrite(pc.writer, prefix, []byte{byte(dataLen >> 8), byte(dataLen)}, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (pc *PacketConn) prefixPacket(addr string) (pool.PB, error) {
	address, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	packetAddrLen := IPAddrToPacketAddrLength(address)
	prefix := pool.Get(7 + packetAddrLen)
	l := len(prefix) - 2
	err = PutPacketAddr(prefix[7:], address)
	if err != nil {
		return nil, err
	}
	if pc.needHandshake {
		pc.needHandshake = false
		prefix[0] = byte(l >> 8)
		prefix[1] = byte(l)
		prefix[2] = 0
		prefix[3] = 0
		prefix[4] = 1 // new
		prefix[5] = 1 // option
		prefix[6] = 2 // udp
	} else {
		prefix[0] = byte(l >> 8)
		prefix[1] = byte(l)
		prefix[2] = 0
		prefix[3] = 0
		prefix[4] = 2 // keep
		prefix[5] = 1 // option
		prefix[6] = 2 // udp
	}

	return prefix, err
}

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
		return errors.New("invalid IP")
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
	p = p[1:]
	port := binary.BigEndian.Uint16(p[0:2])
	ipType := p[2]
	ip := p[3:]
	if ipType == 1 {
		ip = ip[:4]
	} else {
		ip = ip[:16]
	}
	ipAddr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, errors.New("invalid IP")
	}
	return netip.AddrPortFrom(ipAddr, port), nil
}
