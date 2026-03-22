package vision

import (
	"encoding/binary"
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

func (pc *PacketConn) Read(b []byte) (n int, err error) {
	switch pc.network {
	case "tcp":
		return pc.Conn.Read(b)
	case "udp":
		n, _, err = pc.ReadFrom(b)
		return n, err
	default:
		return 0, fmt.Errorf("unsupported network: %s", pc.network)
	}
}

func (pc *PacketConn) Write(b []byte) (n int, err error) {
	switch pc.network {
	case "tcp":
		return pc.Conn.Write(b)
	case "udp":
		return pc.WriteTo(b, pc.addr)
	default:
		return 0, fmt.Errorf("unsupported network: %s", pc.network)
	}
}

// +-------------------+-------------------+
// | Frame Length (2B) | Frame Header (4B) |
// +-------------------+-------------------+
// |Net Type (1B) | PORT (2B)  | IP Type (1B) | IP Address |
// +-------------------+-------------------+
// |   Length Data     |     Payload      |
// +-------------------+-------------------+
func (pc *PacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	// Read frame length (2 bytes)
	var frameLengthBytes [2]byte
	if _, err = io.ReadFull(pc.Conn, frameLengthBytes[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	frameLength := binary.BigEndian.Uint16(frameLengthBytes[:])

	if frameLength < 4 {
		return 0, netip.AddrPort{}, io.EOF
	}

	// Read frame header (4 bytes)
	var frameHeaderBytes [4]byte
	if _, err = io.ReadFull(pc.Conn, frameHeaderBytes[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}

	discard := false
	switch frameHeaderBytes[2] {
	case 0x01:
		return 0, netip.AddrPort{}, fmt.Errorf("unexpected frame new")
	case 0x02:
		// Keep
		if frameLength > 4 {
			netInfo := make([]byte, frameLength-4)
			if _, err = io.ReadFull(pc.Conn, netInfo); err != nil {
				return 0, netip.AddrPort{}, err
			}
			netType := netInfo[0]
			if netType != 0x02 { // net type udp
				return 0, netip.AddrPort{}, fmt.Errorf("unsupported net type: %x", netType)
			}
			addrData := netInfo[1:]
			addr, err = ReadPacketAddr(addrData)
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
		}
	case 0x03:
		return 0, netip.AddrPort{}, io.EOF
	case 0x04:
		// KeepAlive
		discard = true
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported frame header: %x", frameHeaderBytes[2])
	}

	if frameHeaderBytes[3]&1 != 1 {
		return pc.ReadFrom(p)
	}

	// Read length and payload
	var lengthBytes [2]byte
	if _, err = io.ReadFull(pc.Conn, lengthBytes[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := binary.BigEndian.Uint16(lengthBytes[:])
	if length == 0 {
		return pc.ReadFrom(p)
	}
	if length > uint16(len(p)) {
		return 0, netip.AddrPort{}, io.ErrShortBuffer
	}

	n, err = io.ReadFull(pc.Conn, p[:length])
	if !discard {
		return n, addr, err
	}
	return pc.ReadFrom(p)
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
