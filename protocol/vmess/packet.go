package vmess

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(MaxUDPSize)
	defer pool.Put(buf)
	n, err = c.read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if c.metadata.IsPacketAddr() {
		addrTyp, address, err := ExtractPacketAddr(buf)
		addrLen := PacketAddrLength(addrTyp)
		if n < addrLen {
			return 0, netip.AddrPort{}, fmt.Errorf("not enough data to read for PacketAddr")
		}
		copy(p, buf[addrLen:n])
		return n - addrLen, address, err
	} else {
		if !c.dialTgtAddrPort.IsValid() {
			tgt, err := net.ResolveUDPAddr("udp", c.dialTgt)
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
			c.dialTgtAddrPort = tgt.AddrPort()
		}
		copy(p, buf[:n])
		return n, c.dialTgtAddrPort, err
	}
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	if c.metadata.IsPacketAddr() {
		// VMess packet addr does not support domain.
		address, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return 0, err
		}
		packetAddrLen := UDPAddrToPacketAddrLength(address)
		buf := pool.Get(packetAddrLen + len(p))
		defer pool.Put(buf)

		err = PutPacketAddr(buf, address)
		if err != nil {
			return 0, err
		}
		copy(buf[packetAddrLen:], p)
		return c.write(buf)
	}

	return c.write(p)
}
