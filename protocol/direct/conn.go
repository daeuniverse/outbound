package direct

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/daeuniverse/outbound/common"
)

type directPacketConn struct {
	*net.UDPConn
	FullCone      bool
	dialTgt       string
	cachedDialTgt netip.AddrPort
	resolver      *net.Resolver
}

func (c *directPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return c.UDPConn.ReadFromUDPAddrPort(p)
}

func (c *directPacketConn) WriteTo(b []byte, addr string) (int, error) {
	if !c.FullCone {
		// FIXME: check the addr
		return c.Write(b)
	}

	uAddr, err := common.ResolveUDPAddr(c.resolver, addr)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, uAddr)
}

func (c *directPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if !c.FullCone {
		n, err = c.Write(b)
		return n, 0, err
	}
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (c *directPacketConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if !c.FullCone {
		return c.Write(b)
	}
	return c.UDPConn.WriteToUDP(b, addr)
}

func (c *directPacketConn) Write(b []byte) (int, error) {
	if !c.FullCone {
		return c.UDPConn.Write(b)
	}
	if !c.cachedDialTgt.IsValid() {
		ua, err := common.ResolveUDPAddr(c.resolver, c.dialTgt)
		if err != nil {
			return 0, err
		}
		c.cachedDialTgt = ua.AddrPort()
	}
	return c.UDPConn.WriteToUDPAddrPort(b, c.cachedDialTgt)
}

func (c *directPacketConn) Read(b []byte) (int, error) {
	if !c.FullCone {
		return c.UDPConn.Read(b)
	}
	n, _, err := c.UDPConn.ReadFrom(b)
	return n, err
}

var _ interface {
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
} = &directPacketConn{}
