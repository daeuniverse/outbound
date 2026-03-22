package direct

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/daeuniverse/outbound/common"
)

var resolveUDPAddr = common.ResolveUDPAddr

type directPacketConn struct {
	*net.UDPConn
	FullCone      bool
	dialTgt       string
	cachedDialTgt atomic.Pointer[netip.AddrPort]
	cacheOnce     sync.Once
	cacheErr      error
	resolver      *net.Resolver
	// writeMu serializes concurrent Write calls in FullCone mode.
	// Prevents race between target resolution and actual write operations.
	writeMu sync.Mutex
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

func (c *directPacketConn) resolveTarget() error {
	c.cacheOnce.Do(func() {
		ua, err := resolveUDPAddr(c.resolver, c.dialTgt)
		if err != nil {
			c.cacheErr = err
			return
		}
		ap := ua.AddrPort()
		c.cachedDialTgt.Store(&ap)
	})
	return c.cacheErr
}

func (c *directPacketConn) Write(b []byte) (int, error) {
	if !c.FullCone {
		return c.UDPConn.Write(b)
	}

	// Ensure target is resolved
	if c.cachedDialTgt.Load() == nil {
		if err := c.resolveTarget(); err != nil {
			return 0, err
		}
	}

	// Serialize writes to prevent concurrent access to the same UDP connection
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	cached := c.cachedDialTgt.Load()
	return c.UDPConn.WriteToUDPAddrPort(b, *cached)
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
