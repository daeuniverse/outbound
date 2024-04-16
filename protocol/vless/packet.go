package trojanc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	// FIXME: a compromise on Symmetric NAT
	addr = c.cachedProxyAddrIpIP

	bLen := pool.Get(2)
	defer pool.Put(bLen)
	if _, err = io.ReadFull(c, bLen); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(bLen))
	if len(p) < length {
		return 0, netip.AddrPort{}, fmt.Errorf("buf size is not enough")
	}
	n, err = io.ReadFull(c, p[:length])
	return n, addr, err
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	bLen := pool.Get(2)
	defer pool.Put(bLen)
	binary.BigEndian.PutUint16(bLen, uint16(len(p)))
	if _, err = c.Write(bLen); err != nil {
		return 0, err
	}
	return c.Write(p)
}
