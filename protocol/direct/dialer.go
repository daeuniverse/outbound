package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
)

var SymmetricDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: false, WithCache: false})
var FullconeDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: true, WithCache: false})

type Option struct {
	FullCone  bool
	WithCache bool
}

type addrCache struct {
	lastAddr     string
	lastRemoteIp string
}
type directDialer struct {
	tcpDialer      *net.Dialer
	tcpDialerMptcp *net.Dialer
	udpLocalAddr   *net.UDPAddr
	Option         Option

	muCache sync.Mutex
	cache   addrCache
}

func NewDirectDialerLaddr(lAddr netip.Addr, option Option) netproxy.Dialer {
	var tcpLocalAddr *net.TCPAddr
	var udpLocalAddr *net.UDPAddr
	if lAddr.IsValid() {
		tcpLocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
		udpLocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
	}
	tcpDialer := &net.Dialer{LocalAddr: tcpLocalAddr}
	tcpDialerMptcp := &net.Dialer{LocalAddr: tcpLocalAddr}
	tcpDialerMptcp.SetMultipathTCP(true)
	d := &directDialer{
		tcpDialer:      tcpDialer,
		tcpDialerMptcp: tcpDialerMptcp,
		udpLocalAddr:   udpLocalAddr,
		Option:         option,
	}

	return d
}

func (d *directDialer) tryRetry(err error, addr string, remoteIp string, cb func(addr string)) {
	host, port, _ := net.SplitHostPort(addr)
	// Check if the host is domain
	if _, e := netip.ParseAddr(host); e == nil {
		// addr is IP
		return
	}

	// addr is domain
	d.muCache.Lock()
	if err == nil {
		d.cache.lastAddr = host
		d.cache.lastRemoteIp = remoteIp
		d.muCache.Unlock()
	} else {
		if d.cache.lastAddr == host && strings.Contains(err.Error(), "i/o timeout") && strings.Contains(err.Error(), "lookup") {
			lastRemoteIp := d.cache.lastRemoteIp
			d.muCache.Unlock()
			// Retry with last remote ip
			cb(net.JoinHostPort(lastRemoteIp, port))
		} else {
			d.muCache.Unlock()
		}
	}
}

func (d *directDialer) dialUdp(ctx context.Context, addr string, mark int) (c netproxy.PacketConn, err error) {
	var remoteIp string
	if d.Option.WithCache {
		defer func() { // don't remove func wrapper for d.tryRetry
			d.tryRetry(err, addr, remoteIp, func(addr string) {
				c, err = d.dialUdp(ctx, addr, mark)
			})
		}()
	}
	if mark == 0 {
		if d.Option.FullCone {
			conn, err := net.ListenUDP("udp", d.udpLocalAddr)
			if err != nil {
				return nil, err
			}
			remoteIp = ""
			return &directPacketConn{UDPConn: conn, FullCone: true, dialTgt: addr}, nil
		} else {
			dialer := net.Dialer{
				LocalAddr: d.udpLocalAddr,
			}
			conn, err := dialer.DialContext(ctx, "udp", addr)
			if err != nil {
				return nil, err
			}
			remoteIp = conn.RemoteAddr().(*net.UDPAddr).IP.String()
			return &directPacketConn{UDPConn: conn.(*net.UDPConn), FullCone: false, dialTgt: addr}, nil
		}

	} else {
		var conn *net.UDPConn
		if d.Option.FullCone {
			c := net.ListenConfig{
				Control: func(network string, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				},
				KeepAlive: 0,
			}
			laddr := ""
			if d.udpLocalAddr != nil {
				laddr = d.udpLocalAddr.String()
			}
			_conn, err := c.ListenPacket(context.Background(), "udp", laddr)
			if err != nil {
				return nil, err
			}
			conn = _conn.(*net.UDPConn)
			remoteIp = ""
		} else {
			dialer := net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				},
				LocalAddr: d.udpLocalAddr,
			}
			c, err := dialer.DialContext(ctx, "udp", addr)
			if err != nil {
				return nil, err
			}
			conn = c.(*net.UDPConn)
			remoteIp = conn.RemoteAddr().(*net.UDPAddr).IP.String()
		}
		return &directPacketConn{UDPConn: conn, FullCone: d.Option.FullCone, dialTgt: addr, resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Control: func(network, address string, c syscall.RawConn) error {
						return netproxy.SoMarkControl(c, mark)
					},
				}
				return d.DialContext(ctx, network, address)
			},
		}}, nil
	}
}

func (d *directDialer) dialTcp(ctx context.Context, addr string, mark int, mptcp bool) (c net.Conn, err error) {
	if d.Option.WithCache {
		defer func() { // don't remove func wrapper for d.tryRetry
			d.tryRetry(err, addr, c.RemoteAddr().(*net.TCPAddr).IP.String(), func(addr string) {
				c, err = d.dialTcp(ctx, addr, mark, mptcp)
			})
		}()
	}
	var dialer *net.Dialer
	if mptcp {
		dialer = d.tcpDialerMptcp
	} else {
		dialer = d.tcpDialer
	}
	if mark == 0 {
		return dialer.DialContext(ctx, "tcp", addr)
	} else {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, mark)
		}
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Control: func(network, address string, c syscall.RawConn) error {
						return netproxy.SoMarkControl(c, mark)
					},
				}
				return d.DialContext(ctx, network, address)
			},
		}
		return dialer.DialContext(ctx, "tcp", addr)
	}
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.dialTcp(ctx, addr, int(magicNetwork.Mark), magicNetwork.Mptcp)
	case "udp":
		return d.dialUdp(ctx, addr, int(magicNetwork.Mark))
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
