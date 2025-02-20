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

func (d *directDialer) dialUdp(ctx context.Context, addr string, mark int) (c netproxy.PacketConn, err error) {
	var remoteAddr string
	if d.Option.WithCache {
		defer func() {
			host, port, _ := net.SplitHostPort(addr)
			// Check if the host is domain
			if _, e := netip.ParseAddr(host); e == nil {
				// addr is IP
				return
			}

			// addr is domain
			var lastRemoteIp string
			d.muCache.Lock()
			if err != nil {
				lastRemoteIp = d.cache.lastRemoteIp
			} else if d.cache.lastAddr != host {
				d.cache.lastAddr = host
				d.cache.lastRemoteIp = remoteAddr
			}
			d.muCache.Unlock()
			if err != nil && strings.Contains(err.Error(), "i/o timeout") && strings.Contains(err.Error(), "lookup") {
				// Retry with last remote ip
				c, err = d.dialUdp(ctx, net.JoinHostPort(lastRemoteIp, port), mark)
			}
		}()
	}
	if mark == 0 {
		if d.Option.FullCone {
			conn, err := net.ListenUDP("udp", d.udpLocalAddr)
			if err != nil {
				return nil, err
			}
			remoteAddr = ""
			return &directPacketConn{UDPConn: conn, FullCone: true, dialTgt: addr}, nil
		} else {
			dialer := net.Dialer{
				LocalAddr: d.udpLocalAddr,
			}
			conn, err := dialer.DialContext(ctx, "udp", addr)
			if err != nil {
				return nil, err
			}
			remoteAddr = conn.RemoteAddr().String()
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
		}
		remoteAddr = conn.RemoteAddr().String()
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
		defer func() {
			host, port, _ := net.SplitHostPort(addr)
			// Check if the host is domain
			if _, e := netip.ParseAddr(host); e == nil {
				// addr is IP
				return
			}

			// addr is domain
			var lastRemoteIp string
			d.muCache.Lock()
			if err != nil {
				lastRemoteIp = d.cache.lastRemoteIp
			} else if d.cache.lastAddr != host {
				d.cache.lastAddr = host
				d.cache.lastRemoteIp = c.RemoteAddr().String()
			}
			d.muCache.Unlock()
			if err != nil && strings.Contains(err.Error(), "i/o timeout") && strings.Contains(err.Error(), "lookup") {
				// Retry with last remote ip
				c, err = d.dialTcp(ctx, net.JoinHostPort(lastRemoteIp, port), mark, mptcp)
			}
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
