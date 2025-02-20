package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	SymmetricDirect netproxy.Dialer
	FullconeDirect  netproxy.Dialer
)

func InitDirectDialers(fallbackDNS string) {
	SymmetricDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: false, FallbackDNS: fallbackDNS})
	FullconeDirect = NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: true, FallbackDNS: fallbackDNS})
}

type Option struct {
	FullCone    bool
	FallbackDNS string
}

type directDialer struct {
	tcpDialer      *net.Dialer
	tcpDialerMptcp *net.Dialer
	udpLocalAddr   *net.UDPAddr
	Option         Option
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

func (d *directDialer) tryRetry(err error, addr string, callback func()) {
	host, _, _ := net.SplitHostPort(addr)
	// Check if the host is domain
	if _, e := netip.ParseAddr(host); e == nil {
		// addr is IP
		return
	}

	// addr is domain
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") && strings.Contains(err.Error(), "lookup") {
			callback()
		}
	}
}

func (d *directDialer) createResolver(mark int, fallback bool) *net.Resolver {
	if mark == 0 && !fallback {
		return nil
	} else {
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{}
				if mark != 0 {
					dialer.Control = func(network, address string, c syscall.RawConn) error {
						return netproxy.SoMarkControl(c, mark)
					}
				}
				if fallback {
					return dialer.DialContext(ctx, network, d.Option.FallbackDNS)
				} else {
					return dialer.DialContext(ctx, network, address)
				}
			},
		}
	}
}

func (d *directDialer) dialUdp(ctx context.Context, addr string, mark int, fallback bool) (c netproxy.PacketConn, err error) {
	if d.Option.FallbackDNS != "" && !fallback {
		defer func() { // don't remove func wrapper for d.tryRetry
			d.tryRetry(err, addr, func() {
				c, err = d.dialUdp(ctx, addr, mark, true)
			})
		}()
	}
	if mark == 0 {
		if d.Option.FullCone {
			conn, err := net.ListenUDP("udp", d.udpLocalAddr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn, FullCone: true, dialTgt: addr, resolver: d.createResolver(mark, fallback)}, nil
		} else {
			dialer := net.Dialer{
				LocalAddr: d.udpLocalAddr,
				Resolver:  d.createResolver(mark, fallback),
			}
			conn, err := dialer.DialContext(ctx, "udp", addr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn.(*net.UDPConn), FullCone: false, dialTgt: addr, resolver: d.createResolver(mark, fallback)}, nil
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
				Resolver:  d.createResolver(mark, fallback),
			}
			c, err := dialer.DialContext(ctx, "udp", addr)
			if err != nil {
				return nil, err
			}
			conn = c.(*net.UDPConn)
		}
		return &directPacketConn{UDPConn: conn, FullCone: d.Option.FullCone, dialTgt: addr, resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Control: func(network, address string, c syscall.RawConn) error {
						return netproxy.SoMarkControl(c, mark)
					},
					Resolver: d.createResolver(mark, fallback),
				}
				return d.DialContext(ctx, network, address)
			},
		}}, nil
	}
}

func (d *directDialer) dialTcp(ctx context.Context, addr string, mark int, mptcp bool, fallback bool) (c net.Conn, err error) {
	if d.Option.FallbackDNS != "" && !fallback {
		defer func() { // don't remove func wrapper for d.tryRetry
			d.tryRetry(err, addr, func() {
				c, err = d.dialTcp(ctx, addr, mark, mptcp, true)
			})
		}()
	}
	var dialer *net.Dialer
	if mptcp {
		dialer = d.tcpDialerMptcp
	} else {
		dialer = d.tcpDialer
	}
	if mark != 0 {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, mark)
		}
	}
	dialer.Resolver = d.createResolver(mark, fallback)
	return dialer.DialContext(ctx, "tcp", addr)
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.dialTcp(ctx, addr, int(magicNetwork.Mark), magicNetwork.Mptcp, false)
	case "udp":
		return d.dialUdp(ctx, addr, int(magicNetwork.Mark), false)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
