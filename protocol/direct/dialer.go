package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
)

var SymmetricDirect = newDirectDialer(false)
var FullconeDirect = newDirectDialer(true)

type directDialer struct {
	tcpLocalAddr *net.TCPAddr
	udpLocalAddr *net.UDPAddr
	fullCone     bool
}

func NewDirectDialerLaddr(fullCone bool, lAddr netip.Addr) netproxy.Dialer {
	var tcpLocalAddr *net.TCPAddr
	var udpLocalAddr *net.UDPAddr
	if lAddr.IsValid() {
		tcpLocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
		udpLocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
	}
	return &directDialer{
		tcpLocalAddr: tcpLocalAddr,
		udpLocalAddr: udpLocalAddr,
		fullCone:     fullCone,
	}
}

func newDirectDialer(fullCone bool) netproxy.Dialer {
	return &directDialer{
		tcpLocalAddr: nil,
		udpLocalAddr: nil,
		fullCone:     fullCone,
	}
}

func (d *directDialer) dialUdp(addr string, mark int) (c netproxy.PacketConn, err error) {
	if mark == 0 {
		if d.fullCone {
			conn, err := net.ListenUDP("udp", d.udpLocalAddr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn, FullCone: true, dialTgt: addr}, nil
		} else {
			dialer := net.Dialer{
				LocalAddr: d.udpLocalAddr,
			}
			conn, err := dialer.Dial("udp", addr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn.(*net.UDPConn), FullCone: false, dialTgt: addr}, nil
		}

	} else {
		var conn *net.UDPConn
		if d.fullCone {
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
			c, err := dialer.Dial("udp", addr)
			if err != nil {
				return nil, err
			}
			conn = c.(*net.UDPConn)
		}
		return &directPacketConn{UDPConn: conn, FullCone: d.fullCone, dialTgt: addr, resolver: &net.Resolver{
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

func (d *directDialer) dialTcp(addr string, mark int, mptcp bool) (c netproxy.Conn, err error) {
	dialer := &net.Dialer{
		LocalAddr: d.tcpLocalAddr,
	}
	dialer.SetMultipathTCP(mptcp)
	if mark == 0 {
		return dialer.Dial("tcp", addr)
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
		return dialer.Dial("tcp", addr)
	}
}

func (d *directDialer) Dial(network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.dialTcp(addr, int(magicNetwork.Mark), magicNetwork.Mptcp)
	case "udp":
		return d.dialUdp(addr, int(magicNetwork.Mark))
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
